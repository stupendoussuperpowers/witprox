package networklog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type IPAddr struct {
	Host string
	Port int
}

func (ip *IPAddr) String() string {
	return fmt.Sprintf("%s:%d", ip.Host, ip.Port)
}

type TransportProtocol string

const (
	ProtocolTCP TransportProtocol = "tcp"
	ProtocolUDP TransportProtocol = "udp"
)

type TransportData interface {
	isTransportData()
}

type ApplicationData interface {
	isApplicationData()
}

// This is the main JSON entry that is stored.
type Packet struct {
	Timestamp  time.Time         `json:"timestamp"`
	DurationMs time.Duration     `json:"duration"`
	Protocol   TransportProtocol `json:"protocol"`
	SrcAddr    string            `json:"src_addr"`
	DstAddr    string            `json:"dst_addr"`
	Data       TransportData     `json:"data"`
}

// -- TCP --
type TCP struct {
	Request  ApplicationData `json:"request"`
	Response ApplicationData `json:"response"`
}

func (*TCP) isTransportData() {}

type HTTP struct {
	TLS        bool                `json:"tls"`
	Method     string              `json:"method,omitempty"`
	StatusCode int                 `json:"status_code,omitempty"`
	Headers    map[string][]string `json:"headers,omitempty"`
	Bytes      int64               `json:"bytes"`
	Hash       string              `json:"hash"`
}

func (*HTTP) isApplicationData() {}

type Raw struct {
	Bytes int64  `json:"bytes"`
	Hash  string `json:"hash"`
}

func (*Raw) isApplicationData() {}

// Raw TCP record processing.
type RawRecord struct {
	Cn     net.Conn
	Count  int64
	Hasher hash.Hash
}

func NewRawRecord(c net.Conn) *RawRecord {
	return &RawRecord{
		Cn:     c,
		Count:  0,
		Hasher: sha256.New(),
	}
}

func (c *RawRecord) Write(p []byte) (int, error) {
	n, err := c.Cn.Write(p)
	if n > 0 {
		c.Count += int64(n)
		c.Hasher.Write(p[:n])
	}

	return n, err
}

func (c *RawRecord) Read(p []byte) (int, error) {
	return c.Cn.Read(p)
}

// Utils for TCP and HTTP logging.
func HashAndReplaceBody(body io.ReadCloser) (string, int64, io.ReadCloser, error) {
	if body == nil {
		return "", 0, nil, nil
	}

	b, err := io.ReadAll(body)

	if err != nil {
		return "", 0, body, err
	}

	body.Close()

	h := sha256.Sum256(b)
	hexh := hex.EncodeToString(h[:])

	return hexh, int64(len(b)), io.NopCloser(bytes.NewReader(b)), nil
}

func BuildTCPRecord(req, resp any, start, end time.Time, destAddr, clientAddr, proto string) (*Packet, error) {
	rec := &Packet{
		Timestamp:  start,
		DurationMs: end.Sub(start),
		Protocol:   ProtocolTCP,
		SrcAddr:    clientAddr,
		DstAddr:    destAddr,
	}

	switch proto {
	case "tls":
		reqBody, resBody, _ := buildHTTPRecord(req.(*http.Request), resp.(*http.Response), true)

		tcpData := &TCP{
			Request:  reqBody,
			Response: resBody,
		}

		rec.Data = tcpData
	case "http":
		reqBody, resBody, _ := buildHTTPRecord(req.(*http.Request), resp.(*http.Response), false)

		tcpData := &TCP{
			Request:  reqBody,
			Response: resBody,
		}

		rec.Data = tcpData
	case "default":
		reqBody, resBody, _ := buildRawRecord(req.(*RawRecord), resp.(*RawRecord))

		tcpData := &TCP{
			Request:  reqBody,
			Response: resBody,
		}

		rec.Data = tcpData
	}

	return rec, nil
}

func buildRawRecord(req, resp *RawRecord) (*Raw, *Raw, error) {
	reqRecord := &Raw{
		Hash:  fmt.Sprintf("%x", req.Hasher.Sum(nil)),
		Bytes: req.Count,
	}

	respRecord := &Raw{
		Hash:  fmt.Sprintf("%x", resp.Hasher.Sum(nil)),
		Bytes: resp.Count,
	}

	return reqRecord, respRecord, nil
}

func buildHTTPRecord(req *http.Request, resp *http.Response, tls bool) (*HTTP, *HTTP, error) {
	reqRecord := &HTTP{
		TLS:     tls,
		Headers: req.Header,
		Method:  req.Method,
	}

	if req.Body != nil {
		hexh, size, rc, err := HashAndReplaceBody(req.Body)
		if err == nil {
			reqRecord.Hash = hexh
			reqRecord.Bytes = size
			req.Body = rc
		}
	}

	respRecord := &HTTP{
		TLS:        tls,
		Headers:    resp.Header,
		StatusCode: resp.StatusCode,
	}

	if resp != nil && resp.Body != nil {
		hexh, size, rc, err := HashAndReplaceBody(resp.Body)
		if err == nil {
			respRecord.Hash = hexh
			respRecord.Bytes = size
			resp.Body = rc
		}
	}

	return reqRecord, respRecord, nil
}

// -- UDP --

type UDP struct {
	Data ApplicationData `json:"data,omitempty"`
}

func (*UDP) isTransportData() {}

type DNSAnswer struct {
	Name  string `json:"name"`
	Type  uint16 `json:"type"`
	Class uint16 `json:"class"`
	TTL   uint32 `json:"ttl"`
	Body  string `json:"data"`
}

func (*DNSAnswer) isApplicationData() {}

type DNSMessage struct {
	ID      uint16 `json:"ID"`
	IsQuery bool   `json:"is_query"`
	Opcode  uint8  `json:"op_code"`
	Rcode   uint8  `json:"r_code"`

	QDCount uint16 `json:"qd_count"`
	ANCount uint16 `json:"an_count"`
	NSCount uint16 `json:"ns_count"`
	ARCount uint16 `json:"ar_count"`

	Question string `json:"question"`
	QType    uint16 `json:"q_type"`
	QClass   uint16 `json:"q_class"`

	Answers []DNSAnswer `json:"answers,omitempty"`
}

func (*DNSMessage) isApplicationData() {}

func BuildUDPRecord(payload []byte, clientAddr, destAddr, proto string) *Packet {
	rawPacket := &Packet{
		Protocol: ProtocolUDP,
		SrcAddr:  clientAddr,
		DstAddr:  destAddr,
	}

	switch proto {
	case "dns":
		dnsMessage, _ := buildDNS(payload)
		rawPacket.Data = &UDP{
			Data: dnsMessage,
		}
	default:
		break
	}
	return rawPacket
}

func buildDNS(payload []byte) (*DNSMessage, error) {
	var msgParsed dnsmessage.Message
	if err := msgParsed.Unpack(payload); err != nil {
		return nil, fmt.Errorf("dns unpack: %w", err)
	}

	msg := &DNSMessage{
		ID:      msgParsed.Header.ID,
		IsQuery: !msgParsed.Header.Response,
		Opcode:  uint8(msgParsed.Header.OpCode),
		Rcode:   uint8(msgParsed.Header.RCode),

		QDCount: uint16(len(msgParsed.Questions)),
		ANCount: uint16(len(msgParsed.Answers)),
		NSCount: uint16(len(msgParsed.Authorities)),
		ARCount: uint16(len(msgParsed.Additionals)),
	}

	if len(msgParsed.Questions) > 0 {
		q := msgParsed.Questions[0]
		msg.Question = q.Name.String()
		msg.QType = uint16(q.Type)
		msg.QClass = uint16(q.Class)
	}

	answers := make([]DNSAnswer, 0, len(msgParsed.Answers))
	for _, a := range msgParsed.Answers {
		ans := DNSAnswer{}
		n := a.Header.Name
		ans.Name = string(n.Data[:n.Length])
		ans.Type = uint16(a.Header.Type)
		ans.TTL = uint32(a.Header.TTL)
		ans.Body = a.Body.GoString()
		ans.Class = uint16(a.Header.Class)
		answers = append(answers, ans) // human-readable
	}
	msg.Answers = answers

	return msg, nil
}

// -- Common --

func AppendRecord(path string, rec Packet) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}
	defer f.Close()

	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal record: %w", err)
	}

	b = append(b, '\n')
	if _, err := f.Write(b); err != nil {
		return fmt.Errorf("write record: %w", err)
	}

	return nil
}
