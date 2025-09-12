package tlsutils

import (
	"bufio"
	"bytes"
	"errors"
	"golang.org/x/crypto/cryptobyte"
	"io"
	"net"
	"net/http"
	"strings"
)

// eatConnectResponseWriter drops the goproxy response to the HTTP CONNECT tunnel creation.
type EatConnectResponseWriter struct {
	net.Conn
}

func (tc EatConnectResponseWriter) Header() http.Header {
	panic("unexpected Header() call")
}

func (tc EatConnectResponseWriter) Write(buf []byte) (int, error) {
	if bytes.Equal(buf, []byte("HTTP/1.0 200 OK\r\n\r\n")) {
		return len(buf), nil // ignore the HTTP OK response Write() from the CONNECT request
	}
	return tc.Conn.Write(buf)
}

func (tc EatConnectResponseWriter) WriteHeader(code int) {
	panic("unexpected WriteHeader() call")
}

func (tc EatConnectResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return tc, bufio.NewReadWriter(bufio.NewReader(tc), bufio.NewWriter(tc)), nil
}

const (
	// TLS golang constants.
	recordHeaderLen = 5
	// TLS handshake message types.
	typeClientHello uint8 = 1
	// TLS extension numbers.
	extensionServerName uint16 = 0
	// TLS record types.
	recordTypeAlert     uint8 = 21
	recordTypeHandshake uint8 = 22
)

// ClientHelloMsg represents the ClientHello portion of the TLS handshake.
// Adapted from https://github.com/golang/go/blob/074f2761b5ff54c9c9d2e2a720abd29efa5474cc/src/crypto/tls/handshake_messages.go#L71
type ClientHelloMsg struct {
	Vers               uint16
	Random             []byte
	SessionID          []byte
	CipherSuites       []uint16
	CompressionMethods []uint8
	ServerName         string
}

type peekedConn struct {
	net.Conn
	buf io.Reader
}

func (pc peekedConn) Read(p []byte) (int, error) {
	n, err := pc.buf.Read(p)
	if err == io.EOF {
		if n == 0 {
			return pc.Conn.Read(p)
		}
		return n, nil
	}
	return n, err
}

// PeekClientHello reads the ClientHello TLS handshake record and returns it as well as a Conn without it read.
func PeekClientHello(c net.Conn) (net.Conn, *ClientHelloMsg, error) {
	buf := new(bytes.Buffer)
	data, err := nextRecord(c, buf)
	if err != nil {
		return nil, nil, err
	}
	if data[0] != typeClientHello {
		return nil, nil, errors.New("tls: unexpected message")
	}
	m := newClientHelloMsg(data)
	if m == nil {
		return nil, nil, errors.New("tls: failed to parse ClientHello")
	}
	return peekedConn{c, buf}, m, err
}

// nextRecord reads a TLS record and returns the body.
// Adapted from https://github.com/golang/go/blob/074f2761b5ff54c9c9d2e2a720abd29efa5474cc/src/crypto/tls/conn.go#L612
func nextRecord(r io.Reader, buf *bytes.Buffer) ([]byte, error) {
	buf.Truncate(0)
	chunk := make([]byte, bytes.MinRead)
	for buf.Len() < recordHeaderLen {
		b, err := r.Read(chunk)
		if err != nil {
			return []byte{}, err
		}
		buf.Write(chunk[:b])
	}
	hdr := buf.Bytes()[:recordHeaderLen]
	typ := uint8(hdr[0])
	vers := uint16(hdr[1])<<8 | uint16(hdr[2])
	n := int(hdr[3])<<8 | int(hdr[4])
	// Be extra suspicious of first message: this might not be a TLS client.
	if (typ != recordTypeAlert && typ != recordTypeHandshake) || vers >= 0x1000 {
		return []byte{}, errors.New("tls: first record does not look like a TLS handshake")
	}
	for buf.Len() < recordHeaderLen+n {
		b, err := r.Read(chunk)
		if err != nil {
			return []byte{}, err
		}
		buf.Write(chunk[:b])
	}
	return buf.Bytes()[recordHeaderLen : recordHeaderLen+n], nil
}

// newClientHelloMsg constructs a ClientHelloMsg from a ClientHello TLS record's body.
// Adapted from https://github.com/golang/go/blob/074f2761b5ff54c9c9d2e2a720abd29efa5474cc/src/crypto/tls/handshake_messages.go#L416
func newClientHelloMsg(data []byte) *ClientHelloMsg {
	m := new(ClientHelloMsg)
	s := cryptobyte.String(data)
	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16(&m.Vers) || !s.ReadBytes(&m.Random, 32) ||
		!s.ReadUint8LengthPrefixed((*cryptobyte.String)(&m.SessionID)) {
		return nil
	}
	var cipherSuites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuites) {
		return nil
	}
	m.CipherSuites = []uint16{}
	for !cipherSuites.Empty() {
		var suite uint16
		if !cipherSuites.ReadUint16(&suite) {
			return nil
		}
		m.CipherSuites = append(m.CipherSuites, suite)
	}
	if !s.ReadUint8LengthPrefixed((*cryptobyte.String)(&m.CompressionMethods)) {
		return nil
	}
	if s.Empty() {
		// ClientHello is optionally followed by extension data
		return m
	}
	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return nil
	}
	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return nil
		}
		switch extension {
		case extensionServerName:
			// RFC 6066, Section 3
			var nameList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&nameList) || nameList.Empty() {
				return nil
			}
			for !nameList.Empty() {
				var nameType uint8
				var serverName cryptobyte.String
				if !nameList.ReadUint8(&nameType) ||
					!nameList.ReadUint16LengthPrefixed(&serverName) ||
					serverName.Empty() {
					return nil
				}
				if nameType != 0 {
					continue
				}
				if len(m.ServerName) != 0 {
					// Multiple names of the same name_type are prohibited.
					return nil
				}
				m.ServerName = string(serverName)
				// An SNI value may not include a trailing dot.
				if strings.HasSuffix(m.ServerName, ".") {
					return nil
				}
			}
		default:
			// Ignore all other extensions.
			continue
		}
		if !extData.Empty() {
			return nil
		}
	}
	return m
}
