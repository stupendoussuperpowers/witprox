package tcp

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/elazarl/goproxy"
	"github.com/google/uuid"

	"github.com/stupendoussuperpowers/witprox/pkg/app"
	"github.com/stupendoussuperpowers/witprox/pkg/networklog"
	"github.com/stupendoussuperpowers/witprox/pkg/tlsutils"
)

const proxyIDHeader = "X-Proxy-Req-Id"

var log = app.GetLogger("TCP")

var (
	startTimes sync.Map
)

type ConnInfo struct {
	OrigDstIp   uint32
	OrigDstPort uint32
	PID         uint32
	Padding     uint32
}

var connInfoMap sync.Map

func ServeTCP() {
	var err error
	app.TCPListener, err = net.Listen("tcp", fmt.Sprintf("localhost:%d", app.Config.TCPPort))

	if err != nil {
		return
	} else {
		log.Infof("TCP server listening on: %d\n", app.Config.TCPPort)
	}

	for {
		conn, err := app.TCPListener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Fatalf("TCPListener.Accept() error: %v\n", err)
		}

		go func(c net.Conn) {
			proto, br, err := detectProtocol(c)
			if err != nil {
				log.Info("Error in detect Protocol:", err)
				c.Close()
				return
			}

			switch proto {
			case "http":
				handleHTTP(c, br)
			case "tls":
				handleTLS(c, br)
			default:
				handleDefault(c, br)
			}
		}(conn)
	}
}

func SetupTLS(ca *tls.Certificate) {
	ConfigureCert(ca)

	app.Config.ProxyServer = goproxy.NewProxyHttpServer()
	app.Config.ProxyServer.Verbose = app.Config.Verbose

	// Tag requests before sending it to the server so that we can use it to store custom metrics. (Start time in
	// this case).
	app.Config.ProxyServer.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		log.Infof("Request: %s %s\n", req.Method, req.URL)

		id := uuid.NewString()
		req.Header.Set(proxyIDHeader, id)
		startTimes.Store(id, time.Now())

		return req, nil
	})

	app.Config.ProxyServer.OnResponse().DoFunc(func(res *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		log.Infof("Response: %d %s %s\n", res.StatusCode, res.Request.Method, res.Request.URL)

		var PID uint32
		var origDst string
		var origDstPort uint32
		if v, ok := connInfoMap.Load(res.Request.RemoteAddr); ok {
			origInfo := v.(string)
			fmt.Sscanf(origInfo, "%s %d %d", &origDst, &origDstPort, &PID)
		} else {
			log.Infof("Unable to read connInfoMap\n")
		}

		log.Infof("PID %d wants to talk to %s:%d\n", PID, origDst, origDstPort)

		// Use the earlier used tag to retrieve custom logging metrics, and then delete this tag before it gets
		// stored in the log.
		var id string
		if res != nil && res.Request != nil {
			id = res.Request.Header.Get(proxyIDHeader)
		}

		res.Header.Del(proxyIDHeader)
		res.Request.Header.Del(proxyIDHeader)

		var start time.Time
		if id != "" {
			if v, ok := startTimes.Load(id); ok {
				if t, ok2 := v.(time.Time); ok2 {
					start = t
				}
				startTimes.Delete(id)
			}
		}

		// Retrieve and store network records to disk at app.Config.TLSLog
		clientAddr := ""
		if ctx != nil && ctx.Req != nil {
			clientAddr = ctx.Req.RemoteAddr
		} else {
			clientAddr = res.Request.RemoteAddr
		}

		rec, _ := networklog.BuildTCPRecord(res.Request, res, start, time.Now(), res.Request.URL.String(), clientAddr, "tls")

		err := networklog.AppendRecord(fmt.Sprintf("%s/tls.%d", app.Config.Log, PID), *rec)
		if err != nil {
			log.Info("Append record failed")
			return res
		}

		return res
	})

	// Use goproxy's MITM app.Config for all TLS requests.
	app.Config.ProxyServer.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile("^.*:443$"))).
		HandleConnect(goproxy.AlwaysMitm)
}

// This setups up the goproxy so that it can use it's MITM confic and serve the certificate we generated
// to the client process making the network calls. To view more logs of this works, use --verbose flags.
// Documentation: https://pkg.go.dev/github.com/elazarl/goproxy#readme-proxy-modes
func ConfigureCert(ca *tls.Certificate) {
	goproxy.OkConnect = &goproxy.ConnectAction{
		Action: goproxy.ConnectAccept, TLSConfig: goproxy.TLSConfigFromCA(ca)}

	goproxy.MitmConnect = &goproxy.ConnectAction{
		Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(ca)}

	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{
		Action: goproxy.ConnectHTTPMitm, TLSConfig: goproxy.TLSConfigFromCA(ca)}

	goproxy.RejectConnect = &goproxy.ConnectAction{
		Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(ca)}
}

func detectProtocol(c net.Conn) (string, *bufio.Reader, error) {
	br := bufio.NewReader(c)

	// Peek at the first 24 bytes (enough for TLS, HTTP, HTTP/2 detection)
	header, err := br.Peek(24)
	if err != nil && err != bufio.ErrBufferFull {
		log.Info("Error!", err)
		return "", nil, err
	}

	if len(header) >= 5 {
		// TLS: check ContentType + Version
		if header[0] == 0x16 && header[1] == 0x03 &&
			(header[2] == 0x00 || header[2] == 0x01 || header[2] == 0x02 || header[2] == 0x03) {
			return "tls", br, nil
		}
	}

	if len(header) >= 8 {
		s := string(header)
		// HTTP/1.x methods
		methods := []string{"GET", "POST", "PUT", "HEAD", "OPTIONS", "DELETE", "PATCH", "CONNECT", "TRACE"}
		for _, m := range methods {
			if strings.HasPrefix(s, m) {
				return "http", br, nil
			}
		}

		// HTTP/2 connection preface
		if s == "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" || strings.HasPrefix(s, "PRI * HTTP/2") {
			return "http2", br, nil
		}
	}

	// Fallback: could be plain text or unknown binary protocol
	return "unknown", br, nil
}

func handleDefault(conn net.Conn, bufreader *bufio.Reader) {
	start := time.Now()

	log.Infof("Connection from: %v\n", conn.RemoteAddr())

	destAddr, port, _, err := getConnInfo(conn)
	if err != nil {
		log.Infof("Error getting original destination: %w\n", err)
		return
	}

	// Connect to original target.
	dialAddr := fmt.Sprintf("%s:%d", destAddr, port)
	dst, err := net.Dial("tcp", dialAddr)
	if err != nil {
		log.Infof("dial error %v\n", err)
		return
	}
	defer dst.Close()

	// Relay information between channels
	done := make(chan struct{}, 2)

	client := networklog.NewRawRecord(conn)
	server := networklog.NewRawRecord(dst)

	go func() {
		_, _ = io.Copy(server, bufreader)
		done <- struct{}{}
	}()

	go func() {
		_, _ = io.Copy(client, server)
		done <- struct{}{}
	}()

	<-done

	log.Infof("Connection closed.\n")

	rec, _ := networklog.BuildTCPRecord(client, server, start, time.Now(), dialAddr, conn.RemoteAddr().String(), "Unknown")

	networklog.AppendRecord(app.Config.Log+"/raw", *rec)
}

func handleHTTP(conn net.Conn, bufreader *bufio.Reader) {
	log.Infof("Connection from: %v\n", conn.RemoteAddr())

	start := time.Now()

	req, err := http.ReadRequest(bufreader)
	if err != nil {
		log.Infof("bad http req: %v\n", err)
		return
	}

	log.Infof("Request: %s %s%s\n", req.Method, req.Host, req.URL)

	PID, port, _, err := getConnInfo(conn)
	if err != nil {
		log.Infof("Error getOriginalDst: %v\n", err)
		return
	}

	log.Infof("port: %d\n", port)

	destIP := networklog.IPAddr{Host: req.Host, Port: int(port)}

	dst, err := net.Dial("tcp", destIP.String())
	if err != nil {
		log.Infof("dial error %v\n", err)
		return
	}

	defer dst.Close()
	// Send the originally intended request to the target.
	if err := req.Write(dst); err != nil {
		log.Infof("write error: %v\n", err)
		return
	}

	// Read the response received from the target.
	resp, err := http.ReadResponse(bufio.NewReader(dst), req)
	if err != nil {
		log.Infof("read error: %v\n", err)
		return
	}

	// Log response hash/size/etc.
	fullyQualName := fmt.Sprintf("http://%s", destIP.String())

	// Forward the response back to the original client.
	if err := resp.Write(conn); err != nil {
		log.Infof("failed to send to client: %v\n", err)
		_ = resp.Body.Close()
		return
	}

	log.Infof("Response: %d %s %s%s\n", resp.StatusCode, req.Method, req.Host, req.URL)

	_ = resp.Body.Close()

	rec, _ := networklog.BuildTCPRecord(req, resp, start, time.Now(), fullyQualName, conn.RemoteAddr().String(), "http")

	log.Infof("HTTP Rec: %v\n", rec)

	// Save log to a log file.
	err = networklog.AppendRecord(fmt.Sprintf("%s/http.%d", app.Config.Log, PID), *rec)
	if err != nil {
		log.Info("Append record failed")
		return
	}
}

func getConnInfo(conn net.Conn) (net.IP, uint32, uint32, error) {
	tcpConn, _ := conn.(*net.TCPConn)

	// First, get the socket cookie.
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		log.Info("Failed to get raw conn")
		return nil, 0, 0, fmt.Errorf("failed to get raw conn")
	}

	var cookie uint64
	var sockErr error

	err = rawConn.Control(func(fd uintptr) {
		cookieBytes := make([]byte, 8)
		sockLen := uint32(8)

		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			syscall.SOL_SOCKET,
			57, // SO_COOKIE
			uintptr(unsafe.Pointer(&cookieBytes[0])),
			uintptr(unsafe.Pointer(&sockLen)),
			0,
		)

		if errno != 0 {
			sockErr = fmt.Errorf("getsockopt failed")
			return
		}

		cookie = binary.NativeEndian.Uint64(cookieBytes)
	})

	if err != nil {
		return nil, 0, 0, fmt.Errorf("control failed")
	}

	if sockErr != nil {
		return nil, 0, 0, sockErr
	}

	// Use cookie to get info about the original connection. This runs POST eBPF builds the maps
	connMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/server_map", nil)
	if err != nil {
		log.Info("Failed to load connmap %w\n", err)
	}
	defer connMap.Close()

	var info ConnInfo
	err = connMap.Lookup(unsafe.Pointer(&cookie), unsafe.Pointer(&info))
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed lookup")
	}

	connMap.Delete(unsafe.Pointer(&cookie))

	// Convert IP, and Port to correct byte order
	origDstBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(origDstBytes, info.OrigDstIp)

	return net.IP(origDstBytes), (info.OrigDstPort>>8)&0xFF | (info.OrigDstPort&0xFF)<<8, info.PID, nil
}

func handleTLS(c net.Conn, br *bufio.Reader) {
	log.Infof("[TLS] Connection from: %s\n", c.RemoteAddr())

	// We read the TLS Hello message sent by the client to get information about
	// the original intended target. Unlike HTTP this is not transparently available
	// and needs some parsing on our end.
	// conn, hello, err := tlsutils.PeekClientHello(c)
	conn, hello, err := tlsutils.PeekClientHelloBufReader(c, br)
	if err != nil {
		log.Infof("Error peaking tls - %v\n", err)
		return
	}

	origDst, origPort, origPID, err := getConnInfo(c)
	if err != nil {
		log.Info("getConnInfo Failed: ", err)
	}

	host := hello.ServerName
	if host == "" {
		log.Info("Non SNI client")
		return
	}

	// Create a custom CONNECT request to the original target, and then forward it to the client.
	connectReq := &http.Request{
		Method: "CONNECT",
		URL: &url.URL{
			Host: net.JoinHostPort(host, fmt.Sprintf("%d", origPort)),
		},
		Host:       net.JoinHostPort(host, fmt.Sprintf("%d", origPort)),
		Header:     make(http.Header),
		RemoteAddr: c.RemoteAddr().String(),
	}

	connInfoMap.Store(c.RemoteAddr().String(), fmt.Sprintf("%s %d %d", origDst.String(), origPort, origPID))
	// This custom writer makes sure that we don't send a duplicate CONNECT response back to the client.
	// It "eats" the CONNECT response.
	ecrw := tlsutils.EatConnectResponseWriter{conn}
	app.Config.ProxyServer.ServeHTTP(ecrw, connectReq)
}
