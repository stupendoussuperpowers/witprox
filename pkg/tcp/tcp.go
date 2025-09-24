package tcp

import (
	"fmt"
	"log"
	"net"
	"bufio"
	"net/http"
	"net/url"
	"sync"
	"regexp"
	"errors"
	"strings"
	"os"
	"io"
	"time"
	"runtime"
	"crypto/tls"

	"github.com/google/uuid"
	"github.com/elazarl/goproxy"

	"github.com/stupendoussuperpowers/witprox/pkg/app"
	"github.com/stupendoussuperpowers/witprox/pkg/tlsutils"
	"github.com/stupendoussuperpowers/witprox/pkg/networklog"
	"golang.org/x/sys/unix"
)

const proxyIDHeader = "X-Proxy-Req-Id"

var (
	startTimes   sync.Map
)

func ServeTCP() {
	var err error
	app.TCPListener, err = net.Listen("tcp", fmt.Sprintf("localhost:%d", app.Config.TCPPort))
	
	if err != nil {
		log.Printf("Error listening on port 1230\n")
		return
	}

	for {
		conn, err := app.TCPListener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Fatalf("Error listening on 1230\n")
		}

		go func(c net.Conn) {
			proto, br, err := detectProtocol(c)
			if err != nil {
				log.Println("Error in detect Protocol:", err)
				c.Close()
				return
			}

			log.Println("Proto: ", proto)
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
		logCat := fLogger()
		logCat.Printf("Request: %s %s\n", req.Method, req.URL)

		id := uuid.NewString()
		req.Header.Set(proxyIDHeader, id)
		startTimes.Store(id, time.Now().UTC())

		return req, nil
	})

	app.Config.ProxyServer.OnResponse().DoFunc(func(res *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		logCat := fLogger()
		logCat.Printf("Response: %d %s %s\n", res.StatusCode, res.Request.Method, res.Request.URL)

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

		rec, _ := networklog.BuildTCPRecord(res.Request, res, start, time.Now(), res.Request.URL.String(), clientAddr, "http") 

		err := networklog.AppendRecord(app.Config.Log, rec)
		if err != nil {
			log.Println("Append record failed")
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
        log.Println("Error!", err)
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

func fLogger() *log.Logger {
	pc, _, _, ok := runtime.Caller(1)
	prefix := ""
	if ok {
		fn := runtime.FuncForPC(pc)
		if fn != nil {
			prefix = fmt.Sprintf("[%s] ", fn.Name())
		}
	}

	return log.New(os.Stdout, prefix, log.LstdFlags|log.Lmsgprefix)
}

func handleDefault(conn net.Conn, bufreader *bufio.Reader) {
	logCat := fLogger()

	start := time.Now()
	
	logCat.Printf("Connection from: %v\n", conn.RemoteAddr())

	port, destAddr, err := getOriginalDst(conn.(*net.TCPConn))
	if err != nil {
		logCat.Printf("Error getOriginalDst: ", err)
		return
	}

	// Connect to original target.
	dialAddr := fmt.Sprintf("%s:%d", destAddr, port)
	dst, err := net.Dial("tcp", dialAddr)
	if err != nil {
		logCat.Printf("dial error %v\n", err)
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

	logCat.Printf("Connection closed.\n")
	
	rec, _ := networklog.BuildTCPRecord(client, server, start, time.Now(), dialAddr, conn.RemoteAddr().String(), "Unknown") 

	networklog.AppendRecord(app.Config.Log, rec)
}

func handleHTTP(conn net.Conn, bufreader *bufio.Reader) {
	logCat := fLogger()
	logCat.Printf("Connection from: %v\n", conn.RemoteAddr())

	start := time.Now()

	req, err := http.ReadRequest(bufreader)
	if err != nil {
		logCat.Printf("bad http req: %v\n", err)
		return
	}

	logCat.Printf("Request: %s %s%s", req.Method, req.Host, req.URL)

	port, _, err := getOriginalDst(conn.(*net.TCPConn))
	if err != nil {
		logCat.Printf("Error getOriginalDst: ", err)
		return
	}

	log.Printf("port: %d\n", port)
	// Connect to original target.

	usePort := ":80"
	if strings.Contains(req.Host, ":") {
		usePort = ""	
	} 
	
	destAddr := fmt.Sprintf("%s%s", req.Host, usePort)
	
	dst, err := net.Dial("tcp", destAddr)
	if err != nil {
		logCat.Printf("dial error %v\n", err)
		return
	}

	defer dst.Close()
	// Send the originally intended request to the target.
	if err := req.Write(dst); err != nil {
		logCat.Printf("write error: %v\n", err)
		return
	}

	// Read the response received from the target.
	resp, err := http.ReadResponse(bufio.NewReader(dst), req)
	if err != nil {
		logCat.Printf("read error: %v\n", err)
		return
	}

	// Log response hash/size/etc.
	fullyQualName := fmt.Sprintf("http://%s", destAddr)

	// Forward the response back to the original client.
	if err := resp.Write(conn); err != nil {
		logCat.Printf("failed to send to client: %v\n", err)
		_ = resp.Body.Close()
		return
	}

	logCat.Printf("Response: %d %s %s%s\n", resp.StatusCode, req.Method, req.Host, req.URL)

	_ = resp.Body.Close()

	if err != nil {
		logCat.Println("Build record failed")
		return
	}

	rec, _ := networklog.BuildTCPRecord(req, resp, start, time.Now(), fullyQualName, conn.RemoteAddr().String(), "http") 

	log.Printf("HTTP Rec: %v\n", rec)

	// Save log to a log file.
	err = networklog.AppendRecord(app.Config.Log, rec)
	if err != nil {
		logCat.Println("Append record failed")
		return
	}
}

func getOriginalDst(conn *net.TCPConn) (int, string, error) {
	file, err := conn.File()
	if err != nil {
		return -1, "", err
	}

	defer file.Close()
	fd := int(file.Fd())

	addr, err := unix.GetsockoptIPv6Mreq(int(fd), unix.SOL_IP, 80)
	if err != nil {
		return -1, "", err
	}

	server := fmt.Sprintf("%d.%d.%d.%d", 
		addr.Multiaddr[4],
		addr.Multiaddr[5],
		addr.Multiaddr[6],
		addr.Multiaddr[7],
	)

	return int(addr.Multiaddr[2]) << 8 | int(addr.Multiaddr[3]), server, nil
}

func handleTLS(c net.Conn, br *bufio.Reader) {
	logCat := fLogger()
	logCat.Println("Connection from: ", c.RemoteAddr())

	// We read the TLS Hello message sent by the client to get information about
	// the original intended target. Unlike HTTP this is not transparently available
	// and needs some parsing on our end.
	// conn, hello, err := tlsutils.PeekClientHello(c)
	conn, hello, err := tlsutils.PeekClientHelloBufReader(c, br)
	if err != nil {
		logCat.Printf("Error peaking tls - %v\n", err)
		return
	}

	port, _, err := getOriginalDst(c.(*net.TCPConn))
	if err != nil {
		logCat.Println("gOD: ", err)
		return
	}

	host := hello.ServerName
	if host == "" {
		logCat.Println("Non SNI client")
		return
	}

	// Create a custom CONNECT request to the original target, and then forward it to the client.
	connectReq := &http.Request{
		Method: "CONNECT",
		URL: &url.URL{
			Host: net.JoinHostPort(host, fmt.Sprintf("%d", port)),
		},
		Host:       net.JoinHostPort(host, fmt.Sprintf("%d", port)),
		Header:     make(http.Header),
		RemoteAddr: c.RemoteAddr().String(),
	}

	// This custom writer makes sure that we don't send a duplicate CONNECT response back to the client.
	// It "eats" the CONNECT response.
	ecrw := tlsutils.EatConnectResponseWriter{conn}
	app.Config.ProxyServer.ServeHTTP(ecrw, connectReq)
}
