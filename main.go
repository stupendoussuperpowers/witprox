package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/elazarl/goproxy"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sync"

	"time"

	"github.com/google/uuid"

	"github.com/stupendoussuperpowers/witprox/pkg/certificates"
	"github.com/stupendoussuperpowers/witprox/pkg/networklog"
	"github.com/stupendoussuperpowers/witprox/pkg/tlsutils"

	"bufio"
)

func main() {
	// The TLS proxy can only run if we have a generated certificate that is trusted by ths host computer.
	// In order to generate and save a certicate to disk, use this flag. You'll be prompted to use this
	// flag in case a cert file is not detected at `/tmp/witprox-ca.pem` or a key file is not detected at
	// `/tmp/witprox-key.pem`
	flagGenerate := flag.Bool("generate-ca", false, "Generate a new TLS certificate")
	flag.Parse()

	ca := certificates.LoadCA()

	if *flagGenerate {
		log.Println("Generating a new TLS certificate")
		ca = certificates.GenerateCA()
		certificates.PersistCA(ca)
		log.Printf("New cert generated and saved to %s. Add it to the trusted certs on your system\n", "")
		return
	} else if ca == nil {
		log.Println("No existing certificate. Use --generate-ca to save one.")
		return
	} else {
		log.Println("Loaded existing certificate")
	}

	ConfigureCert(ca)

	Run("localhost:1234")
}

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

const proxyIDHeader = "X-Proxy-Req-Id"

var (
	startTimes sync.Map
)

func Run(listenAddr string) error {
	proxyServer := goproxy.NewProxyHttpServer()
	proxyServer.Verbose = true

	proxyServer.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		fmt.Printf("Request: %s %s\n", req.Method, req.URL)

		id := uuid.NewString()
		req.Header.Set(proxyIDHeader, id)
		startTimes.Store(id, time.Now().UTC())

		return req, nil
	})

	proxyServer.OnResponse().DoFunc(func(res *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		fmt.Printf("Response: %s %s\n", res.Request.Method, res.Request.URL)

		var id string
		if res != nil && res.Request != nil {
			id = res.Request.Header.Get(proxyIDHeader)
		}

		var start time.Time
		if id != "" {
			if v, ok := startTimes.Load(id); ok {
				if t, ok2 := v.(time.Time); ok2 {
					start = t
				}
				startTimes.Delete(id)
			}
		}

		clientAddr := ""

		if ctx != nil && ctx.Req != nil {
			clientAddr = ctx.Req.RemoteAddr
		} else {
			clientAddr = res.Request.RemoteAddr
		}

		rec, err := networklog.BuildNetworkRecord(res.Request, res, start, time.Now(), clientAddr, "")

		if err != nil {
			fmt.Println("Build record failed")
			return res
		}

		err = networklog.AppendRecord(fmt.Sprintf("/tmp/proxy_%s.log", id), rec)
		if err != nil {
			fmt.Println("Append record failed")
			return res
		}

		return res
	})

	var alwaysMitmHTTP goproxy.FuncHttpsHandler = func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		return goproxy.HTTPMitmConnect, host
	}
	proxyServer.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile("^[^:]*(:80)?$"))).
		HandleConnect(alwaysMitmHTTP)

	proxyServer.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile("^.*:" + "443" + "$"))).
		HandleConnect(goproxy.AlwaysMitm)

	go ServeTLS(proxyServer)
	ServeHTTP()

	return nil
}

// All HTTP traffic is proxied by this function, which acts as a middleware to perform logging.
func ServeHTTP() {
	listener, err := net.Listen("tcp", "localhost:1233")
	if err != nil {
		log.Fatalf("Error listening on 1233 - %v\n", err)
	}

	for {
		fmt.Println("Waiting for HTTP Connections")
		conn, err := listener.Accept()
		if err != nil {
			if err == net.ErrClosed {
				return
			}

			fmt.Printf("Error accepting HTTP connection: %v\n", err)
			continue
		}

		go func(conn net.Conn) {
			defer conn.Close()

			start := time.Now()

			// Read the request sent by the client.
			bufreader := bufio.NewReader(conn)
			req, err := http.ReadRequest(bufreader)
			if err != nil {
				log.Printf("bad http req: %v\n", err)
				return
			}

			// Connect to the originally intended target.
			destAddr := fmt.Sprintf("%s:%d", req.Host, 80)
			dst, err := net.Dial("tcp", destAddr)
			if err != nil {
				log.Printf("dial error %v\n", err)
				return
			}

			defer dst.Close()
			// Send the originally intended request to the target.
			if err := req.Write(dst); err != nil {
				log.Printf("write error: %v\n", err)
				return
			}

			// Read the response received from the target.
			resp, err := http.ReadResponse(bufio.NewReader(dst), req)
			if err != nil {
				log.Printf("read error: %v\n", err)
				return
			}

			// Log response hash/size/etc.
			fullyQualName := fmt.Sprintf("http://%s", destAddr)
			rec, err := networklog.BuildNetworkRecord(req, resp, start, time.Now(), conn.RemoteAddr().String(), fullyQualName)

			// Forward the response back to the original client.
			if err := resp.Write(conn); err != nil {
				log.Printf("failed to send to client: %v\n", err)
				_ = resp.Body.Close()
				return
			}

			_ = resp.Body.Close()

			if err != nil {
				fmt.Println("Build record failed")
				return
			}

			// Save log to a log file.
			err = networklog.AppendRecord(fmt.Sprintf("/tmp/proxy_%s.log", "http"), rec)
			if err != nil {
				fmt.Println("Append record failed")
				return
			}
		}(conn)
	}
}

func ServeTLS(proxyServer *goproxy.ProxyHttpServer) {
	// Run TLS Server
	listener, err := net.Listen("tcp", "localhost:1234")
	if err != nil {
		log.Fatalf("Error listening on 1234")
	}

	fmt.Println("Server listening on port: 1234")

	var inflight sync.WaitGroup

	for {
		fmt.Println("Waiting for connections")
		conn, err := listener.Accept()
		if err != nil {
			if err == net.ErrClosed {
				return
			}
			fmt.Printf("Error accepting connection: %v\n", err)
			continue
		}

		inflight.Add(1)

		defer inflight.Done()

		go func(c net.Conn) {
			fmt.Println("Connection from: ", c.RemoteAddr())

			conn, hello, err := tlsutils.PeekClientHello(c)
			if err != nil {
				fmt.Printf("Error peaking tls - %v\n", err)
				return
			}

			host := hello.ServerName
			if host == "" {
				fmt.Println("Non SNI client")
				return
			}
			fmt.Printf("Host: %s\n", host)
			fmt.Printf("Remote Addr: %s\n", c.RemoteAddr().String())
			connectReq := &http.Request{
				Method: "CONNECT",
				URL: &url.URL{
					Host: net.JoinHostPort(host, "443"),
				},
				Host:       net.JoinHostPort(host, "443"),
				Header:     make(http.Header),
				RemoteAddr: c.RemoteAddr().String(),
			}

			ecrw := tlsutils.EatConnectResponseWriter{conn}
			proxyServer.ServeHTTP(ecrw, connectReq)

		}(conn)
	}

}
