package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"sync"
	"syscall"

	"errors"
	"github.com/elazarl/goproxy"

	"time"

	"github.com/google/uuid"

	"github.com/stupendoussuperpowers/witprox/pkg/certificates"
	"github.com/stupendoussuperpowers/witprox/pkg/networklog"
	"github.com/stupendoussuperpowers/witprox/pkg/tlsutils"

	"bufio"
)

type WitproxConfig struct {
	TLSPort  int64
	HTTPPort int64
	CaPath   string
	KeyPath  string
	HTTPLog  string
	TLSLog   string
	Verbose  bool
}

const proxyIDHeader = "X-Proxy-Req-Id"

var (
	startTimes   sync.Map
	TLSListener  net.Listener
	HTTPListener net.Listener
	config       WitproxConfig
)

func main() {
	// This flag is used if we need to generate a fresh TLS certificate. More details are documented below.
	flagGenerate := flag.Bool("generate-ca", false, "Generate a new TLS certificate")
	flagInstall := flag.Bool("install-ca", false, "Install the certificate at cert-path. Only supported on Debian/Ubunut.")
	flagTLSPort := flag.Int64("tls-port", 1234, "Configure the TLS Port on localhost")
	flagHTTPPort := flag.Int64("http-port", 1233, "Configure the HTTP Port on localhost")
	flagCaPath := flag.String("cert-path", "/tmp/witproxca.crt", "TLS Certificate Path")
	flagKeyPath := flag.String("key-path", "/tmp/witproxkey.pem", "TLS Certificate Path")
	flagHTTPLog := flag.String("http-log", "/tmp/witprox.http.log", "Log file for HTTP requests")
	flagTLSLog := flag.String("tls-log", "/tmp/witprox.tls.log", "Log file for TLS requests")
	flagVerbose := flag.Bool("verbose", false, "Goproxy verbose logs")

	flag.Parse()

	config = WitproxConfig{
		TLSPort:  *flagTLSPort,
		HTTPPort: *flagHTTPPort,
		CaPath:   *flagCaPath,
		KeyPath:  *flagKeyPath,
		HTTPLog:  *flagHTTPLog,
		TLSLog:   *flagTLSLog,
		Verbose:  *flagVerbose,
	}

	// The workflow is to try to load the certificate stored at config.CaPath and the key at config.KeyPath.
	// This certicate must be trusted by the client system that is making the TLS calls we want to monitor.
	// If a certicate or key doesn't exist at the given paths, we prompt the use of --generate-ca flag.
	//
	// To trust a certificate on Debian/Ubuntu for example. We need to copy the certificate to /usr/local/share/ca-certificates
	// And then run update-ca-certificates.

	if *flagInstall {
		err := certificates.InstallCA(config.CaPath)
		if err != nil {
			fmt.Printf("Unable to install certificate at path %s with error: %v\n\n", config.CaPath, err)
			fmt.Printf("New cert generated and saved to (%s). Add it to the trusted certs on your system\n", config.CaPath)
		}

		return
	}

	ca := certificates.LoadCA(config.CaPath, config.KeyPath)

	if *flagGenerate {
		fmt.Printf("Generating a new TLS certificate at %s\n", config.CaPath)

		ca = certificates.GenerateCA()
		if ca == nil {
			return
		}

		certificates.PersistCA(ca, config.CaPath, config.KeyPath)
		fmt.Println("Use --install-ca to install cert locally.")
		return
	} else if ca == nil {
		fmt.Println("No existing certificate. Use --generate-ca to generate and save a certificate.")
		return
	} else {
		log.Printf("Loaded certificate at %s\n", config.CaPath)
	}

	ConfigureCert(ca)

	// Start a HTTP and TLS server to monitor these calls.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	go ServeTLS()
	go ServeHTTP()

	<-ctx.Done()

	stop()

	log.Println("Shutting down proxy servers.")

	TLSListener.Close()
	HTTPListener.Close()
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

func ServeTLS() {
	logCat := log.New(os.Stdout, "[TLS] ", log.LstdFlags|log.Lmsgprefix)
	proxyServer := goproxy.NewProxyHttpServer()
	proxyServer.Verbose = config.Verbose

	// Tag requests before sending it to the server so that we can use it to store custom metrics. (Start time in
	// this case).
	proxyServer.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		logCat.Printf("Request: %s %s\n", req.Method, req.URL)

		id := uuid.NewString()
		req.Header.Set(proxyIDHeader, id)
		startTimes.Store(id, time.Now().UTC())

		return req, nil
	})

	proxyServer.OnResponse().DoFunc(func(res *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
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

		// Retrieve and store network records to disk at config.TLSLog
		clientAddr := ""
		if ctx != nil && ctx.Req != nil {
			clientAddr = ctx.Req.RemoteAddr
		} else {
			clientAddr = res.Request.RemoteAddr
		}

		rec, err := networklog.BuildNetworkRecord(res.Request, res, start, time.Now(), clientAddr, "")

		if err != nil {
			logCat.Println("Build record failed")
			return res
		}

		err = networklog.AppendRecord(config.TLSLog, rec)
		if err != nil {
			logCat.Println("Append record failed")
			return res
		}

		return res
	})

	// Use goproxy's MITM config for all TLS requests.
	proxyServer.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile("^.*:443$"))).
		HandleConnect(goproxy.AlwaysMitm)

	// Run TLS Server
	var err error
	TLSListener, err = net.Listen("tcp", fmt.Sprintf("localhost:%d", config.TLSPort))
	if err != nil {
		log.Fatalf("Error listening on %d", config.TLSPort)
	}

	logCat.Printf("TLS Server listening on port: %d", config.TLSPort)

	var inflight sync.WaitGroup

	for {
		logCat.Println("Waiting for connections")
		conn, err := TLSListener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			logCat.Printf("Error accepting connection: %v\n", err)
			continue
		}

		inflight.Add(1)

		defer inflight.Done()

		go func(c net.Conn) {
			logCat.Println("Connection from: ", c.RemoteAddr())

			// We read the TLS Hello message sent by the client to get information about
			// the original intended target. Unlike HTTP this is not transparently available
			// and needs some parsing on our end.
			conn, hello, err := tlsutils.PeekClientHello(c)
			if err != nil {
				logCat.Printf("Error peaking tls - %v\n", err)
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
					Host: net.JoinHostPort(host, "443"),
				},
				Host:       net.JoinHostPort(host, "443"),
				Header:     make(http.Header),
				RemoteAddr: c.RemoteAddr().String(),
			}

			// This custom writer makes sure that we don't send a duplicate CONNECT response back to the client.
			// It "eats" the CONNECT response.
			ecrw := tlsutils.EatConnectResponseWriter{conn}
			proxyServer.ServeHTTP(ecrw, connectReq)
		}(conn)
	}
}

// Logging HTTP data is more straightforward, this function essentially acts as a middleware that reads Req and Res
// and logs them.
func ServeHTTP() {
	logCat := log.New(os.Stdout, "[HTTP] ", log.Lmsgprefix|log.LstdFlags)

	var err error
	HTTPListener, err = net.Listen("tcp", fmt.Sprintf("localhost:%d", config.HTTPPort))
	if err != nil {
		log.Fatalf("Error listening on %d - %v\n", config.HTTPPort, err)
	}

	logCat.Printf("HTTP Server listening on %d\n", config.HTTPPort)

	for {
		logCat.Println("Waiting for HTTP Connections")
		conn, err := HTTPListener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}

			logCat.Printf("Error accepting HTTP connection: %v\n", err)
			continue
		}

		go func(conn net.Conn) {
			defer conn.Close()

			logCat.Printf("Connection from: %v\n", conn.RemoteAddr())

			start := time.Now()

			// Read the request sent by the client.
			bufreader := bufio.NewReader(conn)
			req, err := http.ReadRequest(bufreader)
			if err != nil {
				logCat.Printf("bad http req: %v\n", err)
				return
			}

			logCat.Printf("Request: %s %s%s", req.Method, req.Host, req.URL)

			// Connect to the originally intended target.
			destAddr := fmt.Sprintf("%s:%d", req.Host, 80)
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
			rec, err := networklog.BuildNetworkRecord(req, resp, start, time.Now(), conn.RemoteAddr().String(), fullyQualName)

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

			// Save log to a log file.
			err = networklog.AppendRecord(config.HTTPLog, rec)
			if err != nil {
				logCat.Println("Append record failed")
				return
			}
		}(conn)
	}
}
