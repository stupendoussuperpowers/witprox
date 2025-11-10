package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/stupendoussuperpowers/witprox/pkg/app"
	"github.com/stupendoussuperpowers/witprox/pkg/certificates"
	"github.com/stupendoussuperpowers/witprox/pkg/tcp"
	"github.com/stupendoussuperpowers/witprox/pkg/udp"
)

const PIDFILE = "/var/witnessd.pid"
const SOCKET_PATH = "/var/witnessd.sock"

var commServer CommServer

var log = app.GetLogger("INIT")

type CommServer interface {
	Start() error
	Close()
}

func main() {
	flagCaPath := flag.String("cert-path", "/tmp/witproxca.crt", "TLS Certificate path")
	flagKeyPath := flag.String("cert-key", "/tmp/witproxkey.pem", "TLS Key path")
	flagLog := flag.String("log", "/tmp/", "Log folder")
	flagVerbose := flag.Bool("verbose", false, "verbose logs for proxy")
	flagServers := flag.Bool("servers", false, "Launch transparent proxies")

	flag.Parse()

	app.Config = app.WitproxConfig{
		CaPath:  *flagCaPath,
		KeyPath: *flagKeyPath,
		Log:     *flagLog,
		Verbose: *flagVerbose,
		TCPPort: 1230,
		UDPPort: 2230,
	}

	// Only spawn the Proxy servers. This flow is used by the daemon itself once it's done setting up eBPFs and cgroups.
	if *flagServers {
		ca := certificates.LoadCA(app.Config.CaPath, app.Config.KeyPath)

		if ca == nil {
			log.Infof("Generating a new TLS certificate at %s", app.Config.CaPath)

			ca = certificates.GenerateCA()
			if ca == nil {
				return
			}

			certificates.PersistCA(ca, app.Config.CaPath, app.Config.KeyPath)

		} else {
			log.Infof("Loaded certificate at %s", app.Config.CaPath)
		}

		err := certificates.InstallCA(app.Config.CaPath)
		if err != nil {
			log.Fatalf("Unable to install certificate at path %s with error: %v", app.Config.CaPath, err)
		}

		log.Infof("Starting only servers")
		tcp.SetupTLS(ca)
		app.InitNetworkStore()

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		go tcp.ServeTCP()
		go udp.ServeUDP()

		commServer = createComm()
		go commServer.Start()

		<-ctx.Done()

		stop()
		log.Info("Shutting down proxy servers")
		app.TCPListener.Close()
		commServer.Close()
	} else {
		if _, err := os.Stat(PIDFILE); err == nil {
			log.Fatalf("witnessd already running.")
		}

		pidMain := os.Getpid()
		if err := os.WriteFile(PIDFILE, []byte(fmt.Sprintf("%d", pidMain)), 0644); err != nil {
			log.Fatalf("failed to write pid file: %v", err)
		}
		defer os.Remove(PIDFILE)

		setupTracing()
		defer cleanUpTracing()

		runServers()
	}
}
