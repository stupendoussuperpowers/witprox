package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"

	"github.com/stupendoussuperpowers/witprox/pkg/app"
	"github.com/stupendoussuperpowers/witprox/pkg/certificates"
	"github.com/stupendoussuperpowers/witprox/pkg/tcp"
	"github.com/stupendoussuperpowers/witprox/pkg/udp"
)

var activeLinks []link.Link

func main() {
	// This flag is used if we need to generate a fresh TLS certificate. More details are documented below.
	flagGenerate := flag.Bool("generate-ca", false, "Generate a new TLS certificate")
	flagInstall := flag.Bool("install-ca", false, "Install the certificate at cert-path. Only supported on Debian/Ubuntu.")
	flagCaPath := flag.String("cert-path", "/tmp/witproxca.crt", "TLS Certificate Path")
	flagKeyPath := flag.String("key-path", "/tmp/witproxkey.pem", "TLS Certificate Path")
	flagLog := flag.String("log", "/tmp/witprox.log", "Log file")
	flagVerbose := flag.Bool("verbose", false, "Goproxy verbose logs")
	flagPort := flag.Int("port", 1230, "Start TCP listener on this port")
	flagUDPPort := flag.Int("udp-port", 2230, "Start UDP listener on this port")
	flagSetup := flag.Bool("setup", false, "Setup eBPF")
	flagServers := flag.Bool("servers", false, "Only run the servers, without any eBPF setups.")

	flag.Parse()

	app.Config = app.WitproxConfig{
		TCPPort: *flagPort,
		UDPPort: *flagUDPPort,
		CaPath:  *flagCaPath,
		KeyPath: *flagKeyPath,
		Log:     *flagLog,
		Verbose: *flagVerbose,
	}

	// The workflow is to try to load the certificate stored at config.CaPath and the key at config.KeyPath.
	// This certicate must be trusted by the client system that is making the TLS calls we want to monitor.
	// If a certicate or key doesn't exist at the given paths, we prompt the use of --generate-ca flag.
	//
	// To trust a certificate on Debian/Ubuntu for example. We need to copy the certificate to /usr/local/share/ca-certificates
	// And then run update-ca-certificates.

	if *flagInstall {
		err := certificates.InstallCA(app.Config.CaPath)
		if err != nil {
			fmt.Printf("Unable to install certificate at path %s with error: %v\n\n", app.Config.CaPath, err)
			fmt.Printf("New cert generated and saved to (%s). Add it to the trusted certs on your system\n", app.Config.CaPath)
		}

		return
	}

	ca := certificates.LoadCA(app.Config.CaPath, app.Config.KeyPath)

	if *flagGenerate {
		fmt.Printf("Generating a new TLS certificate at %s\n", app.Config.CaPath)

		ca = certificates.GenerateCA()
		if ca == nil {
			return
		}

		certificates.PersistCA(ca, app.Config.CaPath, app.Config.KeyPath)
		fmt.Println("Use --install-ca to install cert locally.")
		return
	} else if ca == nil {
		fmt.Println("No existing certificate. Use --generate-ca to generate and save a certificate.")
		return
	} else {
		log.Printf("Loaded certificate at %s\n", app.Config.CaPath)
	}

	if *flagSetup {
		activeLinks = SetupEBPF()

		cmd := exec.Command(os.Args[0], "-servers")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		log.Printf("Starting only servers\n")
		if err := cmd.Start(); err != nil {
			log.Fatalf("failed to start servers: %v", err)
		}

		pid := cmd.Process.Pid
		log.Printf("Moving PID to cgroup: %d\n", pid)
		moveToCgroup(pid, "/sys/fs/cgroup/witprox")

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

		go func() {
			sig := <-sigChan
			log.Printf("Received SIG %s, forwarding to child\n", sig)
			_ = cmd.Process.Signal(sig)
		}()

		var wstatus syscall.WaitStatus
		var rusage syscall.Rusage

		wpid, err := syscall.Wait4(pid, &wstatus, 0, &rusage)
		if err != nil {
			log.Fatalf("wait4: %v", err)
		}
		log.Printf("wait4: PID: %d\n", wpid)

		CleanUpEBPF()
	}

	if *flagServers {
		tcp.SetupTLS(ca)

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		go tcp.ServeTCP()
		go udp.ServeUDP()
		<-ctx.Done()

		stop()
		log.Println("Shutting down proxy server")
		app.TCPListener.Close()
	}
}
