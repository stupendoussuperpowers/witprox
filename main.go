package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/stupendoussuperpowers/witprox/pkg/app"
	"github.com/stupendoussuperpowers/witprox/pkg/certificates"
	"github.com/stupendoussuperpowers/witprox/pkg/tcp"
	"github.com/stupendoussuperpowers/witprox/pkg/udp"
)

var activeLinks []link.Link

const PIDFILE = "/var/witnessd.pid"

var log = app.GetLogger("INIT")

func main() {
	// Daemon-handling
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

	ca := certificates.LoadCA(app.Config.CaPath, app.Config.KeyPath)

	if ca == nil {
		fmt.Printf("Generating a new TLS certificate at %s\n", app.Config.CaPath)

		ca = certificates.GenerateCA()
		if ca == nil {
			return
		}

		certificates.PersistCA(ca, app.Config.CaPath, app.Config.KeyPath)

	} else {
		log.Infof("Loaded certificate at %s\n", app.Config.CaPath)
	}

	err := certificates.InstallCA(app.Config.CaPath)
	if err != nil {
		fmt.Printf("Unable to install certificate at path %s with error: %v\n\n", app.Config.CaPath, err)

		fmt.Printf("New cert generated and saved to (%s). Add it to the trusted certs on your system\n", app.Config.CaPath)
	}

	if *flagServers {
		log.Infof("Starting only servers\n")
		tcp.SetupTLS(ca)

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		go tcp.ServeTCP()
		go udp.ServeUDP()
		<-ctx.Done()

		stop()
		log.Info("Shutting down proxy server")
		app.TCPListener.Close()
	} else {
		if _, err := os.Stat(PIDFILE); err == nil {
			log.Fatalf("witnessd already running.")
		}

		pidMain := os.Getpid()
		if err := os.WriteFile(PIDFILE, []byte(fmt.Sprintf("%d", pidMain)), 0644); err != nil {
			log.Fatalf("failed to write pid file: %v", err)
		}
		defer os.Remove(PIDFILE)

		activeLinks = setupEBPF()
		defer cleanUpEBPF()

		cmd := exec.Command(os.Args[0], "--servers")

		cgroupFD, err := unix.Open(CGROUP_WITPROX, unix.O_PATH, 0)
		if err != nil {
			log.Info("Couldn't run network tracing:", err)
			return
		}
		cmd.SysProcAttr = &unix.SysProcAttr{
			CgroupFD:    cgroupFD,
			UseCgroupFD: true,
		}

		stdoutPipe, _ := cmd.StdoutPipe()
		stderrPipe, _ := cmd.StderrPipe()

		if err := cmd.Start(); err != nil {
			log.Fatalf("failed to start servers: %v", err)
		}

		prefix := fmt.Sprintf("[%d]", cmd.Process.Pid)

		go func(r io.Reader, w io.Writer, tag string) {
			scanner := bufio.NewScanner(r)
			for scanner.Scan() {
				fmt.Fprintf(w, "%s %s\n", tag, scanner.Text())
			}
		}(stdoutPipe, os.Stdout, prefix)

		go func(r io.Reader, w io.Writer, tag string) {
			scanner := bufio.NewScanner(r)
			for scanner.Scan() {
				fmt.Fprintf(w, "%s %s\n", tag, scanner.Text())
			}
		}(stderrPipe, os.Stderr, prefix)

		pidServers := cmd.Process.Pid

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

		go func() {
			sig := <-sigChan
			log.Infof("Received SIG %s, forwarding to child\n", sig)
			_ = cmd.Process.Signal(sig)
		}()

		var wstatus syscall.WaitStatus
		var rusage syscall.Rusage

		wpid, err := syscall.Wait4(pidServers, &wstatus, 0, &rusage)
		if err != nil {
			log.Fatalf("wait4: %v", err)
		}
		log.Infof("wait4: PID: %d\n", wpid)
	}
}
