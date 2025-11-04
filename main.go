package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/stupendoussuperpowers/witprox/pkg/app"
	"github.com/stupendoussuperpowers/witprox/pkg/certificates"
	"github.com/stupendoussuperpowers/witprox/pkg/networklog"
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

		userver := &UnixServer{
			socketPath: SOCKET_PATH,
		}
		app.NetworkStore = make(map[int][]networklog.Packet)

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		go tcp.ServeTCP()
		go udp.ServeUDP()
		go userver.Start()
		<-ctx.Done()

		stop()
		log.Info("Shutting down proxy server")
		app.TCPListener.Close()
		userver.listener.Close()
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

const SOCKET_PATH = "/var/witnessd.sock"

type UnixServer struct {
	socketPath string
	listener   net.Listener
}

func (s *UnixServer) Start() error {
	os.Remove(SOCKET_PATH)

	listener, err := net.Listen("unix", SOCKET_PATH)
	if err != nil {
		return fmt.Errorf("failed to create socket: %w", err)
	}

	s.listener = listener

	if err := os.Chmod(SOCKET_PATH, 0600); err != nil {
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	log.Info("Daemon socket listening")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Infof("Accept error: %v\n", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

func (s *UnixServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	_, ok := conn.(*net.UnixConn)
	if !ok {
		log.Infof("Not a unix connection")
		return
	}

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 2 {
			conn.Write([]byte("ERROR invalid command\n"))
			continue
		}

		cmd := parts[0]
		switch cmd {
		case "GET":
			var pid int
			fmt.Sscanf(parts[1], "%d", &pid)

			logs, _ := app.FetchLogs(pid)

			for _, log := range logs {
				data, _ := json.Marshal(log)
				conn.Write(append(data, '\n'))
			}
			conn.Write([]byte("END\n"))
		}
	}
}
