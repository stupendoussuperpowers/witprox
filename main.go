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
	//	"github.com/stupendoussuperpowers/witprox/pkg/networklog"
	"github.com/stupendoussuperpowers/witprox/pkg/tcp"
	"github.com/stupendoussuperpowers/witprox/pkg/udp"
)

var activeLinks []link.Link

const PIDFILE = "/var/witnessd.pid"
const SOCKET_PATH = "/var/witnessd.sock"

var log = app.GetLogger("INIT")

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

		userver := &UnixServer{
			socketPath: SOCKET_PATH,
		}

		app.InitNetworkStore()

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		go tcp.ServeTCP()
		go udp.ServeUDP()
		go userver.Start()
		<-ctx.Done()

		stop()
		log.Info("Shutting down proxy servers")
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

		// Launch the servers inside the cgroup WITPROX.
		args := append([]string{"--servers"}, app.Config.Cli()...)
		cmd := exec.Command(os.Args[0], args...)

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

		// Copy over logs from --servers process to the main Stdout/Stderr log
		go func(r io.Reader, w io.Writer) {
			scanner := bufio.NewScanner(r)
			for scanner.Scan() {
				fmt.Fprintf(w, "%s\n", scanner.Text())
			}
		}(stdoutPipe, os.Stdout)

		go func(r io.Reader, w io.Writer) {
			scanner := bufio.NewScanner(r)
			for scanner.Scan() {
				fmt.Fprintf(w, "%s\n", scanner.Text())
			}
		}(stderrPipe, os.Stderr)

		pidServers := cmd.Process.Pid

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

		go func() {
			sig := <-sigChan
			log.Infof("Received SIG %s, forwarding to child", sig)
			_ = cmd.Process.Signal(sig)
		}()

		var wstatus syscall.WaitStatus
		var rusage syscall.Rusage

		_, err = syscall.Wait4(pidServers, &wstatus, 0, &rusage)
		if err != nil {
			log.Fatalf("wait4: %v", err)
		}
	}
}

// For witnessd communication, witness sends a message through this UNIX socket
// with PID, witnessd responds with list of network calls.
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
			log.Infof("Accept error: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

func (s *UnixServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Check if connection is a Unix Connection.
	_, ok := conn.(*net.UnixConn)
	if !ok {
		return
	}

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 2 {
			conn.Write([]byte("ERROR invalid command"))
			continue
		}

		cmd := parts[0]
		switch cmd {
		case "GET":
			var pid uint32
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
