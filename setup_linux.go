//go:build linux

package main

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/stupendoussuperpowers/witprox/pkg/app"
)

// The eBPF binaries are embedded below. Use make all to ensure these .o files
// are present in the correct location.

//go:embed internal/bpf/witprox.o
var witproxObj []byte

//go:embed internal/bpf/redirect.o
var redirectObj []byte

var CGROUP_REDIRECT = "/sys/fs/cgroup/redirect"
var CGROUP_WITPROX = "/sys/fs/cgroup/witprox"

var activeLinks []link.Link

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

func (s *UnixServer) Close() {
	s.listener.Close()
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

func createComm() CommServer {
	log.Infof("Starting communication socket")
	return &UnixServer{
		socketPath: SOCKET_PATH,
	}
}

// Setup eBPF directories, pins, maps, and programs that are required for linux tracing.
func setupTracing() {
	// Load redirect object, and pin all the maps.
	log.Infof("Setting up eBFP...")
	redirectColl, err := pinMaps(redirectObj, "/sys/fs/bpf/")
	if err != nil {
		log.Fatal(err)
	}

	defer redirectColl.Close()

	witproxSpec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(witproxObj))
	if err != nil {
		log.Fatal(err)
	}

	// PinByName ensures that the maps are shared between the two programs.
	for name, m := range witproxSpec.Maps {
		switch name {
		case "client_map":
			m.Pinning = ebpf.PinByName
		case "t_2_c":
			m.Pinning = ebpf.PinByName
		case "server_map":
			m.Pinning = ebpf.PinByName
		}
	}

	witproxColl, err := ebpf.NewCollectionWithOptions(witproxSpec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf",
		}})

	if err != nil {
		log.Fatal(err)
	}

	defer witproxColl.Close()

	createCgroup(CGROUP_REDIRECT)
	createCgroup(CGROUP_WITPROX)

	// Pin both programs so that they can be attached later.
	os.MkdirAll("/sys/fs/bpf/redirect", 0755)
	os.MkdirAll("/sys/fs/bpf/witprox", 0755)
	for name, m := range redirectColl.Programs {
		pp := filepath.Join("/sys/fs/bpf/redirect", name)
		if err := m.Pin(pp); err != nil {
			log.Fatalf("pin prog %s: %v", name, err)
		}
		log.Infof("pinned prog %s to %s", name, pp)
	}

	for name, m := range witproxColl.Programs {
		pp := filepath.Join("/sys/fs/bpf/witprox", name)
		if err := m.Pin(pp); err != nil {
			log.Fatalf("pin prog %s: %v", name, err)
		}
		log.Infof("pinned prog %s to %s", name, pp)
	}

	programLinks := make([]link.Link, 0)

	programLinks = append(programLinks, attachProgram("redirect", "track_conn", ebpf.AttachCGroupSockOps))
	programLinks = append(programLinks, attachProgram("redirect", "redirect_connect4", ebpf.AttachCGroupInet4Connect))

	programLinks = append(programLinks, attachProgram("witprox", "track_conn", ebpf.AttachCGroupSockOps))

	// The attachments are only valid so long as their links are still in memory.
	// To ensure that the GC doesn't eat them up, we return it and store it in a global variable.
	// 	return programLinks
	activeLinks = programLinks
}

func cleanUpTracing() {
	// Remove the attached programs.
	log.Infof("Tearing down eBPF setups")
	if activeLinks != nil {
		for _, l := range activeLinks {
			if err := l.Close(); err != nil {
				log.Infof("error closing link: %v", err)
			}
		}
		activeLinks = nil
	}

	// Delete all pins.
	pinnedObjects := []string{
		"/sys/fs/bpf/client_map",
		"/sys/fs/bpf/t_2_c",
		"/sys/fs/bpf/server_map",
		"/sys/fs/bpf/redirect/track_conn",
		"/sys/fs/bpf/redirect/redirect_connect4",
		"/sys/fs/bpf/witprox/track_conn",
		"/sys/fs/bpf/witprox/",
		"/sys/fs/bpf/redirect/",
	}

	for _, path := range pinnedObjects {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			log.Infof("failed to remove pinned map: %s: %v", path, err)
		}
	}

	// Delete cgroups.
	for _, cg := range []string{CGROUP_REDIRECT, CGROUP_WITPROX} {
		if err := os.Remove(cg); err != nil && !os.IsNotExist(err) {
			log.Infof("failed to remove cgroup %s: %v", cg, err)
		}
	}

	log.Info("eBPF cleanup complete.")
}

func runServers() {
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

func pinMaps(bpfBytes []byte, pinPath string) (*ebpf.Collection, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfBytes))
	if err != nil {
		return nil, log.Errorf("load collection spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, log.Errorf("create collection: %v", err)
	}

	if err := os.MkdirAll(pinPath, 0755); err != nil {
		return nil, log.Errorf("mkdir pin path: %v", err)
	}

	for name, m := range coll.Maps {
		if m == nil || strings.Contains(name, "rodata") {
			continue
		}
		p := filepath.Join(pinPath, name)
		if err := m.Pin(p); err != nil {
			return nil, log.Errorf("pin map %s: %v", name, err)
		}
	}

	return coll, nil
}

func createCgroup(path string) error {
	if err := os.MkdirAll(path, 0755); err != nil && !os.IsExist(err) {
		return log.Errorf("mkdir cgroup: %v", err)
	}

	return nil
}

func attachProgram(cgroup string, path string, attachType ebpf.AttachType) link.Link {
	pinnedProg, _ := ebpf.LoadPinnedProgram(fmt.Sprintf("/sys/fs/bpf/%s/%s", cgroup, path), nil)
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup/" + cgroup,
		Attach:  attachType,
		Program: pinnedProg,
	})

	if err != nil {
		log.Fatalf("attach cgroup: witness track_conn")
	}

	return l
}
