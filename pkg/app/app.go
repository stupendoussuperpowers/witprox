package app

import (
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/stupendoussuperpowers/witprox/pkg/networklog"
)

type WitproxConfig struct {
	TCPPort     int
	UDPPort     int
	CaPath      string
	KeyPath     string
	Log         string
	Verbose     bool
	ProxyServer *goproxy.ProxyHttpServer
}

func (wc *WitproxConfig) Cli() []string {
	cliArgs := []string{
		"--cert-path", wc.CaPath,
		"--cert-key", wc.KeyPath,
		"--log", wc.Log,
	}
	if wc.Verbose {
		cliArgs = append(cliArgs, "--verbose")
	}

	return cliArgs
}

var (
	TCPListener  net.Listener
	UDPListener  *net.UDPConn
	Config       WitproxConfig
	NetworkStore map[uint32][]networklog.Packet
)

// helper to print a full dump of NetworkStore
func printNetworkStoreState(prefix string) {
	fmt.Printf("\n[%s] === NetworkStore dump ===\n", prefix)
	if len(NetworkStore) == 0 {
		fmt.Println("  (empty)")
		return
	}

	for pid, packets := range NetworkStore {
		fmt.Printf("  PID %d:\n", pid)
		for i, pkt := range packets {
			fmt.Printf("    [%d] %+v\n", i, pkt)
		}
	}
	fmt.Println("==============================")
}

func StoreLog(pid uint32, pkt networklog.Packet) {
	NetworkStore[pid] = append(NetworkStore[pid], pkt)
	if Config.Verbose {
		printNetworkStoreState(fmt.Sprintf("store %d", pid))
	}
}

func FetchLogs(pid uint32) ([]networklog.Packet, bool) {
	entries, ok := NetworkStore[pid]
	if Config.Verbose {
		printNetworkStoreState(fmt.Sprintf("fetch %d", pid))
	}
	delete(NetworkStore, pid)
	return entries, ok
}

var logMu sync.Mutex

type Logger struct {
	Context string
	PID     int
}

func timestamp() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05Z")
}

func (l Logger) log(level, format string, args ...any) {
	logMu.Lock()
	defer logMu.Unlock()
	formatStr := "%s [PID: %d] %-5s %-5s %s \n"
	msg := fmt.Sprintf(formatStr, timestamp(), l.PID, level, l.Context, fmt.Sprintf(format, args...))
	os.Stdout.Write([]byte(msg))
}

func (l Logger) Infof(format string, args ...any) {
	l.log("INFO", format, args...)
}

func (l Logger) Fatalf(format string, args ...any) {
	l.log("FATAL", format, args...)
	log.Fatal("")
}

func (l Logger) Errorf(format string, args ...any) error {
	l.log("ERROR", format, args...)
	return fmt.Errorf(format, args...)
}

func (l Logger) Info(args ...any) {
	l.Infof("%s", fmt.Sprintln(args...))
}

func (l Logger) Error(args ...any) error {
	return l.Errorf("%s", fmt.Sprintln(args...))
}

func (l Logger) Fatal(args ...any) {
	l.Fatalf("%s", fmt.Sprintln(args...))
}

func GetLogger(context string) *Logger {
	return &Logger{Context: context, PID: os.Getpid()}
}
