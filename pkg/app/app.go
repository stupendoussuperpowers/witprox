package app

import (
	"fmt"
	"github.com/elazarl/goproxy"
	"github.com/stupendoussuperpowers/witprox/pkg/networklog"
	"log"
	"net"
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
		"--key-path", wc.KeyPath,
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
	NetworkStore map[int][]networklog.Packet
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

func StoreLog(pid int, pkt networklog.Packet) {
	NetworkStore[pid] = append(NetworkStore[pid], pkt)
	printNetworkStoreState(fmt.Sprintf("store %d", pid))
}

func FetchLogs(pid int) ([]networklog.Packet, bool) {
	entries, ok := NetworkStore[pid]
	printNetworkStoreState(fmt.Sprintf("fetch %d", pid))

	delete(NetworkStore, pid)
	return entries, ok
}

type Logger struct {
	Context string
}

func (l Logger) Infof(format string, args ...any) {
	pre := fmt.Sprintf("[INFO] %s\t", l.Context)
	fmt.Printf(pre+format, args...)
}

func (l Logger) Info(format string, args ...any) {
	pre := fmt.Sprintf("[INFO] %s\t", l.Context)
	fmt.Println(append([]any{pre}, args...)...)
}

func (l Logger) Errorf(format string, args ...any) {
	pre := fmt.Sprintf("[ERROR] %s\t", l.Context)
	fmt.Printf(pre+format, args...)
}

func (l Logger) Error(format string, args ...any) {
	pre := fmt.Sprintf("[Error] %s\t", l.Context)
	fmt.Println(append([]any{pre}, args...)...)
}

func (l Logger) Fatal(args ...any) {
	pre := fmt.Sprintf("[FATAL] %s\t", l.Context)
	log.Fatal(append([]any{pre}, args...)...)
}

func (l Logger) Fatalf(format string, v ...any) {
	pre := fmt.Sprintf("[FATAL] %s\t", l.Context)
	log.Fatalf(pre+format, v...)
}

func GetLogger(context string) *Logger {
	return &Logger{Context: context}
}
