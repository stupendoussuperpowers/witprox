package app

import (
	"fmt"
	"github.com/elazarl/goproxy"
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

var (
	TCPListener net.Listener
	UDPListener *net.UDPConn
	Config      WitproxConfig
)

type Logger struct {
	Context string
}

func (l Logger) Infof(format string, args ...any) {
	pre := fmt.Sprintf("[INFO] %s\t", l.Context)
	fmt.Printf(pre+format, args...)
}

func (l Logger) Info(format string, args ...any) {
	pre := fmt.Sprintf("[INFO] %s\t", l.Context)
	fmt.Println(append([]interface{}{pre}, args...)...)
}

func (l Logger) Errorf(format string, args ...any) {
	pre := fmt.Sprintf("[ERROR] %s\t", l.Context)
	fmt.Printf(pre+format, args...)
}

func (l Logger) Error(format string, args ...any) {
	pre := fmt.Sprintf("[Error] %s\t", l.Context)
	fmt.Println(append([]interface{}{pre}, args...)...)
}

func GetLogger(context string) *Logger {
	return &Logger{Context: context}
}
