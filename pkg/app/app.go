package app 

import (
	"net"
	"fmt"
	// "syscall"
	// "log"
	"golang.org/x/sys/unix"
	"github.com/elazarl/goproxy"
)

type WitproxConfig struct {
	TCPPort int
	UDPPort int
	CaPath   string
	KeyPath  string
	Log   string
	Verbose  bool
	ProxyServer *goproxy.ProxyHttpServer
}

const proxyIDHeader = "X-Proxy-Req-Id"

var (
	TCPListener  net.Listener
	UDPListener	*net.UDPConn
	Config       WitproxConfig
)

func GetOriginalDst(conn *net.TCPConn) (int, string, error) {
	file, err := conn.File()
	if err != nil {
		return -1, "", err
	}

	defer file.Close()
	fd := int(file.Fd())

	addr, err := unix.GetsockoptIPv6Mreq(int(fd), unix.SOL_IP, 80)
	if err != nil {
		return -1, "", err
	}

	server := fmt.Sprintf("%d.%d.%d.%d", 
		addr.Multiaddr[4],
		addr.Multiaddr[5],
		addr.Multiaddr[6],
		addr.Multiaddr[7],
	)

	return int(addr.Multiaddr[2]) << 8 | int(addr.Multiaddr[3]), server, nil
}

func GetOriginalDstUDP(conn *net.UDPConn) (int, string, error) {
	file, err := conn.File()
	if err != nil {
		return -1, "", err
	}

	defer file.Close()
	fd := int(file.Fd())

	addr, err := unix.GetsockoptIPv6Mreq(int(fd), unix.SOL_IP, 80)
	if err != nil {
		return -1, "", err
	}

	server := fmt.Sprintf("%d.%d.%d.%d", 
		addr.Multiaddr[4],
		addr.Multiaddr[5],
		addr.Multiaddr[6],
		addr.Multiaddr[7],
	)

	return int(addr.Multiaddr[2]) << 8 | int(addr.Multiaddr[3]), server, nil
}
