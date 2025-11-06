package udp

import (
	"encoding/binary"
	"net"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/stupendoussuperpowers/witprox/pkg/app"
	"github.com/stupendoussuperpowers/witprox/pkg/networklog"
)

var log = app.GetLogger("UDP")

func getOriginalDstUDP(oob []byte) (*net.UDPAddr, error) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, err
	}

	for _, msg := range msgs {
		if msg.Header.Level == unix.SOL_IP && msg.Header.Type == unix.IP_ORIGDSTADDR {
			if len(msg.Data) < unix.SizeofSockaddrInet4 {
				return nil, log.Errorf("short sockaddr_in")
			}

			sa := *(*unix.RawSockaddrInet4)(unsafe.Pointer(&msg.Data[0]))
			ip := net.IP(sa.Addr[:])
			port := int(binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&sa.Port))[:]))

			return &net.UDPAddr{IP: ip, Port: port}, nil
		}
	}

	return nil, log.Errorf("no original destination found")
}

func ServeUDP() {
	port := app.Config.UDPPort
	addr := &net.UDPAddr{IP: net.IPv4zero, Port: port}

	// Create raw socket for TPROXY
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err != nil {
		log.Infof("Failed to create socket: %v", err)
		return
	}
	defer unix.Close(fd)

	// Enable transparent proxying for TPROXY
	if err := unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
		log.Infof("Failed to set IP_TRANSPARENT: %v", err)
		return
	}

	// Enable receiving original destination address (works with TPROXY)
	if err := unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1); err != nil {
		log.Infof("Failed to set IP_RECVORIGDSTADDR: %v", err)
		return
	}

	// Bind to any address for TPROXY
	sa := &unix.SockaddrInet4{Port: addr.Port}
	copy(sa.Addr[:], net.IPv4zero.To4())

	if err := unix.Bind(fd, sa); err != nil {
		log.Infof("Failed to bind: %v", err)
		return
	}

	// Convert to net.UDPConn for easier handling
	file := os.NewFile(uintptr(fd), "tproxy-udp")
	connPC, err := net.FilePacketConn(file)
	if err != nil {
		log.Infof("Failed to create packet conn: %v", err)
		return
	}
	conn := connPC.(*net.UDPConn)
	defer conn.Close()

	log.Infof("UDP TPROXY listening on port %d", port)

	buf := make([]byte, 4096)
	oob := make([]byte, 4096)

	for {
		n, oobn, _, clientAddr, err := conn.ReadMsgUDP(buf, oob)
		if err != nil {
			log.Infof("Read error: %v", err)
			continue
		}

		// Extract original destination from TPROXY
		origDst, err := getOriginalDstUDP(oob[:oobn])
		if err != nil {
			log.Infof("Failed to get original destination: %v", err)
			continue
		}

		// Copy the payload
		data := make([]byte, n)
		copy(data, buf[:n])

		log.Infof("Received %d bytes from %s for %s", n, clientAddr.String(), origDst.String())

		// Log received data from client

		proto := detectProtocol(data)

		go handleUDPPacket(conn, clientAddr, origDst, data, proto)
	}
}

func detectProtocol(payload []byte) string {
	if len(payload) < 4 {
		return "unknown"
	}

	if len(payload) >= 12 {
		qdCount := int(payload[4])<<8 | int(payload[5])
		if qdCount > 0 {
			return "dns"
		}
	}

	return "unknown"
}

func handleUDPPacket(proxyConn *net.UDPConn, clientAddr *net.UDPAddr, origDst *net.UDPAddr, data []byte, proto string) {
	clientUDPMessage := networklog.BuildUDPRecord(data, clientAddr.String(), origDst.String(), proto)

	networklog.AppendRecord(app.Config.Log, *clientUDPMessage)

	// For UDP, handle each packet individually (stateless)
	// Create a temporary connection to the server
	log.Infof("Dialing server %v", origDst)
	serverConn, err := net.DialUDP("udp", nil, origDst)
	if err != nil {
		log.Infof("Failed to dial server %v: %v", origDst, err)
		return
	}
	defer serverConn.Close()

	// Send data to server
	_, err = serverConn.Write(data)
	if err != nil {
		log.Infof("Failed to write to server: %v", err)
		return
	}

	// Read response from server with timeout
	serverConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	responseLen, err := serverConn.Read(buf)
	if err != nil {
		log.Infof("Failed to read from server: %v", err)
		return
	}

	// Log received data from server

	dstRawUDP := networklog.BuildUDPRecord(buf[:responseLen], origDst.String(), clientAddr.String(), proto)

	networklog.AppendRecord(app.Config.Log, *dstRawUDP)

	err = sendUDPResponse(buf[:responseLen], origDst, clientAddr)

	if err != nil {
		log.Infof("Failed to send response to client: %v", err)
		return
	}
}

// sendUDPResponse sends a UDP datagram with the given payload
// as if it were coming from origSrc -> clientDst.
func sendUDPResponse(payload []byte, origSrc, clientDst *net.UDPAddr) error {
	// Create raw UDP socket
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	// Mark socket as transparent so we can spoof the source
	if err := unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
		return err
	}

	// Bind to the *original source* (the DNS server like 8.8.8.8:53)
	saSrc := &unix.SockaddrInet4{Port: origSrc.Port}
	copy(saSrc.Addr[:], origSrc.IP.To4())
	if err := unix.Bind(fd, saSrc); err != nil {
		return err
	}

	// Destination is the client
	saDst := &unix.SockaddrInet4{Port: clientDst.Port}
	copy(saDst.Addr[:], clientDst.IP.To4())

	// Send packet
	if err := unix.Sendto(fd, payload, 0, saDst); err != nil {
		return err
	}

	log.Infof("Sent %d bytes forged from %v to %v", len(payload), origSrc, clientDst)
	return nil
}
