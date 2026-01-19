package mysingboxlib

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	_ "golang.org/x/mobile/bind"
)

// --- PHẦN 1: Android TUN ---
type TunnelHandle struct {
	device *device.Device
	tun    tun.Device
}
type AndroidTUN struct {
	file   *os.File
	events chan tun.Event
}
func CreateAndroidTUN(fd int) (tun.Device, error) {
	file := os.NewFile(uintptr(fd), "tun")
	return &AndroidTUN{file: file, events: make(chan tun.Event, 10)}, nil
}
func (t *AndroidTUN) File() *os.File { return t.file }
func (t *AndroidTUN) Read(buffs [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.file.Read(buffs[0][offset:])
	if err != nil { return 0, err }
	sizes[0] = n; return 1, nil
}
func (t *AndroidTUN) Write(buffs [][]byte, offset int) (int, error) {
	if len(buffs) == 0 { return 0, nil }
	_, err := t.file.Write(buffs[0][offset:])
	if err != nil { return 0, err }
	return 1, nil
}
func (t *AndroidTUN) MTU() (int, error) { return 1500, nil }
func (t *AndroidTUN) BatchSize() int { return 1 }
func (t *AndroidTUN) Close() error   { return t.file.Close() }
func (t *AndroidTUN) Name() (string, error) { return "tun", nil }
func (t *AndroidTUN) Events() <-chan tun.Event { return t.events }

// --- PHẦN 2: SOCKS5 BIND ---

type Socks5Bind struct {
	proxyAddr string
	username  string
	password  string
	udpConn   *net.UDPConn
	target    *net.UDPAddr
	tcpConn   net.Conn
	logger    *device.Logger
}

func NewSocks5Bind(proxy, user, pass string, logger *device.Logger) *Socks5Bind {
	return &Socks5Bind{
		proxyAddr: proxy,
		username:  user,
		password:  pass,
		logger:    logger,
	}
}

func (s *Socks5Bind) handShake() error {
	s.logger.Verbosef("SOCKS5: Connecting to %s...", s.proxyAddr)

	conn, err := net.DialTimeout("tcp", s.proxyAddr, 5*time.Second)
	if err != nil {
		s.logger.Errorf("SOCKS5: Dial failed: %v", err)
		return err
	}
	s.tcpConn = conn

	// 1. Method Selection
	if s.username != "" {
		conn.Write([]byte{0x05, 0x02, 0x00, 0x02})
	} else {
		conn.Write([]byte{0x05, 0x01, 0x00})
	}

	buf := make([]byte, 2)
	if _, err := conn.Read(buf); err != nil { return err }

	s.logger.Verbosef("SOCKS5: Server Selected Method: 0x%02x", buf[1])

	// 2. Auth
	if buf[1] == 0x02 {
		authPayload := []byte{0x01}
		authPayload = append(authPayload, byte(len(s.username)))
		authPayload = append(authPayload, []byte(s.username)...)
		authPayload = append(authPayload, byte(len(s.password)))
		authPayload = append(authPayload, []byte(s.password)...)

		conn.Write(authPayload)

		authResp := make([]byte, 2)
		if _, err := conn.Read(authResp); err != nil { return err }

		if authResp[1] != 0x00 {
			return fmt.Errorf("SOCKS5 Authentication Failed")
		}
		s.logger.Verbosef("SOCKS5: Auth Success!")
	} else if buf[1] != 0x00 {
		return fmt.Errorf("SOCKS5 unsupported method: 0x%02x", buf[1])
	}

	// 3. UDP Associate
	s.logger.Verbosef("SOCKS5: Requesting UDP Associate...")
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	conn.Write(req)

	resp := make([]byte, 10+256)
	n, err := conn.Read(resp)
	if err != nil { return err }

	if n < 10 || resp[1] != 0x00 {
		return fmt.Errorf("SOCKS5 UDP Associate failed (Code: 0x%02x)", resp[1])
	}

	// 4. Parse Relay Address
	var relayIP net.IP
	var relayPort int

	switch resp[3] {
	case 1: // IPv4
		relayIP = net.IP(resp[4:8])
		relayPort = int(binary.BigEndian.Uint16(resp[8:10]))
	default:
		host, _, _ := net.SplitHostPort(s.proxyAddr)
		relayIP = net.ParseIP(host)
		relayPort = int(binary.BigEndian.Uint16(resp[len(resp)-2:]))
	}

	s.logger.Verbosef("SOCKS5: UDP Relay at %s:%d", relayIP.String(), relayPort)

	laddr, _ := net.ResolveUDPAddr("udp", ":0")
	s.udpConn, err = net.ListenUDP("udp", laddr)
	if err != nil { return err }

	s.target = &net.UDPAddr{IP: relayIP, Port: relayPort}
	return nil
}

// --- Implement conn.Bind ---

func (s *Socks5Bind) BatchSize() int { return 1 }

func (s *Socks5Bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	if err := s.handShake(); err != nil {
		s.logger.Errorf("SOCKS5 Handshake Error: %v", err)
		return nil, 0, err
	}
	return []conn.ReceiveFunc{s.Receive}, 0, nil
}

func (s *Socks5Bind) Close() error {
	if s.udpConn != nil { s.udpConn.Close() }
	if s.tcpConn != nil { s.tcpConn.Close() }
	return nil
}

func (s *Socks5Bind) SetMark(mark uint32) error { return nil }

func (s *Socks5Bind) Send(buffs [][]byte, endpoint conn.Endpoint) error {
	if s.udpConn == nil { return fmt.Errorf("closed") }

	header := make([]byte, 10)
	header[0], header[1], header[2] = 0, 0, 0
	header[3] = 1 // IPv4

	epStr := endpoint.DstToString()
	dstAddr, _ := net.ResolveUDPAddr("udp", epStr)
	if dstAddr != nil && dstAddr.IP.To4() != nil {
		copy(header[4:8], dstAddr.IP.To4())
		binary.BigEndian.PutUint16(header[8:10], uint16(dstAddr.Port))
	}

	packet := append(header, buffs[0]...)
	_, err := s.udpConn.WriteToUDP(packet, s.target)
	return err
}

func (s *Socks5Bind) Receive(buffs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	if s.udpConn == nil { return 0, fmt.Errorf("closed") }

	buf := make([]byte, 2048)
	n, _, err := s.udpConn.ReadFromUDP(buf)
	if err != nil { return 0, err }

	if n < 10 { return 0, nil }

	// --- FIX LỖI CÚ PHÁP Ở ĐÂY ---
	headerLen := 10
	if buf[3] == 3 {
		headerLen = 7 + int(buf[4])
	} else if buf[3] == 4 { // Đã sửa: } else if {
		headerLen = 22
	}

	if n <= headerLen { return 0, nil }

	copy(buffs[0], buf[headerLen:n])
	sizes[0] = n - headerLen
	eps[0] = s.CreateEndpoint()
	return 1, nil
}

func (s *Socks5Bind) ParseEndpoint(sStr string) (conn.Endpoint, error) {
	return conn.NewDefaultBind().ParseEndpoint(sStr)
}
func (s *Socks5Bind) CreateEndpoint() conn.Endpoint {
	ep, _ := conn.NewDefaultBind().ParseEndpoint("0.0.0.0:0")
	return ep
}

// --- StartVPN ---
func StartVPN(fd int, settings string, proxyAddr, socksUser, socksPass string, logLevel int) (*TunnelHandle, error) {
	tunDevice, err := CreateAndroidTUN(fd)
	if err != nil { return nil, fmt.Errorf("tun error: %v", err) }

	logger := device.NewLogger(logLevel, "(AndroidSocks) ")

	var bind conn.Bind
	if proxyAddr != "" {
		bind = NewSocks5Bind(proxyAddr, socksUser, socksPass, logger)
		logger.Verbosef("SOCKS5 Configured: %s", proxyAddr)
	} else {
		bind = conn.NewDefaultBind()
	}

	dev := device.NewDevice(tunDevice, bind, logger)
	dev.Up()

	if err := dev.IpcSet(settings); err != nil {
		dev.Close()
		return nil, err
	}
	return &TunnelHandle{device: dev, tun: tunDevice}, nil
}

func (t *TunnelHandle) Stop() {
	if t.device != nil { t.device.Close() }
}