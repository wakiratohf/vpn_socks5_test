package mysingboxlib

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
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
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

func (t *AndroidTUN) Write(buffs [][]byte, offset int) (int, error) {
	if len(buffs) == 0 {
		return 0, nil
	}
	_, err := t.file.Write(buffs[0][offset:])
	if err != nil {
		return 0, err
	}
	return 1, nil
}

// --- FIX 1: MTU AN TOÀN ---
// Giảm từ 1500 xuống 1280 để chừa chỗ cho SOCKS5 Header + UDP Header
// Tránh việc gói tin bị phân mảnh hoặc bị drop bởi Router trung gian
func (t *AndroidTUN) MTU() (int, error) { return 1280, nil }

// --- FIX 2: BATCH SIZE CHUẨN ---
// Dùng hằng số chuẩn của WireGuard thay vì hardcode
func (t *AndroidTUN) BatchSize() int { return conn.IdealBatchSize }

func (t *AndroidTUN) Close() error { return t.file.Close() }

func (t *AndroidTUN) Name() (string, error) { return "tun", nil }

func (t *AndroidTUN) Events() <-chan tun.Event { return t.events }

// --- PHẦN 2: SOCKS5 BIND ---

// Pool bộ nhớ để tái sử dụng buffer, giảm Garbage Collection
var udpBufferPool = sync.Pool{
	New: func() interface{} {
		// Buffer 2048 là đủ cho MTU 1280 + Header
		b := make([]byte, 2048)
		return &b
	},
}

type Socks5Bind struct {
	proxyAddr      string
	username       string
	password       string
	udpConn        *net.UDPConn
	target         *net.UDPAddr
	tcpConn        net.Conn
	logger         *device.Logger
	targetEndpoint conn.Endpoint
	// Mutex để đảm bảo an toàn khi đóng kết nối từ nhiều goroutine
	mu sync.Mutex
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

	// Tăng timeout lên 10s để xử lý trường hợp mạng lag
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.Dial("tcp", s.proxyAddr)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}

	// --- FIX 3: TCP KEEPALIVE ---
	// Rất quan trọng: Giữ kết nối TCP luôn sống.
	// Nếu TCP đứt, Server SOCKS5 sẽ đóng cổng UDP ngay lập tức.
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(15 * time.Second)
		tcpConn.SetNoDelay(true)
	}

	s.tcpConn = conn

	// 1. Gửi Method Selection
	if s.username != "" {
		// Hỗ trợ auth username/password (0x02)
		conn.Write([]byte{0x05, 0x02, 0x00, 0x02})
	} else {
		// Không auth (0x00)
		conn.Write([]byte{0x05, 0x01, 0x00})
	}

	buf := make([]byte, 2)
	if _, err := conn.Read(buf); err != nil {
		return fmt.Errorf("read method response failed: %w", err)
	}

	// 2. Xử lý Auth nếu cần
	if buf[1] == 0x02 {
		auth := []byte{0x01, byte(len(s.username))}
		auth = append(auth, []byte(s.username)...)
		auth = append(auth, byte(len(s.password)))
		auth = append(auth, []byte(s.password)...)
		conn.Write(auth)

		authBuf := make([]byte, 2)
		if _, err := conn.Read(authBuf); err != nil {
			return fmt.Errorf("read auth response failed: %w", err)
		}
		if authBuf[1] != 0x00 {
			return fmt.Errorf("SOCKS5 auth failed")
		}
	} else if buf[1] != 0x00 {
		return fmt.Errorf("SOCKS5 unsupported method: 0x%02x", buf[1])
	}

	// 3. Gửi UDP Associate Request
	// IP 0.0.0.0 Port 0 là yêu cầu tiêu chuẩn
req := []byte{
    0x05, 0x03, 0x00, 0x01, // Header
    127, 0, 0, 1,           // IP: 127.0.0.1
    0, 0,                   // Port: 0
}
conn.Write(req)

	// Đọc phản hồi (tối đa ~262 bytes cho domain name dài nhất)
	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil || n < 10 {
		return fmt.Errorf("read udp associate response failed: %w", err)
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("SOCKS5 UDP associate rejected (status: 0x%02x)", resp[1])
	}

	// 4. Parse Relay Address (Địa chỉ mà Server cấp cho mình gửi hàng vào)
	var relayIP net.IP
	var relayPort int

	switch resp[3] {
	case 1: // IPv4
		relayIP = net.IP(resp[4:8])
		relayPort = int(binary.BigEndian.Uint16(resp[8:10]))
	case 3: // Domain
		dLen := int(resp[4])
		if len(resp) < 5+dLen+2 {
			return fmt.Errorf("invalid domain response length")
		}
		domain := string(resp[5 : 5+dLen])
		ips, err := net.LookupIP(domain)
		if err != nil || len(ips) == 0 {
			return fmt.Errorf("failed to resolve relay domain: %s", domain)
		}
		relayIP = ips[0]
		relayPort = int(binary.BigEndian.Uint16(resp[5+dLen : 7+dLen]))
	case 4: // IPv6
		relayIP = net.IP(resp[4:20])
		relayPort = int(binary.BigEndian.Uint16(resp[20:22]))
	default:
		return fmt.Errorf("unsupported address type: %d", resp[3])
	}

	s.target = &net.UDPAddr{IP: relayIP, Port: relayPort}
	s.logger.Verbosef("SOCKS5: UDP Relay established at %s", s.target.String())

	// 5. Mở cổng UDP Local để hứng traffic từ WireGuard
	laddr, _ := net.ResolveUDPAddr("udp", ":0")
	s.udpConn, err = net.ListenUDP("udp", laddr)
	if err != nil {
		return fmt.Errorf("listen udp failed: %w", err)
	}

	// Tạo endpoint giả lập để báo cho WireGuard biết "server" ở đâu
	s.targetEndpoint, _ = s.ParseEndpoint(s.target.String())
	return nil
}

func (s *Socks5Bind) BatchSize() int { return conn.IdealBatchSize }

func (s *Socks5Bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	if err := s.handShake(); err != nil {
		s.Close()
		return nil, 0, err
	}

	// Chạy goroutine giám sát kết nối TCP
	// Nếu TCP đứt -> Đóng luôn UDP để WireGuard biết mà reconnect
	go func() {
		b := make([]byte, 1)
		s.tcpConn.Read(b)
		s.logger.Errorf("SOCKS5 control channel closed/lost")
		s.Close()
	}()

	return []conn.ReceiveFunc{s.Receive}, uint16(s.udpConn.LocalAddr().(*net.UDPAddr).Port), nil
}

func (s *Socks5Bind) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.udpConn != nil {
		s.udpConn.Close()
	}
	if s.tcpConn != nil {
		s.tcpConn.Close()
	}
	return nil
}

func (s *Socks5Bind) SetMark(mark uint32) error { return nil }

func (s *Socks5Bind) Send(buffs [][]byte, endpoint conn.Endpoint) error {
	// Không cần lock ở đây để tối ưu hiệu năng,
	// nhưng cần check nil an toàn nếu có thể.
	// WireGuard logic đảm bảo Send không gọi sau khi Close.
	if s.udpConn == nil {
		return os.ErrClosed
	}

	// Lấy địa chỉ đích thật sự (WireGuard Server Endpoint)
	epStr := endpoint.DstToString()
	dstAddr, err := net.ResolveUDPAddr("udp", epStr)
	if err != nil {
		return err
	}

	// Tạo Header SOCKS5 cho mỗi gói tin
	// Tối ưu: Nếu endpoint không đổi, có thể cache header này (Advanced)
	var header []byte
	if ip4 := dstAddr.IP.To4(); ip4 != nil {
		header = make([]byte, 10)
		header[0], header[1], header[2] = 0, 0, 0 // RSV + FRAG
		header[3] = 1 // IPv4
		copy(header[4:8], ip4)
		binary.BigEndian.PutUint16(header[8:10], uint16(dstAddr.Port))
	} else {
		header = make([]byte, 22)
		header[0], header[1], header[2] = 0, 0, 0
		header[3] = 4 // IPv6
		copy(header[4:20], dstAddr.IP.To16())
		binary.BigEndian.PutUint16(header[20:22], uint16(dstAddr.Port))
	}

	for _, b := range buffs {
		tmpPtr := udpBufferPool.Get().(*[]byte)
		tmp := *tmpPtr

		// Copy Header + Payload vào buffer tạm
		copy(tmp, header)
		copy(tmp[len(header):], b)

		// Gửi đến Relay Server
		_, err := s.udpConn.WriteToUDP(tmp[:len(header)+len(b)], s.target)
		udpBufferPool.Put(tmpPtr)

		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Socks5Bind) Receive(buffs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	if s.udpConn == nil {
		return 0, os.ErrClosed
	}

	count := 0
	for i := 0; i < len(buffs); i++ {
		bufPtr := udpBufferPool.Get().(*[]byte)
		buf := *bufPtr

		// Chỉ set deadline cho các gói tiếp theo trong batch để tránh block lâu
		if i > 0 {
			s.udpConn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		}

		n, _, err := s.udpConn.ReadFromUDP(buf)

		if i > 0 {
			s.udpConn.SetReadDeadline(time.Time{})
		}

		if err != nil {
			udpBufferPool.Put(bufPtr)
			// Nếu lỗi timeout ở gói thứ 2 trở đi -> coi như batch này xong
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				break
			}
			return count, err
		}

		// Parse Header để lấy Payload
		if n < 10 { // Header tối thiểu 10 byte (IPv4)
			udpBufferPool.Put(bufPtr)
			continue
		}

		hLen := 0
		switch buf[3] { // ATYP
		case 1: // IPv4
			hLen = 10
		case 4: // IPv6
			hLen = 22
		case 3: // Domain
			hLen = 7 + int(buf[4])
		default:
			udpBufferPool.Put(bufPtr)
			continue
		}

		if n <= hLen {
			udpBufferPool.Put(bufPtr)
			continue
		}

		// Copy payload vào buffer của WireGuard
		payloadLen := n - hLen
		copy(buffs[count], buf[hLen:n])
		sizes[count] = payloadLen
		eps[count] = s.targetEndpoint // Gán endpoint giả lập
		count++

		udpBufferPool.Put(bufPtr)
	}
	return count, nil
}

func (s *Socks5Bind) ParseEndpoint(sStr string) (conn.Endpoint, error) {
	return conn.NewDefaultBind().ParseEndpoint(sStr)
}

// Hàm khởi tạo VPN (Entry Point)
func StartVPN(fd int, settings string, proxyAddr, socksUser, socksPass string, logLevel int) (*TunnelHandle, error) {
	tunDevice, err := CreateAndroidTUN(fd)
	if err != nil {
		return nil, fmt.Errorf("tun error: %w", err)
	}

	logger := device.NewLogger(logLevel, "(VPN) ")

	// FIX 4: Nếu proxyAddr rỗng thì dùng Direct, ngược lại dùng Socks5Bind
	var bind conn.Bind
	if proxyAddr != "" {
		logger.Verbosef("Using SOCKS5 Proxy: %s", proxyAddr)
		bind = NewSocks5Bind(proxyAddr, socksUser, socksPass, logger)
	} else {
		logger.Verbosef("Using Direct Connection")
		bind = conn.NewDefaultBind()
	}

	dev := device.NewDevice(tunDevice, bind, logger)

	// Up device trước khi set config
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}

	if err := dev.IpcSet(settings); err != nil {
		dev.Close()
		return nil, err
	}

	return &TunnelHandle{device: dev, tun: tunDevice}, nil
}

func (t *TunnelHandle) Stop() {
	if t.device != nil {
		t.device.Close()
	}
}