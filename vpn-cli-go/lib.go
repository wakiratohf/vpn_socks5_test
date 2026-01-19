package mysingboxlib

import (
	"fmt"
	"os"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	_ "golang.org/x/mobile/bind"
)

// --- PHẦN 1: Wrapper Handle ---
type TunnelHandle struct {
	device *device.Device
	tun    tun.Device
}

// --- PHẦN 2: Custom TUN Device cho Android ---
type AndroidTUN struct {
	file   *os.File
	events chan tun.Event
}

func CreateAndroidTUN(fd int) (tun.Device, error) {
	file := os.NewFile(uintptr(fd), "tun")
	return &AndroidTUN{
		file:   file,
		events: make(chan tun.Event, 10),
	}, nil
}

func (t *AndroidTUN) File() *os.File {
	return t.file
}

func (t *AndroidTUN) Read(buffs [][]byte, sizes []int, offset int) (int, error) {
	// Đọc packet từ FD
	n, err := t.file.Read(buffs[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil // Trả về 1 packet
}

func (t *AndroidTUN) Write(buffs [][]byte, offset int) (int, error) {
	if len(buffs) == 0 {
		return 0, nil
	}

	// FIX LỖI: Thay 'n' bằng '_' vì ta không cần dùng số byte đã ghi
	_, err := t.file.Write(buffs[0][offset:])
	if err != nil {
		return 0, err
	}
	return 1, nil // Trả về 1 packet
}

// FIX LỖI: Bổ sung hàm MTU() còn thiếu
func (t *AndroidTUN) MTU() (int, error) {
	return 1280, nil // Trả về MTU tiêu chuẩn của WireGuard
}

func (t *AndroidTUN) BatchSize() int {
	return 1 // Chỉ xử lý từng gói một
}

func (t *AndroidTUN) Close() error {
	return t.file.Close()
}

func (t *AndroidTUN) Name() (string, error) {
	return "tun", nil
}

func (t *AndroidTUN) Events() <-chan tun.Event {
	return t.events
}

// --- PHẦN 3: Hàm StartVPN Chính ---
func StartVPN(fd int, settings string, logLevel int) (*TunnelHandle, error) {
	// 1. Dùng Custom TUN
	tunDevice, err := CreateAndroidTUN(fd)
	if err != nil {
		return nil, fmt.Errorf("failed to create AndroidTUN: %v", err)
	}

	// 2. Logger
	logger := device.NewLogger(logLevel, "(AndroidVPN) ")

	// 3. Khởi tạo Device
	dev := device.NewDevice(tunDevice, conn.NewDefaultBind(), logger)

	// 4. Bật device
	dev.Up()

	// 5. Nạp cấu hình
	if err := dev.IpcSet(settings); err != nil {
		dev.Close()
		return nil, fmt.Errorf("failed to config IPC: %v", err)
	}

	return &TunnelHandle{device: dev, tun: tunDevice}, nil
}

func (t *TunnelHandle) Stop() {
	if t.device != nil {
		t.device.Close()
	}
}
