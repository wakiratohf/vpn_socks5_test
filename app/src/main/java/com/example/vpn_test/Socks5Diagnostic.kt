package com.example.vpn_test // Nhớ đổi package name cho đúng

import android.util.Log
import java.net.InetSocketAddress
import java.net.Socket

object Socks5Diagnostic {
    private const val TAG = "Socks5Test"

    /**
     * Chạy test SOCKS5 UDP Associate trên luồng riêng
     * @param host: IP của SOCKS5 Proxy (VD: "192.168.1.10")
     * @param port: Port của SOCKS5 Proxy (VD: 1080)
     */
    fun runTest(host: String, port: Int) {
        Thread {
            Log.w(TAG, "=== BẮT ĐẦU TEST SOCKS5 ===")
            Log.d(TAG, "Đang kết nối tới $host:$port...")

            var socket: Socket? = null
            try {
                // 1. Kết nối TCP
                socket = Socket()
                socket.connect(InetSocketAddress(host, port), 5000)
                val input = socket.getInputStream()
                val output = socket.getOutputStream()

                Log.d(TAG, "TCP Connected! Đang gửi Handshake...")

                // 2. Gửi Method Selection (05 01 00 - No Auth)
                // Gửi: VER(5) NMETHODS(1) METHODS(0=NoAuth)
                output.write(byteArrayOf(0x05, 0x01, 0x00))

                val buffer = ByteArray(1024)
                var n = input.read(buffer)

                Log.d(TAG, "<< Server đáp [Handshake]: ${toHex(buffer, n)}")

                if (n < 2 || buffer[0] != 0x05.toByte()) {
                    Log.e(TAG, "LỖI: Server không phải SOCKS5.")
                    return@Thread
                }

                if (buffer[1] == 0xFF.toByte()) {
                    Log.e(TAG, "LỖI: Server yêu cầu Auth nhưng ta không gửi user/pass.")
                    return@Thread
                }

                if (buffer[1] != 0x00.toByte()) {
                    Log.e(TAG, "LỖI: Server chọn method lạ: ${String.format("%02X", buffer[1])}")
                    return@Thread
                }

                // 3. Gửi UDP ASSOCIATE Request (Quan trọng nhất)
                Log.d(TAG, ">> Gửi lệnh: UDP ASSOCIATE...")
                // Gửi: VER(5) CMD(3=UDP) RSV(0) ATYP(1=IPv4) IP(0.0.0.0) PORT(0)
                val udpReq = byteArrayOf(0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0)
                output.write(udpReq)

                n = input.read(buffer)
                Log.d(TAG, "<< Server đáp [UDP Response]: ${toHex(buffer, n)}")

                if (n > 1) {
                    val status = buffer[1]
                    when (status) {
                        0x00.toByte() -> {
                            Log.i(TAG, "✅ THÀNH CÔNG: Server CÓ hỗ trợ UDP!")
                            // In ra IP/Port Relay mà server cấp
                            if (n >= 10) {
                                val ip = "${buffer[4].toUByte()}.${buffer[5].toUByte()}.${buffer[6].toUByte()}.${buffer[7].toUByte()}"
                                val portRelay = ((buffer[8].toInt() and 0xFF) shl 8) or (buffer[9].toInt() and 0xFF)
                                Log.i(TAG, "✅ Server mở cổng Relay tại: $ip:$portRelay")
                            }
                        }

                        0x07.toByte() -> {
                            Log.e(TAG, "❌ THẤT BẠI: Lỗi 07 (Command not supported).")
                            Log.e(TAG, "👉 KẾT LUẬN: Shadowsocks chưa bật cờ '-u' hoặc 'mode=tcp_and_udp'.")
                        }

                        else -> {
                            Log.e(TAG, "❌ THẤT BẠI: Mã lỗi 0x${String.format("%02X", status)}")
                        }
                    }
                }

            } catch (e: Exception) {
                Log.e(TAG, "EXCEPTION: ${e.message}")
                e.printStackTrace()
            } finally {
                socket?.close()
                Log.w(TAG, "=== KẾT THÚC TEST ===")
            }
        }.start()
    }

    // Helper convert byte sang Hex để dễ đọc log
    private fun toHex(bytes: ByteArray, len: Int): String {
        if (len <= 0) return ""
        val sb = StringBuilder()
        for (i in 0 until len) {
            sb.append(String.format("%02X ", bytes[i]))
        }
        return sb.toString().trim()
    }
}