package com.example.vpn_test

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
// Import package từ Go (gomobile tự viết hoa chữ cái đầu)
import mysingboxlib.Mysingboxlib
import mysingboxlib.TunnelHandle

class MyVpnService : VpnService() {

    private var pfd: ParcelFileDescriptor? = null
    private var goTunnel: TunnelHandle? = null

    companion object {
        const val ACTION_STOP = "STOP_VPN"
        const val CHANNEL_ID = "VPN_CHANNEL"
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopVpn()
            return START_NOT_STICKY
        }

        // Tạo Notification để giữ Service chạy ngầm (Bắt buộc với Android O trở lên)
        startForeground(1, createNotification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_MANIFEST)

        // Chạy kết nối trên Thread riêng để không chặn UI
        Thread {
            startWireGuard()
        }.start()

        return START_STICKY
    }

    private fun startWireGuard() {
        if (pfd != null) return

        Log.i("VPN", "Đang khởi tạo kết nối đến 172.104.55.236...")

        // --- PHẦN 1: Cấu hình Android Interface (TUN) ---
        val builder = Builder()
            .setSession("MyVPN")
            .setMtu(1500)                     // Theo profile của bạn
            .addAddress("10.0.0.2", 32)       // Local Address của bạn
            .addDnsServer("8.8.8.8")          // DNS Google (hoặc dùng 1.1.1.1)
            .addRoute("0.0.0.0", 0)           // Route toàn bộ traffic qua VPN
            .addDisallowedApplication(this.packageName)

        pfd = builder.establish()

        if (pfd == null) {
            Log.e("VPN", "Không có quyền VPN hoặc lỗi khởi tạo")
            stopSelf()
            return
        }

        // --- PHẦN 2: Chuẩn bị Key (Convert Base64 -> Hex) ---
        val privateKeyBase64 = "UIZL2DKvnptRMUxCtQ84fV5z9o9ZYUGzzYaMMXZUXVQ="
        val publicKeyBase64 = "ius4nJ+ZV7Farl/EFttRLLjokljSOv+RpPjBTvxoXXQ="

        val privateKeyHex = base64ToHex(privateKeyBase64)
        val publicKeyHex = base64ToHex(publicKeyBase64)

// --- PHẦN 3: Tạo Config UAPI cho Go ---
        // LƯU Ý: Không được để dư dấu cách ở cuối các dòng
        val config = """
        private_key=$privateKeyHex
        public_key=$publicKeyHex
        endpoint=172.104.55.236:51820
        allowed_ip=0.0.0.0/0
        persistent_keepalive_interval=25
    """.trimIndent().trim()
        // Thêm .trim() ở cuối cùng để xóa sạch mọi ký tự trắng thừa nếu có

        Log.d("VPN", "Config String (Hex): \n$config")

        // --- PHẦN 4: Gọi xuống Go ---
        try {
            // QUAN TRỌNG: Dùng detachFd() vì chúng ta dùng Custom TUN bên Go
            val fd = pfd!!.detachFd()
            val socks5Proxy = "127.0.0.1:1080"
            // Gọi hàm Go
            goTunnel = Mysingboxlib.startVPN(fd.toLong(), config, socks5Proxy, "", "", 2)

            Log.i("VPN", "WireGuard Go Connected Successfully!")
        } catch (e: Exception) {
            Log.e("VPN", "Lỗi Go: ${e.message}")
            stopVpn()
        }
    }

    // Hàm chuyển đổi Base64 (dạng chuẩn của WireGuard Client) sang Hex (dạng chuẩn của Go Lib)
    private fun base64ToHex(base64: String): String {
        val decoded = android.util.Base64.decode(base64, android.util.Base64.DEFAULT)
        return decoded.joinToString("") { "%02x".format(it) }
    }

    private fun stopVpn() {
        try {
            goTunnel?.stop() // Gọi hàm Stop của Go
            pfd?.close()     // Đóng file descriptor
        } catch (e: Exception) {
            e.printStackTrace()
        } finally {
            pfd = null
            goTunnel = null
            stopForeground(true)
            stopSelf()
            Log.i("VPN", "VPN Stopped")
        }
    }

    // --- Phần boilerplate tạo Notification ---
    private fun createNotification(): Notification {
        val manager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(CHANNEL_ID, "VPN Status", NotificationManager.IMPORTANCE_DEFAULT)
            manager.createNotificationChannel(channel)
        }

        val stopIntent = Intent(this, MyVpnService::class.java).apply { action = ACTION_STOP }
        val stopPendingIntent = PendingIntent.getService(this, 0, stopIntent, PendingIntent.FLAG_IMMUTABLE)

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("VPN đang chạy")
            .setContentText("Kết nối WireGuard đang hoạt động")
            .setSmallIcon(android.R.drawable.ic_dialog_info) // Thay icon của bạn
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Ngắt kết nối", stopPendingIntent)
            .build()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }
}