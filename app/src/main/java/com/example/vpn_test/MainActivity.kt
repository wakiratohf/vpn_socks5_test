package com.example.vpn_test

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat

class MainActivity : AppCompatActivity() {
    companion object {
        const val VPN_REQUEST_CODE = 100
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Tạo giao diện đơn giản bằng code (không cần file xml layout)
        val button = Button(this).apply {
            text = "Kết nối VPN"
            setOnClickListener { prepareVpn() }
        }
        setContentView(button)
    }

    private fun prepareVpn() {
        // Kiểm tra quyền VPN của hệ thống
        val intent = VpnService.prepare(this)
        if (intent != null) {
            // Nếu chưa có quyền, hệ thống trả về Intent để hỏi người dùng
            startActivityForResult(intent, VPN_REQUEST_CODE)
        } else {
            // Đã có quyền, start luôn
            startVpnService()
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, MyVpnService::class.java)
        ContextCompat.startForegroundService(this@MainActivity, intent)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
            startVpnService()
        }
    }
}