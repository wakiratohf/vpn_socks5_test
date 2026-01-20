package com.example.vpn_test

import android.app.Activity
import android.content.Intent
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import kotlinx.coroutines.delay
import java.io.FileDescriptor
import java.io.IOException

class MainActivity : AppCompatActivity() {
    companion object {
        const val VPN_REQUEST_CODE = 100
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL

            val margin = (16 * resources.displayMetrics.density).toInt()

            val connectParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(margin, margin, margin, margin) }

            val disconnectParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(margin, 0, margin, margin) }

            val connectButton = Button(context).apply {
                text = "Kết nối VPN"
                setOnClickListener { prepareVpn() }
                layoutParams = connectParams
            }

            val disconnectButton = Button(context).apply {
                text = "Ngắt kết nối VPN"
                setOnClickListener {
                    val stopIntent = Intent(context, MyVpnService::class.java)
                    stopService(stopIntent)
                }
                layoutParams = disconnectParams
            }

            val testButton = Button(context).apply {
                text = "Test socks5"
                setOnClickListener {
                    Socks5Diagnostic.runTest("127.0.0.1", 1080)
                }
                layoutParams = disconnectParams
            }

            addView(connectButton)
            addView(disconnectButton)
            addView(testButton)
        }

        setContentView(layout)
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