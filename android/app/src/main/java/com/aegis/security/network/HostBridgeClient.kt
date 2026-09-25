package com.aegis.security.network

import android.util.Log
import com.aegis.security.model.AppAuditItem
import com.aegis.security.model.ConnectionState
import com.aegis.security.model.ThreatAlert
import com.google.gson.Gson
import com.google.gson.JsonObject
import com.google.gson.reflect.TypeToken
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import java.util.concurrent.TimeUnit

class HostBridgeClient(
    private val hostUrl: String = "ws://127.0.0.1:8765"
) {
    private val tag = "AegisBridge"
    private val gson = Gson()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val client = OkHttpClient.Builder()
        .readTimeout(0, TimeUnit.MILLISECONDS)
        .pingInterval(5, TimeUnit.SECONDS)
        .build()

    private var webSocket: WebSocket? = null
    private var isShouldReconnect = true

    private val _connectionState = MutableStateFlow(ConnectionState())
    val connectionState = _connectionState.asStateFlow()

    private val _incomingAlerts = MutableSharedFlow<ThreatAlert>(extraBufferCapacity = 64)
    val incomingAlerts = _incomingAlerts.asSharedFlow()

    private val _auditList = MutableStateFlow<List<AppAuditItem>>(emptyList())
    val auditList = _auditList.asStateFlow()

    private val _feedbackMessages = MutableSharedFlow<String>(extraBufferCapacity = 32)
    val feedbackMessages = _feedbackMessages.asSharedFlow()

    fun connect() {
        isShouldReconnect = true
        initiateConnection()
    }

    private fun initiateConnection() {
        val request = Request.Builder()
            .url(hostUrl)
            .build()

        _connectionState.value = _connectionState.value.copy(
            isConnected = false,
            statusMessage = "Connecting to Host Bridge via USB..."
        )

        webSocket = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(ws: WebSocket, response: Response) {
                Log.i(tag, "WebSocket connection established with laptop host.")
                _connectionState.value = ConnectionState(
                    isConnected = true,
                    activeProtection = true,
                    statusMessage = "Shield Active (Connected to Laptop via USB)"
                )
                // Request initial audit list
                requestAudit()
            }

            override fun onMessage(ws: WebSocket, text: String) {
                handleIncomingMessage(text)
            }

            override fun onClosed(ws: WebSocket, code: Int, reason: String) {
                Log.w(tag, "WebSocket closed: $reason ($code)")
                handleDisconnect()
            }

            override fun onFailure(ws: WebSocket, t: Throwable, response: Response?) {
                Log.e(tag, "WebSocket failure: ${t.message}")
                handleDisconnect()
            }
        })
    }

    private fun handleDisconnect() {
        _connectionState.value = ConnectionState(
            isConnected = false,
            activeProtection = false,
            statusMessage = "Disconnected from Laptop. Retrying USB link..."
        )
        if (isShouldReconnect) {
            scope.launch {
                delay(3000)
                initiateConnection()
            }
        }
    }

    private fun handleIncomingMessage(text: String) {
        try {
            val json = gson.fromJson(text, JsonObject::class.java)
            val type = json.get("type")?.asString ?: return

            when (type) {
                "CONNECTION_ESTABLISHED" -> {
                    val serial = json.get("device_serial")?.asString ?: "USB_DEVICE"
                    _connectionState.value = _connectionState.value.copy(
                        isConnected = true,
                        deviceSerial = serial,
                        activeProtection = true,
                        statusMessage = "Protected by Laptop Agent ($serial)"
                    )
                }
                "SENSOR_ALERT" -> {
                    val alert = gson.fromJson(text, ThreatAlert::class.java)
                    _incomingAlerts.tryEmit(alert)
                }
                "BLOCK_RESPONSE" -> {
                    val status = json.get("status")?.asString ?: ""
                    val pkg = json.get("package_name")?.asString ?: ""
                    val msg = json.get("message")?.asString ?: ""
                    _feedbackMessages.tryEmit("[$status] $pkg: $msg")
                    requestAudit() // Refresh audit
                }
                "UNBLOCK_RESPONSE" -> {
                    val status = json.get("status")?.asString ?: ""
                    val pkg = json.get("package_name")?.asString ?: ""
                    val msg = json.get("message")?.asString ?: ""
                    _feedbackMessages.tryEmit("[$status] Restored $pkg: $msg")
                    requestAudit()
                }
                "AUDIT_REPORT" -> {
                    val appsJson = json.getAsJsonArray("apps")
                    val typeToken = object : TypeToken<List<AppAuditItem>>() {}.type
                    val list: List<AppAuditItem> = gson.fromJson(appsJson, typeToken)
                    _auditList.value = list
                }
            }
        } catch (e: Exception) {
            Log.e(tag, "Error parsing host message: ${e.message}")
        }
    }

    fun blockApp(packageName: String, sensor: String) {
        val payload = JsonObject().apply {
            addProperty("action", "BLOCK_APP")
            addProperty("package_name", packageName)
            addProperty("sensor", sensor)
        }
        webSocket?.send(payload.toString())
    }

    fun unblockApp(packageName: String, sensor: String) {
        val payload = JsonObject().apply {
            addProperty("action", "UNBLOCK_APP")
            addProperty("package_name", packageName)
            addProperty("sensor", sensor)
        }
        webSocket?.send(payload.toString())
    }

    fun requestAudit() {
        val payload = JsonObject().apply {
            addProperty("action", "REQUEST_AUDIT")
        }
        webSocket?.send(payload.toString())
    }

    fun simulateAlert(scenario: String = "CALCULATOR_CAMERA") {
        val payload = JsonObject().apply {
            addProperty("action", "SIMULATE_ALERT")
            addProperty("scenario", scenario)
        }
        webSocket?.send(payload.toString())
    }

    fun disconnect() {
        isShouldReconnect = false
        webSocket?.close(1000, "App closed")
        webSocket = null
    }
}
