package com.aegis.security.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.aegis.security.model.AppAuditItem
import com.aegis.security.model.ConnectionState
import com.aegis.security.model.RiskLevel
import com.aegis.security.model.SensorType
import com.aegis.security.model.ThreatAlert
import com.aegis.security.network.HostBridgeClient
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

class SecurityViewModel(
    private val bridgeClient: HostBridgeClient = HostBridgeClient()
) : ViewModel() {

    val connectionState = bridgeClient.connectionState
    val auditList = bridgeClient.auditList
    val feedbackMessages = bridgeClient.feedbackMessages

    // Active high-priority alert that triggers the Alert Modal
    private val _activeModalAlert = MutableStateFlow<ThreatAlert?>(null)
    val activeModalAlert = _activeModalAlert.asStateFlow()

    // Recent activity log
    private val _recentAlerts = MutableStateFlow<List<ThreatAlert>>(emptyList())
    val recentAlerts = _recentAlerts.asStateFlow()

    // Real-time active sensors mapping (SensorType -> App accessing it)
    private val _liveActiveSensors = MutableStateFlow<Map<SensorType, ThreatAlert>>(emptyMap())
    val liveActiveSensors = _liveActiveSensors.asStateFlow()

    // History of blocked items locally tracked
    private val _blockedApps = MutableStateFlow<Set<String>>(emptySet())
    val blockedApps = _blockedApps.asStateFlow()

    init {
        // Connect to laptop host over USB tunnel
        bridgeClient.connect()

        viewModelScope.launch {
            bridgeClient.incomingAlerts.collectLatest { alert ->
                // Add to recent activity
                val current = _recentAlerts.value.toMutableList()
                current.add(0, alert)
                if (current.size > 50) current.removeAt(current.size - 1)
                _recentAlerts.value = current

                // Track live sensor state
                if (alert.state == "ACTIVE") {
                    val sensors = _liveActiveSensors.value.toMutableMap()
                    sensors[alert.sensor] = alert
                    _liveActiveSensors.value = sensors

                    // If risk level is SUSPICIOUS or CRITICAL, popup the high priority alert modal!
                    if (alert.riskLevel == RiskLevel.CRITICAL || alert.riskLevel == RiskLevel.SUSPICIOUS) {
                        _activeModalAlert.value = alert
                    }
                } else if (alert.state == "RELEASED") {
                    val sensors = _liveActiveSensors.value.toMutableMap()
                    sensors.remove(alert.sensor)
                    _liveActiveSensors.value = sensors
                }
            }
        }
    }

    fun dismissActiveModal() {
        _activeModalAlert.value = null
    }

    fun blockApp(alert: ThreatAlert) {
        bridgeClient.blockApp(alert.packageName, alert.sensorStr)
        _blockedApps.value = _blockedApps.value + alert.packageName
        
        // Remove from active sensors
        val sensors = _liveActiveSensors.value.toMutableMap()
        sensors.remove(alert.sensor)
        _liveActiveSensors.value = sensors

        _activeModalAlert.value = null
    }

    fun unblockApp(packageName: String, sensor: String = "CAMERA") {
        bridgeClient.unblockApp(packageName, sensor)
        _blockedApps.value = _blockedApps.value - packageName
    }

    fun refreshAudit() {
        bridgeClient.requestAudit()
    }

    fun simulateAlert(scenario: String) {
        bridgeClient.simulateAlert(scenario)
    }

    override fun onCleared() {
        super.onCleared()
        bridgeClient.disconnect()
    }
}
