package com.aegis.security.model

import com.google.gson.annotations.SerializedName

enum class SensorType {
    CAMERA,
    MICROPHONE,
    LOCATION,
    BACKGROUND_DATA,
    UNKNOWN;

    companion object {
        fun fromString(type: String?): SensorType {
            return when (type?.uppercase()) {
                "CAMERA" -> CAMERA
                "MICROPHONE", "RECORD_AUDIO", "AUDIO" -> MICROPHONE
                "LOCATION", "FINE_LOCATION" -> LOCATION
                "BACKGROUND_DATA", "DATA" -> BACKGROUND_DATA
                else -> UNKNOWN
            }
        }
    }
}

enum class RiskLevel {
    SAFE,
    LOW,
    SUSPICIOUS,
    CRITICAL;

    companion object {
        fun fromScore(score: Int): RiskLevel {
            return when {
                score >= 75 -> CRITICAL
                score >= 55 -> SUSPICIOUS
                score >= 30 -> LOW
                else -> SAFE
            }
        }

        fun fromString(level: String?): RiskLevel {
            return when (level?.uppercase()) {
                "CRITICAL" -> CRITICAL
                "SUSPICIOUS" -> SUSPICIOUS
                "LOW" -> LOW
                else -> SAFE
            }
        }
    }
}

data class ThreatAlert(
    @SerializedName("timestamp") val timestamp: Long = System.currentTimeMillis(),
    @SerializedName("state") val state: String = "ACTIVE",
    @SerializedName("sensor") val sensorStr: String = "CAMERA",
    @SerializedName("package_name") val packageName: String = "",
    @SerializedName("app_name") val appName: String = "",
    @SerializedName("category") val category: String = "UNKNOWN",
    @SerializedName("is_background") val isBackground: Boolean = false,
    @SerializedName("risk_score") val riskScore: Int = 0,
    @SerializedName("risk_level") val riskLevelStr: String = "SAFE",
    @SerializedName("reasons") val reasons: List<String> = emptyList(),
    @SerializedName("recommend_block") val recommendBlock: Boolean = false,
    @SerializedName("description") val description: String = ""
) {
    val sensor: SensorType get() = SensorType.fromString(sensorStr)
    val riskLevel: RiskLevel get() = RiskLevel.fromString(riskLevelStr)
}

data class AppAuditItem(
    @SerializedName("package_name") val packageName: String,
    @SerializedName("app_name") val appName: String,
    @SerializedName("permissions") val permissions: List<String>,
    @SerializedName("risk_score") val riskScore: Int,
    @SerializedName("is_blocked") val isBlocked: Boolean,
    @SerializedName("flags") val flags: List<String>
) {
    val riskLevel: RiskLevel get() = RiskLevel.fromScore(riskScore)
}

data class ConnectionState(
    val isConnected: Boolean = false,
    val deviceSerial: String = "",
    val activeProtection: Boolean = false,
    val statusMessage: String = "Connecting to Host Engine over USB..."
)
