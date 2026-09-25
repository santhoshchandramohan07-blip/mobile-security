package com.aegis.security.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CameraAlt
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.Public
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aegis.security.model.SensorType
import com.aegis.security.model.ThreatAlert
import com.aegis.security.theme.CyberBorder
import com.aegis.security.theme.CyberSurface
import com.aegis.security.theme.CyberSurfaceVariant
import com.aegis.security.theme.NeonCyan
import com.aegis.security.theme.NeonGreen
import com.aegis.security.theme.TextMuted
import com.aegis.security.theme.TextPrimary
import com.aegis.security.theme.TextSecondary
import com.aegis.security.theme.ThreatRed
import com.aegis.security.theme.WarningAmber

@Composable
fun SensorIndicatorBadge(
    sensorType: SensorType,
    activeAlert: ThreatAlert?,
    modifier: Modifier = Modifier
) {
    val isActive = activeAlert != null
    val icon: ImageVector = when (sensorType) {
        SensorType.CAMERA -> Icons.Default.CameraAlt
        SensorType.MICROPHONE -> Icons.Default.Mic
        SensorType.LOCATION -> Icons.Default.Public
        else -> Icons.Default.Public
    }

    val sensorName = when (sensorType) {
        SensorType.CAMERA -> "CAMERA"
        SensorType.MICROPHONE -> "MIC"
        SensorType.LOCATION -> "LOCATION"
        SensorType.BACKGROUND_DATA -> "DATA"
        else -> "SENSOR"
    }

    val badgeColor = when {
        !isActive -> TextMuted.copy(alpha = 0.3f)
        activeAlert?.riskScore ?: 0 >= 75 -> ThreatRed
        activeAlert?.riskScore ?: 0 >= 50 -> WarningAmber
        else -> NeonGreen
    }

    val containerBg = if (isActive) CyberSurfaceVariant else CyberSurface
    val borderColor = if (isActive) badgeColor.copy(alpha = 0.8f) else CyberBorder

    Box(
        modifier = modifier
            .clip(RoundedCornerShape(12.dp))
            .background(containerBg)
            .border(1.dp, borderColor, RoundedCornerShape(12.dp))
            .padding(horizontal = 12.dp, vertical = 10.dp)
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                // Pulsing indicator dot
                Box(
                    modifier = Modifier
                        .size(10.dp)
                        .clip(CircleShape)
                        .background(badgeColor)
                )

                Spacer(modifier = Modifier.width(10.dp))

                Icon(
                    imageVector = icon,
                    contentDescription = sensorName,
                    tint = if (isActive) TextPrimary else TextMuted,
                    modifier = Modifier.size(20.dp)
                )

                Spacer(modifier = Modifier.width(8.dp))

                Column {
                    Text(
                        text = sensorName,
                        style = MaterialTheme.typography.labelSmall,
                        color = if (isActive) TextPrimary else TextMuted
                    )
                    Text(
                        text = if (isActive) "ACTIVE: ${activeAlert?.appName}" else "IDLE / PROTECTED",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = if (isActive) FontWeight.SemiBold else FontWeight.Normal,
                        color = if (isActive) badgeColor else TextMuted,
                        fontSize = 12.sp
                    )
                }
            }

            if (isActive && activeAlert != null) {
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(badgeColor.copy(alpha = 0.2f))
                        .padding(horizontal = 8.dp, vertical = 4.dp)
                ) {
                    Text(
                        text = "${activeAlert.riskScore}/100",
                        style = MaterialTheme.typography.labelSmall,
                        color = badgeColor,
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        }
    }
}
