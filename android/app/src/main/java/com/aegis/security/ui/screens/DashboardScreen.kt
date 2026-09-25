package com.aegis.security.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cable
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aegis.security.model.RiskLevel
import com.aegis.security.model.SensorType
import com.aegis.security.theme.CyberBg
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
import com.aegis.security.ui.components.RadarScanner
import com.aegis.security.ui.components.SensorIndicatorBadge
import com.aegis.security.viewmodel.SecurityViewModel

@Composable
fun DashboardScreen(
    viewModel: SecurityViewModel,
    modifier: Modifier = Modifier
) {
    val connectionState by viewModel.connectionState.collectAsState()
    val liveSensors by viewModel.liveActiveSensors.collectAsState()
    val recentAlerts by viewModel.recentAlerts.collectAsState()

    val hasActiveThreat = liveSensors.values.any { it.riskLevel == RiskLevel.CRITICAL }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .background(CyberBg)
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Spacer(modifier = Modifier.height(8.dp))
            // 1. USB Connection Status Header
            Card(
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(containerColor = CyberSurface),
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, CyberBorder, RoundedCornerShape(12.dp))
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.Cable,
                            contentDescription = "USB",
                            tint = if (connectionState.isConnected) NeonCyan else TextMuted,
                            modifier = Modifier.size(20.dp)
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Column {
                            Text(
                                text = if (connectionState.isConnected) "USB HOST LINKED" else "USB OFFLINE",
                                style = MaterialTheme.typography.labelSmall,
                                color = if (connectionState.isConnected) NeonCyan else TextMuted,
                                fontWeight = FontWeight.Bold
                            )
                            Text(
                                text = connectionState.statusMessage,
                                style = MaterialTheme.typography.bodyMedium,
                                fontSize = 11.sp,
                                color = TextSecondary
                            )
                        }
                    }

                    Box(
                        modifier = Modifier
                            .size(10.dp)
                            .clip(CircleShape)
                            .background(if (connectionState.isConnected) NeonGreen else ThreatRed)
                    )
                }
            }
        }

        item {
            // 2. Center Radar HUD with Shield Status
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 12.dp),
                contentAlignment = Alignment.Center
            ) {
                RadarScanner(
                    size = 180.dp,
                    isThreatActive = hasActiveThreat
                ) {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center
                    ) {
                        Icon(
                            imageVector = if (hasActiveThreat) Icons.Default.Security else Icons.Default.Shield,
                            contentDescription = "Shield",
                            tint = if (hasActiveThreat) ThreatRed else NeonCyan,
                            modifier = Modifier.size(36.dp)
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = if (hasActiveThreat) "THREAT!" else "GUARDED",
                            style = MaterialTheme.typography.labelSmall,
                            color = if (hasActiveThreat) ThreatRed else NeonGreen,
                            fontWeight = FontWeight.Bold,
                            fontSize = 12.sp
                        )
                    }
                }
            }
        }

        item {
            // 3. Real-Time Active Sensor Indicators
            Text(
                text = "REAL-TIME SENSOR TELEMETRY",
                style = MaterialTheme.typography.labelSmall,
                color = TextSecondary,
                fontWeight = FontWeight.Bold
            )
            Spacer(modifier = Modifier.height(8.dp))

            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                SensorIndicatorBadge(
                    sensorType = SensorType.CAMERA,
                    activeAlert = liveSensors[SensorType.CAMERA]
                )
                SensorIndicatorBadge(
                    sensorType = SensorType.MICROPHONE,
                    activeAlert = liveSensors[SensorType.MICROPHONE]
                )
                SensorIndicatorBadge(
                    sensorType = SensorType.LOCATION,
                    activeAlert = liveSensors[SensorType.LOCATION]
                )
            }
        }

        item {
            // 4. Test Trigger / Simulation Buttons for User Demo
            Card(
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(containerColor = CyberSurfaceVariant.copy(alpha = 0.5f)),
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, CyberBorder, RoundedCornerShape(12.dp))
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text(
                        text = "TEST SENSOR ACCESS SCENARIOS",
                        style = MaterialTheme.typography.labelSmall,
                        color = NeonCyan,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = "Trigger simulated access events to verify risk scoring & popup alerts:",
                        style = MaterialTheme.typography.bodyMedium,
                        fontSize = 11.sp,
                        color = TextSecondary,
                        modifier = Modifier.padding(vertical = 4.dp)
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = { viewModel.simulateAlert("CALCULATOR_CAMERA") },
                            colors = ButtonDefaults.buttonColors(containerColor = ThreatRed.copy(alpha = 0.8f)),
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Calc → Camera", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                        }

                        Button(
                            onClick = { viewModel.simulateAlert("FLASHLIGHT_MIC") },
                            colors = ButtonDefaults.buttonColors(containerColor = WarningAmber.copy(alpha = 0.8f)),
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Flashlight → Mic", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }
        }

        item {
            // 5. Recent Activity Stream Header
            Text(
                text = "ACCESS EVENT LOGS",
                style = MaterialTheme.typography.labelSmall,
                color = TextSecondary,
                fontWeight = FontWeight.Bold
            )
        }

        if (recentAlerts.isEmpty()) {
            item {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(24.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = "No unauthorized sensor activity recorded.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = TextMuted
                    )
                }
            }
        } else {
            items(recentAlerts) { alert ->
                Card(
                    shape = RoundedCornerShape(10.dp),
                    colors = CardDefaults.cardColors(containerColor = CyberSurface),
                    modifier = Modifier
                        .fillMaxWidth()
                        .border(
                            1.dp,
                            if (alert.riskLevel == RiskLevel.CRITICAL) ThreatRed.copy(alpha = 0.5f) else CyberBorder,
                            RoundedCornerShape(10.dp)
                        )
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(12.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "${alert.appName} (${alert.sensorStr})",
                                style = MaterialTheme.typography.titleMedium,
                                color = TextPrimary,
                                fontSize = 14.sp
                            )
                            Text(
                                text = alert.packageName,
                                style = MaterialTheme.typography.labelSmall,
                                color = TextMuted,
                                fontSize = 11.sp
                            )
                            if (alert.reasons.isNotEmpty()) {
                                Text(
                                    text = alert.reasons.first(),
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = TextSecondary,
                                    fontSize = 11.sp,
                                    maxLines = 1,
                                    modifier = Modifier.padding(top = 2.dp)
                                )
                            }
                        }

                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(6.dp))
                                .background(
                                    when (alert.riskLevel) {
                                        RiskLevel.CRITICAL -> ThreatRed.copy(alpha = 0.2f)
                                        RiskLevel.SUSPICIOUS -> WarningAmber.copy(alpha = 0.2f)
                                        else -> NeonGreen.copy(alpha = 0.2f)
                                    }
                                )
                                .padding(horizontal = 8.dp, vertical = 4.dp)
                        ) {
                            Text(
                                text = "${alert.riskScore}/100",
                                style = MaterialTheme.typography.labelSmall,
                                color = when (alert.riskLevel) {
                                    RiskLevel.CRITICAL -> ThreatRed
                                    RiskLevel.SUSPICIOUS -> WarningAmber
                                    else -> NeonGreen
                                },
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                }
            }
        }

        item {
            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}
