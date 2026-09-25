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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aegis.security.model.RiskLevel
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
import com.aegis.security.viewmodel.SecurityViewModel

@Composable
fun AppAuditScreen(
    viewModel: SecurityViewModel,
    modifier: Modifier = Modifier
) {
    val auditList by viewModel.auditList.collectAsState()
    val blockedApps by viewModel.blockedApps.collectAsState()

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(CyberBg)
            .padding(horizontal = 16.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = "PERMISSION RISK AUDIT",
                    style = MaterialTheme.typography.titleLarge,
                    color = NeonCyan,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = "${auditList.size} Applications Profiled",
                    style = MaterialTheme.typography.bodyMedium,
                    color = TextSecondary,
                    fontSize = 12.sp
                )
            }

            IconButton(onClick = { viewModel.refreshAudit() }) {
                Icon(
                    imageVector = Icons.Default.Refresh,
                    contentDescription = "Refresh",
                    tint = NeonCyan
                )
            }
        }

        if (auditList.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(32.dp),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        text = "Scanning Device Packages via ADB...",
                        style = MaterialTheme.typography.bodyLarge,
                        color = TextSecondary
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Button(
                        onClick = { viewModel.refreshAudit() },
                        colors = ButtonDefaults.buttonColors(containerColor = NeonCyan)
                    ) {
                        Text("Trigger App Audit", color = CyberBg, fontWeight = FontWeight.Bold)
                    }
                }
            }
        } else {
            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(10.dp),
                modifier = Modifier.fillMaxSize()
            ) {
                items(auditList) { app ->
                    val isBlocked = blockedApps.contains(app.packageName) || app.isBlocked
                    Card(
                        shape = RoundedCornerShape(12.dp),
                        colors = CardDefaults.cardColors(containerColor = CyberSurface),
                        modifier = Modifier
                            .fillMaxWidth()
                            .border(1.dp, CyberBorder, RoundedCornerShape(12.dp))
                    ) {
                        Column(modifier = Modifier.padding(14.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = app.appName,
                                        style = MaterialTheme.typography.titleMedium,
                                        color = TextPrimary,
                                        fontWeight = FontWeight.Bold
                                    )
                                    Text(
                                        text = app.packageName,
                                        style = MaterialTheme.typography.labelSmall,
                                        color = TextMuted,
                                        fontSize = 11.sp
                                    )
                                }

                                Box(
                                    modifier = Modifier
                                        .clip(RoundedCornerShape(6.dp))
                                        .background(
                                            when (app.riskLevel) {
                                                RiskLevel.CRITICAL -> ThreatRed.copy(alpha = 0.2f)
                                                RiskLevel.SUSPICIOUS -> WarningAmber.copy(alpha = 0.2f)
                                                else -> NeonGreen.copy(alpha = 0.2f)
                                            }
                                        )
                                        .padding(horizontal = 8.dp, vertical = 4.dp)
                                ) {
                                    Text(
                                        text = "Risk: ${app.riskScore}/100",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = when (app.riskLevel) {
                                            RiskLevel.CRITICAL -> ThreatRed
                                            RiskLevel.SUSPICIOUS -> WarningAmber
                                            else -> NeonGreen
                                        },
                                        fontWeight = FontWeight.Bold
                                    )
                                }
                            }

                            Spacer(modifier = Modifier.height(8.dp))

                            // Permissions Row
                            Row(
                                horizontalArrangement = Arrangement.spacedBy(6.dp),
                                modifier = Modifier.padding(vertical = 4.dp)
                            ) {
                                app.permissions.forEach { perm ->
                                    Box(
                                        modifier = Modifier
                                            .clip(RoundedCornerShape(4.dp))
                                            .background(CyberSurfaceVariant)
                                            .padding(horizontal = 6.dp, vertical = 2.dp)
                                    ) {
                                        Text(
                                            text = perm,
                                            style = MaterialTheme.typography.labelSmall,
                                            fontSize = 10.sp,
                                            color = TextSecondary
                                        )
                                    }
                                }
                            }

                            // Flags
                            app.flags.forEach { flag ->
                                Text(
                                    text = "• $flag",
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = ThreatRed,
                                    fontSize = 11.sp,
                                    modifier = Modifier.padding(vertical = 1.dp)
                                )
                            }

                            Spacer(modifier = Modifier.height(10.dp))

                            // Action Button
                            Button(
                                onClick = {
                                    if (isBlocked) {
                                        viewModel.unblockApp(app.packageName)
                                    } else {
                                        viewModel.blockApp(
                                            com.aegis.security.model.ThreatAlert(
                                                packageName = app.packageName,
                                                appName = app.appName,
                                                sensorStr = "CAMERA",
                                                riskScore = app.riskScore
                                            )
                                        )
                                    }
                                },
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = if (isBlocked) NeonGreen else ThreatRed
                                ),
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier.fillMaxWidth().height(38.dp)
                            ) {
                                Text(
                                    text = if (isBlocked) "UNBLOCK PERMISSIONS" else "BLOCK ACCESS (ENFORCE VIA ADB)",
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Bold
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}
