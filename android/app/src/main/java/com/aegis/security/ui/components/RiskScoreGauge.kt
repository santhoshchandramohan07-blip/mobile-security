package com.aegis.security.ui.components

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aegis.security.model.RiskLevel
import com.aegis.security.theme.CyberSurfaceVariant
import com.aegis.security.theme.NeonGreen
import com.aegis.security.theme.SafeBlue
import com.aegis.security.theme.TextMuted
import com.aegis.security.theme.TextPrimary
import com.aegis.security.theme.ThreatRed
import com.aegis.security.theme.WarningAmber

@Composable
fun RiskScoreGauge(
    score: Int,
    level: RiskLevel,
    modifier: Modifier = Modifier
) {
    val targetFraction = (score.coerceIn(0, 100)) / 100f
    val animatedFraction by animateFloatAsState(
        targetValue = targetFraction,
        animationSpec = tween(durationMillis = 800),
        label = "RiskProgress"
    )

    val color = when (level) {
        RiskLevel.CRITICAL -> ThreatRed
        RiskLevel.SUSPICIOUS -> WarningAmber
        RiskLevel.LOW -> SafeBlue
        RiskLevel.SAFE -> NeonGreen
    }

    Column(modifier = modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "THREAT LEVEL: ${level.name}",
                style = MaterialTheme.typography.labelSmall,
                color = color,
                fontWeight = FontWeight.Bold,
                fontSize = 12.sp
            )
            Text(
                text = "$score / 100",
                style = MaterialTheme.typography.headlineSmall,
                color = color,
                fontWeight = FontWeight.Bold
            )
        }

        Box(
            modifier = Modifier
                .padding(top = 6.dp)
                .fillMaxWidth()
                .height(10.dp)
                .clip(RoundedCornerShape(5.dp))
                .background(CyberSurfaceVariant)
        ) {
            Box(
                modifier = Modifier
                    .fillMaxWidth(animatedFraction)
                    .fillMaxHeight()
                    .clip(RoundedCornerShape(5.dp))
                    .background(color)
            )
        }
    }
}
