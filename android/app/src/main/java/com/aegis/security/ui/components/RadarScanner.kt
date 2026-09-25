package com.aegis.security.ui.components

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.aegis.security.theme.CyberBorder
import com.aegis.security.theme.NeonCyan
import com.aegis.security.theme.NeonGreen
import com.aegis.security.theme.ThreatRed

@Composable
fun RadarScanner(
    modifier: Modifier = Modifier,
    size: Dp = 160.dp,
    isThreatActive: Boolean = false,
    content: @Composable () -> Unit = {}
) {
    val infiniteTransition = rememberInfiniteTransition(label = "RadarTransition")
    val angle by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 2800, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "RadarSweep"
    )

    val sweepColor = if (isThreatActive) ThreatRed else NeonCyan
    val ringColor = if (isThreatActive) ThreatRed.copy(alpha = 0.3f) else CyberBorder

    Box(
        modifier = modifier.size(size),
        contentAlignment = Alignment.Center
    ) {
        Canvas(modifier = Modifier.size(size)) {
            val center = Offset(size.toPx() / 2, size.toPx() / 2)
            val radius = size.toPx() / 2

            // Concentric Radar Rings
            drawCircle(color = ringColor, radius = radius, style = Stroke(width = 1.5f))
            drawCircle(color = ringColor, radius = radius * 0.66f, style = Stroke(width = 1.2f))
            drawCircle(color = ringColor, radius = radius * 0.33f, style = Stroke(width = 1.0f))

            // Crosshairs
            drawLine(
                color = ringColor.copy(alpha = 0.4f),
                start = Offset(center.x, 0f),
                end = Offset(center.x, size.toPx()),
                strokeWidth = 1f
            )
            drawLine(
                color = ringColor.copy(alpha = 0.4f),
                start = Offset(0f, center.y),
                end = Offset(size.toPx(), center.y),
                strokeWidth = 1f
            )

            // Radar Sweep gradient
            rotate(degrees = angle, pivot = center) {
                drawArc(
                    brush = Brush.sweepGradient(
                        colors = listOf(
                            Color.Transparent,
                            sweepColor.copy(alpha = 0.1f),
                            sweepColor.copy(alpha = 0.45f)
                        ),
                        center = center
                    ),
                    startAngle = 0f,
                    sweepAngle = 65f,
                    useCenter = true
                )
            }
        }

        content()
    }
}
