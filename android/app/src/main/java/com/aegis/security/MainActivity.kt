package com.aegis.security

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import com.aegis.security.theme.AegisShieldTheme
import com.aegis.security.theme.CyberBorder
import com.aegis.security.theme.CyberSurface
import com.aegis.security.theme.NeonCyan
import com.aegis.security.theme.TextMuted
import com.aegis.security.theme.TextPrimary
import com.aegis.security.ui.components.ThreatAlertModal
import com.aegis.security.ui.screens.AppAuditScreen
import com.aegis.security.ui.screens.BlockedAppsScreen
import com.aegis.security.ui.screens.DashboardScreen
import com.aegis.security.viewmodel.SecurityViewModel
import kotlinx.coroutines.flow.collectLatest

sealed class NavTab(val title: String, val icon: ImageVector) {
    object Dashboard : NavTab("Dashboard", Icons.Default.Radar)
    object Audit : NavTab("Audit", Icons.Default.Security)
    object Blocked : NavTab("Blocked", Icons.Default.Block)
}

class MainActivity : ComponentActivity() {
    private val viewModel: SecurityViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            AegisShieldTheme {
                MainScreen(viewModel = viewModel)
            }
        }
    }
}

@Composable
fun MainScreen(viewModel: SecurityViewModel) {
    var selectedTab by remember { mutableIntStateOf(0) }
    val tabs = listOf(NavTab.Dashboard, NavTab.Audit, NavTab.Blocked)

    val activeModalAlert by viewModel.activeModalAlert.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(Unit) {
        viewModel.feedbackMessages.collectLatest { msg ->
            snackbarHostState.showSnackbar(msg)
        }
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) },
        bottomBar = {
            NavigationBar(
                containerColor = CyberSurface,
                tonalElevation = androidx.compose.ui.unit.dp
            ) {
                tabs.forEachIndexed { index, tab ->
                    NavigationBarItem(
                        selected = selectedTab == index,
                        onClick = { selectedTab = index },
                        icon = { Icon(tab.icon, contentDescription = tab.title) },
                        label = { Text(tab.title) },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = NeonCyan,
                            selectedTextColor = NeonCyan,
                            unselectedIconColor = TextMuted,
                            unselectedTextColor = TextMuted,
                            indicatorColor = CyberBorder
                        )
                    )
                }
            }
        }
    ) { innerPadding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {
            when (selectedTab) {
                0 -> DashboardScreen(viewModel = viewModel)
                1 -> AppAuditScreen(viewModel = viewModel)
                2 -> BlockedAppsScreen(viewModel = viewModel)
            }

            // High Priority Anomaly Modal pop up!
            activeModalAlert?.let { alert ->
                ThreatAlertModal(
                    alert = alert,
                    onBlockClick = { threat ->
                        viewModel.blockApp(threat)
                    },
                    onDismissClick = {
                        viewModel.dismissActiveModal()
                    }
                )
            }
        }
    }
}
