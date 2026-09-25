# AegisShield: Real-Time Mobile Security & Sensor Anomaly Guard

A mobile security system that detects real-time Camera, Microphone, and Data access by Android applications via an ADB bridge over USB. It computes permission anomaly risk scores (e.g., flagging a Calculator requesting Camera or Microphone access) and displays live telemetry with one-click blocking on a Jetpack Compose Android app.

---

## System Architecture

```
+-------------------------------------------------------------+
|                     LAPTOP (HOST ENGINE)                    |
|                                                             |
|   +------------------+         +-------------------------+  |
|   |  dumpsys camera  |         |   Risk Scoring Engine   |  |
|   |  dumpsys audio   | ------> | - Category Anomaly      |  |
|   |  cmd appops      |         | - Background Penalty    |  |
|   +------------------+         | - Exfiltration Threat   |  |
|                                +-------------------------+  |
|                                             |               |
|                                             v               |
|   +-----------------------------------------------------+   |
|   |         WebSocket Server (ws://127.0.0.1:8765)      |   |
|   +-----------------------------------------------------+   |
+-------------------------------------------------------------+
                              |
               [ USB Cable with ADB Reverse ]
                              |
+-------------------------------------------------------------+
|                  ANDROID PHONE (KOTLIN APP)                 |
|                                                             |
|   +------------------+         +-------------------------+  |
|   | WebSocket Client | ------> |  Real-Time Security HUD |  |
|   +------------------+         |  - Radar Scanner        |  |
|            ^                   |  - Sensor Badges        |  |
|            |                   |  - Live Access Feed     |  |
|            |                   +-------------------------+  |
|            |                                |               |
|            +------ "BLOCK APP" Action <-----+               |
|                                                             |
|   +-----------------------------------------------------+   |
|   | High-Priority Alert Modal (e.g., Calculator Alert)  |   |
|   +-----------------------------------------------------+   |
+-------------------------------------------------------------+
```

---

## Features

1. **Real-Time Sensor Telemetry**:
   - 🔴 **Camera**: Tracks active CameraService sessions via `dumpsys media.camera`.
   - 🎙️ **Microphone**: Tracks active AudioFlinger record threads via `dumpsys audio`.
   - 🌐 **Data & Network**: Tracks telemetry and background transmission.

2. **Context-Aware Risk Scoring (0 - 100)**:
   - Evaluates **App Category vs Sensor Mismatch** (e.g., Calculator or Flashlight accessing Camera or Mic triggers an immediate **85 - 100 Critical Threat Score**).
   - Penalizes stealth background sensor access (+35 - +40 penalty).
   - Evaluates data exfiltration risk when dangerous sensors are combined with Internet permission.

3. **Enforced Blocking Without Root**:
   - Leverages Android OS AppOps: `cmd appops set <package> <op> ignore`.
   - The offending app is silenced/blocked without crashing the system or requiring root privileges.

4. **Modern Cyberpunk UI (Jetpack Compose + Material 3)**:
   - Animated Cyber Radar Scanner.
   - Pulsing live sensor badges.
   - High-priority Anomaly Alert Modal with risk meter and direct block button.
   - Complete App Risk Audit screen.
   - Blocked Apps Management screen.

---

## Directory Layout

```
aegis-security/
├── host/                             # Laptop Companion Daemon
│   ├── adb_manager.py                # ADB command execution & AppOps enforcement
│   ├── risk_engine.py                # Category anomaly heuristics & risk scoring
│   ├── sensor_monitor.py             # Polling loop for active camera & mic clients
│   ├── host_daemon.py                # Main WebSocket server & event dispatcher
│   ├── test_risk_engine.py           # Unit tests for risk engine
│   ├── test_mobile_bridge.py         # End-to-end WebSocket communication test
│   └── requirements.txt              # Python dependencies
├── android/                          # Android Kotlin Project (Jetpack Compose)
│   ├── app/
│   │   ├── src/main/java/com/aegis/security/
│   │   │   ├── MainActivity.kt       # Root activity & bottom tab navigation
│   │   │   ├── theme/                # Cyberpunk dark theme & typography
│   │   │   ├── model/                # Data models (ThreatAlert, RiskLevel, etc.)
│   │   │   ├── network/              # OkHttp WebSocket client over USB
│   │   │   ├── viewmodel/            # Reactive state management
│   │   │   └── ui/
│   │   │       ├── components/       # RadarScanner, SensorBadge, ThreatAlertModal
│   │   │       └── screens/          # Dashboard, AppAudit, BlockedApps
│   │   └── build.gradle.kts
│   ├── build.gradle.kts
│   └── settings.gradle.kts
└── run_host.bat                      # 1-Click launcher for laptop host
```

---

## Quick Start Guide

### Step 1: Prepare Your Android Phone
1. Go to **Settings > About Phone** and tap **Build Number** 7 times to enable **Developer Options**.
2. Go to **Settings > Developer Options** and enable **USB Debugging**.
3. Plug your phone into your laptop via USB cable. When prompted on your phone, tap **"Always allow from this computer"**.

### Step 2: Start the Laptop Host Daemon
1. Open a terminal in `aegis-security/host` or double-click `run_host.bat`:
   ```bash
   cd host
   pip install -r requirements.txt
   python host_daemon.py
   ```
2. The daemon will automatically detect your phone, map the reverse USB port (`adb reverse tcp:8765 tcp:8765`), and start the security monitor.

### Step 3: Run the Android App
1. Open the `aegis-security/android` folder in **Android Studio**.
2. Click **Run > Run 'app'** to install it on your connected phone.
3. The app will open and show **"USB HOST LINKED: Shield Active"** with the live radar scanning!

### Step 4: Test Anomaly Detection
- Open any camera or recording app on your phone to see the live sensor badges light up.
- Or tap **"Calc -> Camera"** on the app dashboard to simulate the exact Calculator anomaly scenario and watch the **Threat Alert Modal** pop up with risk score 85/100 and the **"BLOCK APP IMMEDIATELY"** button!
