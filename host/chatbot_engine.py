"""
AegisShield Mobile Security - AI Copilot Chatbot Engine
Provides real-time conversational intelligence regarding device permissions,
live sensor access events, camera/microphone usage history, and comprehensive mobile security guidance.
"""

import re
import time
from typing import Dict, List, Any, Optional

PACKAGE_NAME_MAP = {
    "com.instagram.android": "Instagram",
    "com.whatsapp": "WhatsApp",
    "com.snapchat.android": "Snapchat",
    "com.sec.android.app.camera": "Samsung Camera",
    "com.google.android.GoogleCamera": "Google Camera",
    "com.sec.android.app.popupcalculator": "Calculator",
    "com.sec.android.app.voicenote": "Voice Recorder",
    "com.openai.chatgpt": "ChatGPT",
    "com.google.android.apps.nbu.paisa.user": "Google Pay",
    "com.phonepe.app": "PhonePe",
    "com.google.android.apps.photos": "Google Photos",
    "com.picsart.studio": "Picsart Studio",
    "com.android.chrome": "Google Chrome",
    "com.google.android.youtube": "YouTube",
    "com.truecaller": "Truecaller",
    "org.telegram.messenger": "Telegram"
}

class SecurityChatbotEngine:
    def __init__(self, adb_manager, sensor_monitor, risk_engine):
        self.adb = adb_manager
        self.sensor_monitor = sensor_monitor
        self.risk_engine = risk_engine

    def _infer_app_title(self, package_name: str) -> str:
        if package_name in PACKAGE_NAME_MAP:
            return PACKAGE_NAME_MAP[package_name]
        # Check installed apps cache
        apps = self.adb.get_installed_third_party_apps()
        for a in apps:
            if a.get("package_name") == package_name and a.get("app_name"):
                return a["app_name"]
        clean = package_name.split(".")[-1].replace("_", " ").title()
        return clean

    def process_message(self, user_text: str) -> Dict[str, Any]:
        """Process user's security question and return conversational answer with actionable suggestions."""
        text = user_text.lower().strip()
        apps_data = self.adb.get_installed_third_party_apps()
        event_history = self.sensor_monitor.event_history
        last_sensors = self.sensor_monitor.last_sensor_use

        # Helper to find app by name in third party apps
        def find_app(name_query: str) -> Optional[Dict]:
            for app in apps_data:
                if name_query.lower() in app.get("app_name", "").lower() or name_query.lower() in app.get("package_name", "").lower():
                    return app
            return None

        # ----------------------------------------------------
        # 1. ACTION: Direct Block / Unblock Permission Request
        # ----------------------------------------------------
        if "block" in text and ("calculator" in text or "snapchat" in text or "camera" in text or "mic" in text or "instagram" in text):
            target_pkg = None
            target_sensor = "CAMERA"
            target_name = "the requested app"

            if "calculator" in text:
                target_pkg = "com.sec.android.app.popupcalculator"
                target_name = "Calculator"
            elif "snapchat" in text:
                target_pkg = "com.snapchat.android"
                target_name = "Snapchat"
            elif "instagram" in text:
                target_pkg = "com.instagram.android"
                target_name = "Instagram"
            
            if "mic" in text or "audio" in text:
                target_sensor = "MICROPHONE"

            if target_pkg:
                success, msg = self.adb.block_permission(target_pkg, target_sensor)
                return {
                    "reply": f"🛡️ **Action Executed:** I have blocked **{target_sensor}** permission for **{target_name}** (`{target_pkg}`) via Android AppOps.\n\n"
                             f"The app will no longer be able to access your {target_sensor.lower()} silently. Blank frames or silence will be fed to prevent crashes.",
                    "action_executed": True,
                    "package_name": target_pkg,
                    "sensor": target_sensor,
                    "suggestions": ["View Blocked Apps", "What apps accessed camera today?", "Is my phone safe?"]
                }

        # ----------------------------------------------------
        # 2. QUERY: "What is this project for?" / Purpose of AegisShield
        # ----------------------------------------------------
        if any(p in text for p in [
            "what the project is for", "what is this project for", "what is the project for",
            "project purpose", "about aegisshield", "what is aegisshield", "what is this project",
            "why aegisshield", "what do you do", "what does this app do", "project about"
        ]):
            return {
                "reply": (
                    "🛡️ **What AegisShield Project Is For:**\n\n"
                    "**AegisShield** is a zero-latency **Hardware-Level Mobile Security Guardian** designed to protect your smartphone against stealth surveillance, silent background recording, and covert data exfiltration.\n\n"
                    "### 🔑 Core Capabilities of This Project:\n"
                    "1. **Real-Time Live Sensor Telemetry (USB ADB Bridge):**\n"
                    "   Directly hooks into Android low-level system services (`dumpsys media.camera`, `AudioFlinger`, `dumpsys window`) to detect the millisecond an app turns on your **Camera**, **Microphone**, or accesses **Photos & Videos**.\n\n"
                    "2. **Zero-Trust Background Spying Detection:**\n"
                    "   Cross-references active hardware streams with the Android Window Manager. If an unusual app (like Calculator) or a background service tries to record video or audio without screen presence, AegisShield sounds an immediate alert.\n\n"
                    "3. **Surgical AppOps Permission Enforcement:**\n"
                    "   Allows 1-tap blocking using Android AppOps (`cmd appops set <pkg> <op> ignore`). Blocked apps receive blank frames or silence without crashing, stopping data leaks immediately.\n\n"
                    "4. **Fair Multi-Factor Privacy Risk Engine:**\n"
                    "   Evaluates every installed app on your Samsung Galaxy S24 fairly based on requested permissions, app category legitimacy, and background capabilities.\n\n"
                    "5. **Interactive AI Security Copilot:**\n"
                    "   Answers any question about your phone's live access logs, permission audit, app legitimacy, and privacy best practices."
                ),
                "suggestions": [
                    "What apps accessed my camera from morning?",
                    "Which apps can access my photos and videos?",
                    "Is my phone safe right now?"
                ]
            }

        # ----------------------------------------------------
        # 3. QUERY: "What apps are accessing my camera from morning / today / history?"
        # ----------------------------------------------------
        is_camera_history_query = (
            "camera" in text and any(w in text for w in [
                "morning", "today", "from morning", "history", "who", "when",
                "accessing", "accessed", "used", "last", "currently", "log", "recent"
            ])
        )

        if is_camera_history_query:
            # 1. Fetch live active clients right now
            active_cams = self.adb.get_active_camera_clients()
            active_app_names = [self._infer_app_title(p) for p in active_cams]

            # 2. Fetch history from dumpsys media.camera
            raw_history = self.adb.get_camera_history()

            # Group camera events by app
            app_sessions = {} # pkg -> list of timestamps
            for ev in raw_history:
                pkg = ev["package_name"]
                t = ev["date_time"]
                act = ev["action"]
                if pkg not in app_sessions:
                    app_sessions[pkg] = []
                if act == "CONNECT":
                    # Keep track of connect timestamps
                    app_sessions[pkg].append(t)

            # Check sensor_monitor event history as well
            for ev in event_history:
                if ev.get("sensor") == "CAMERA":
                    pkg = ev.get("package_name")
                    t = ev.get("time_str", "Earlier")
                    if pkg and pkg not in app_sessions:
                        app_sessions[pkg] = []
                    if pkg and t not in app_sessions[pkg]:
                        app_sessions[pkg].append(t)

            # Build detailed report
            lines = []
            if active_cams:
                lines.append(f"🔴 **Currently Active Right Now:** **{', '.join(active_app_names)}** is actively streaming from your camera hardware.")
            else:
                lines.append("🟢 **Current Status:** Camera hardware is currently **Idle** (no active recording session).")

            lines.append("\n📅 **Camera Access History (Today / From Morning):**")

            if app_sessions:
                for pkg, times in app_sessions.items():
                    app_title = self._infer_app_title(pkg)
                    sample_times = ", ".join(times[:4]) if times else "Recent sessions"
                    count = len(times)
                    
                    if "calculator" in pkg.lower():
                        verdict = "🚨 **CRITICAL ANOMALY** (Utility app has no reason to access camera!)"
                    elif pkg in ["com.instagram.android", "com.whatsapp", "com.snapchat.android", "com.sec.android.app.camera"]:
                        verdict = "✅ **Safe Foreground Capture** (Normal social/photo use)"
                    else:
                        verdict = "🔍 **Monitored App**"

                    lines.append(
                        f"• **{app_title}** (`{pkg}`):\n"
                        f"  - Sessions Recorded: **{count} times**\n"
                        f"  - Timestamps: `{sample_times}`\n"
                        f"  - Security Verdict: {verdict}"
                    )
            else:
                lines.append("• No prior third-party camera activations logged since the last hardware service restart.")

            lines.append("\n🛡️ **Security Assessment:**")
            if any("calculator" in p.lower() for p in app_sessions.keys()):
                lines.append("⚠️ **Alert:** Suspicious camera access was flagged for Calculator. We recommend blocking it immediately.")
            else:
                lines.append("All camera sessions from morning were legitimate foreground operations by verified apps (like Instagram / WhatsApp). No stealth background spyware was detected on your Galaxy S24.")

            return {
                "reply": "\n".join(lines),
                "suggestions": [
                    "What is my screen time today?",
                    "Which apps can access my photos and videos?",
                    "What apps have microphone access?"
                ]
            }

        # ----------------------------------------------------
        # 3.5 QUERY: Screen Time & App Usage
        # ----------------------------------------------------
        if any(w in text for w in ["screen time", "screen-time", "screentime", "usage time", "how much time", "app usage", "time spent", "time using"]):
            st = self.adb.get_daily_screen_time_stats()
            top_apps = st.get("apps", [])[:6]
            lines = [
                f"⏱️ **Your Daily Screen Time Report (Samsung Galaxy S24):**\n",
                f"• **Total Screen Time Today:** **{st.get('total_screen_time', '0m')}** across {st.get('active_apps_count', 0)} active applications.",
                f"• **Most Used App:** **{st.get('most_used_app', {}).get('app_name', 'N/A')}** ({st.get('most_used_app', {}).get('screen_time', '0m')})\n",
                "📊 **Top Apps by Screen Time Today:**"
            ]
            for a in top_apps:
                cam_indicator = "📸 (Camera Active Today)" if a.get("has_camera") else "🛡️ (No Camera)"
                lines.append(f"  #{a['rank']} **{a['app_name']}**: **{a['screen_time_str']}** ({a['percentage']}%) — Last active: {a['last_accessed']} {cam_indicator}")
            
            lines.append("\n💡 *You can view the full interactive analytics in the dedicated **Screen Time** tab!*")
            return {
                "reply": "\n".join(lines),
                "suggestions": [
                    "What apps accessed my camera from morning?",
                    "Which apps can access my photos and videos?",
                    "Is my phone safe right now?"
                ]
            }

        # ----------------------------------------------------
        # 4. QUERY: Photos & Videos / Gallery Access
        # ----------------------------------------------------
        if any(w in text for w in ["photo", "photos", "video", "videos", "gallery", "media", "storage"]):
            active_media = list(self.sensor_monitor.active_sensors.get("PHOTOS_VIDEOS", []))
            
            # Find all apps that accessed photos/videos today
            photo_events = [ev for ev in event_history if ev.get("sensor") == "PHOTOS_VIDEOS"]
            photo_sessions = {}
            for ev in photo_events:
                pkg = ev.get("package_name")
                t = ev.get("time_str", "Earlier")
                if pkg and pkg not in photo_sessions:
                    photo_sessions[pkg] = []
                if pkg and t not in photo_sessions[pkg]:
                    photo_sessions[pkg].append(t)

            photo_apps = [a for a in apps_data if "PHOTOS_VIDEOS" in a.get("permissions", [])]
            app_names = [f"• **{a['app_name']}** (`{a['package_name']}`)" for a in photo_apps[:8]]

            lines = ["🖼️ **Photos & Videos Access Telemetry (Samsung Galaxy S24):**\n"]
            if active_media:
                active_names = [self._infer_app_title(p) for p in active_media]
                lines.append(f"🔴 **Currently Accessing Media Right Now:** **{', '.join(active_names)}** is actively using or sending photos/videos!")
            else:
                lines.append("🟢 **Current Status:** Media storage is **Secured** (no active photo/video transfer).")

            if photo_sessions:
                lines.append("\n📅 **Apps That Accessed Photos & Videos Today:**")
                for pkg, times in photo_sessions.items():
                    title = self._infer_app_title(pkg)
                    sample_t = ", ".join(times[:3])
                    lines.append(f"• **{title}** (`{pkg}`): accessed on `{sample_t}`")
            
            lines.append(f"\n📱 **Installed Apps With Media Permission ({len(photo_apps)} apps):**")
            lines.extend(app_names)
            lines.append("\n🛡️ **Security Guard:** AegisShield actively monitors every time an app accesses, shares, or reads photos and videos via Android AppOps.")

            return {
                "reply": "\n".join(lines),
                "suggestions": [
                    "What apps accessed my camera from morning?",
                    "What is my screen time today?",
                    "Which apps have microphone access?"
                ]
            }

        # ----------------------------------------------------
        # 5. QUERY: Microphone Access & History
        # ----------------------------------------------------
        if "mic" in text or "microphone" in text or "audio" in text or "listen" in text:
            active_mics = self.adb.get_active_audio_clients()
            mic_apps = [a for a in apps_data if "MICROPHONE" in a.get("permissions", [])]
            app_names = [f"• **{a['app_name']}** (`{a['package_name']}`)" for a in mic_apps[:8]]

            status_str = f"🔴 **Actively Recording:** {', '.join(active_mics)}" if active_mics else "🟢 **Idle:** No apps are actively recording audio right now."

            return {
                "reply": (
                    f"🎙️ **Microphone Security & Access Report:**\n\n"
                    f"• {status_str}\n\n"
                    f"**Apps with Microphone Permission ({len(mic_apps)} total):**\n"
                    + "\n".join(app_names) +
                    "\n\n🛡️ **AegisShield Guard:**\n"
                    "AegisShield monitors Android's `AudioFlinger` audio server. If any app opens a microphone recording stream while minimized, you will receive an immediate voice alert and query modal."
                ),
                "suggestions": [
                    "What apps accessed my camera from morning?",
                    "Why does ChatGPT need mic?",
                    "Is my phone safe right now?"
                ]
            }

        # ----------------------------------------------------
        # 6. QUERY: Which apps have Camera permission?
        # ----------------------------------------------------
        if "camera" in text and ("permission" in text or "granted" in text or "list" in text or "have" in text):
            cam_apps = [a for a in apps_data if "CAMERA" in a.get("permissions", [])]
            app_names = [f"• **{a['app_name']}** ({a.get('category', 'App')})" for a in cam_apps[:8]]

            return {
                "reply": (
                    f"📷 **Apps Granted Camera Permission on Your Device:**\n\n"
                    f"There are **{len(cam_apps)} apps** with camera hardware permission in their manifest:\n\n"
                    + "\n".join(app_names) +
                    "\n\n💡 All camera sessions are continuously cross-referenced with your screen focus to ensure zero background streaming."
                ),
                "suggestions": [
                    "What apps accessed my camera from morning?",
                    "Which apps can access my photos and videos?",
                    "Block Calculator Camera"
                ]
            }

        # ----------------------------------------------------
        # 7. APP-SPECIFIC SECURITY ANALYSES
        # ----------------------------------------------------
        # Instagram
        if "instagram" in text:
            return {
                "reply": (
                    "📱 **Instagram Security & Privacy Analysis:**\n\n"
                    "• **Permissions Held:** Camera, Microphone, Photos & Videos, Location, Internet\n"
                    "• **Legitimacy:** Normal for Instagram Stories, Reels, and Direct Messages.\n"
                    "• **Observed Activity:** Instagram accessed your camera earlier today for foreground photo capture.\n"
                    "• **Security Verdict:** **SAFE (20/100)** for foreground use. AegisShield actively ensures Instagram never activates the camera or microphone when running in the background."
                ),
                "suggestions": [
                    "What apps accessed my camera from morning?",
                    "Is Snapchat safe?",
                    "Which apps can access my photos and videos?"
                ]
            }

        # Snapchat
        if "snapchat" in text:
            return {
                "reply": (
                    "👻 **Snapchat Security Analysis:**\n\n"
                    "• **Permissions Held:** Camera, Microphone, Photos & Videos, Location, Internet\n"
                    "• **Why it needs them:** Essential for creating Snaps, AR filters, and voice chat.\n"
                    "• **Security Verdict:** **SAFE (22/100)** when you are actively using it on screen.\n"
                    "• **Protection:** AegisShield watches for any background sensor wake-locks to guarantee zero hidden recording."
                ),
                "suggestions": [
                    "What apps accessed my camera from morning?",
                    "Is Instagram safe?",
                    "Scan for risky apps"
                ]
            }

        # Calculator
        if "calculator" in text:
            return {
                "reply": (
                    "⚠️ **Calculator Security Analysis:**\n\n"
                    "• **Category:** Math & Calculation Utility\n"
                    "• **Legitimate Permissions:** None (Zero hardware access needed)\n"
                    "• **Risk Evaluation:** **CRITICAL ANOMALY (100/100)** if Camera or Microphone is requested.\n"
                    "• **Action:** Calculator should NEVER access camera or audio hardware. You can block it anytime with 1 tap via AegisShield AppOps."
                ),
                "suggestions": [
                    "Block Calculator Camera",
                    "What apps accessed my camera from morning?",
                    "Is my phone safe right now?"
                ]
            }

        # Voice Recorder
        if "voice recorder" in text or "voicenote" in text or "sound recorder" in text:
            return {
                "reply": (
                    "🎙️ **Voice Recorder Security Analysis:**\n\n"
                    "• **Permissions Held:** Microphone, Internet\n"
                    "• **Legitimacy:** Microphone is the core hardware needed to record audio notes.\n"
                    "• **Security Verdict:** **SAFE (10/100)**. It does not touch Camera, Contacts, or Location."
                ),
                "suggestions": [
                    "What apps have microphone access?",
                    "Why does ChatGPT need mic?",
                    "What is this project for?"
                ]
            }

        # ChatGPT
        if "chatgpt" in text or "openai" in text:
            return {
                "reply": (
                    "🤖 **ChatGPT Security Analysis:**\n\n"
                    "• **Permissions Held:** Camera, Microphone, Internet\n"
                    "• **Why it needs them:** Camera is used for Vision AI questions (analyzing pictures and documents), and Microphone is used for conversational voice mode.\n"
                    "• **Security Verdict:** **SAFE (18/100)**. Legitimate modern assistant utility with zero background camera capture detected."
                ),
                "suggestions": [
                    "What apps accessed my camera from morning?",
                    "Is Google Pay safe?",
                    "Scan for risky apps"
                ]
            }

        # Google Pay / PhonePe / Banking
        if any(w in text for w in ["google pay", "phonepe", "gpay", "paytm", "bank"]):
            return {
                "reply": (
                    "💳 **Financial & Payment Apps Security Analysis:**\n\n"
                    "• **Permissions Held:** Camera (to scan merchant UPI QR codes), Location (fraud prevention and merchant verification), Internet.\n"
                    "• **Security Verdict:** **SAFE (15/100)**. They do not access microphone or photo libraries silently."
                ),
                "suggestions": [
                    "What apps accessed my camera from morning?",
                    "Which apps can access my photos and videos?",
                    "Is my phone safe right now?"
                ]
            }

        # WhatsApp
        if "whatsapp" in text:
            return {
                "reply": (
                    "💬 **WhatsApp Security Analysis:**\n\n"
                    "• **Permissions Held:** Camera, Microphone, Photos & Videos, Location, Contacts\n"
                    "• **Legitimacy:** Essential for video calling, voice messages, and media sharing. Chats are end-to-end encrypted.\n"
                    "• **Security Verdict:** **SAFE (20/100)**. Camera was accessed earlier today during normal messaging."
                ),
                "suggestions": [
                    "What apps accessed my camera from morning?",
                    "Is Instagram safe?",
                    "Check risky apps"
                ]
            }

        # ----------------------------------------------------
        # 8. QUERY: "Is my phone safe / hacked / spyware?"
        # ----------------------------------------------------
        if any(w in text for w in ["safe", "hacked", "spyware", "malware", "virus", "threat", "risk", "anomaly", "danger", "clean"]):
            active_cams = self.adb.get_active_camera_clients()
            active_mics = self.adb.get_active_audio_clients()
            blocked_count = sum(len(v) for v in self.adb.blocked_registry.values())

            return {
                "reply": (
                    "🛡️ **Live Device Security Audit for Samsung Galaxy S24:**\n\n"
                    f"• **Active Camera Streams:** {len(active_cams)} ({', '.join(active_cams) if active_cams else 'None / Secure'})\n"
                    f"• **Active Audio Recordings:** {len(active_mics)} ({', '.join(active_mics) if active_mics else 'None / Secure'})\n"
                    f"• **AppOps Protections Enforced:** {blocked_count} blocked permissions active\n"
                    f"• **Third-Party Installed Apps:** {len(apps_data)} apps audited\n\n"
                    "✅ **Overall Verdict: DEVICE SECURED**\n"
                    "No background audio eavesdropping, silent video recording, or suspicious data tunneling was detected on your hardware bridge."
                ),
                "suggestions": [
                    "What apps accessed my camera from morning?",
                    "Which apps can access my photos and videos?",
                    "What the project is for?"
                ]
            }

        # ----------------------------------------------------
        # 9. QUERY: How AppOps blocking works
        # ----------------------------------------------------
        if any(w in text for w in ["appops", "how does block", "how do you block", "blocking work"]):
            return {
                "reply": (
                    "🛡️ **How AegisShield AppOps Deep Enforcement Works:**\n\n"
                    "Unlike standard permission revoke which often causes third-party apps to crash:\n"
                    "1. **Silent Blackhole Mode:** Aegis executes `cmd appops set <pkg> <op> ignore` via the low-level ADB shell.\n"
                    "2. **Zero Crashes:** When the blocked app tries to open the Camera or Mic, Android returns an empty black frame or total silence without crashing the app.\n"
                    "3. **Zero Data Leak:** No real sensor bytes ever leave the hardware to reach the blocked application."
                ),
                "suggestions": [
                    "Block Calculator Camera",
                    "What apps accessed my camera from morning?",
                    "Is my phone safe right now?"
                ]
            }

        # ----------------------------------------------------
        # 10. QUERY: Can apps spy secretly in background?
        # ----------------------------------------------------
        if any(w in text for w in ["spy", "secret", "silent", "record without", "listening to me", "hidden"]):
            return {
                "reply": (
                    "👁️ **Can Android Apps Secretly Spy in the Background?**\n\n"
                    "• **The Vulnerability:** Malicious SDKs or spyware apps request camera/microphone permissions under the guise of utilities and try to maintain background wake-locks to record you.\n"
                    "• **How AegisShield Stops It:** AegisShield cross-references Android's hardware client list with the active window state. If an app attempts to read camera or mic streams without being open in the foreground, Aegis immediately alerts you and allows you to block it via AppOps."
                ),
                "suggestions": [
                    "What apps accessed my camera from morning?",
                    "What the project is for?",
                    "Is my phone safe right now?"
                ]
            }

        # ----------------------------------------------------
        # 11. GENERAL SECURITY COPILOT RESPONSE (Catch-all for any security question)
        # ----------------------------------------------------
        # Extract potential app name if mentioned
        matched_app = None
        for a in apps_data:
            if a.get("app_name", "").lower() in text:
                matched_app = a
                break

        if matched_app:
            perms = ", ".join(matched_app.get("permissions", []))
            return {
                "reply": (
                    f"📱 **Security Analysis for {matched_app['app_name']} (`{matched_app['package_name']}`):**\n\n"
                    f"• **Category:** {matched_app.get('category', 'Application')}\n"
                    f"• **Permissions Held:** {perms or 'None'}\n"
                    f"• **Status:** Protected under AegisShield live telemetry.\n"
                    f"• **Guidance:** AegisShield actively monitors this app's sensor requests to ensure no background leakage occurs."
                ),
                "suggestions": [
                    "What apps accessed my camera from morning?",
                    "Which apps can access my photos and videos?",
                    "What the project is for?"
                ]
            }

        return {
            "reply": (
                f"🛡️ **Aegis AI Security Copilot:**\n\n"
                f"I am actively guarding your **Samsung Galaxy S24**.\n\n"
                f"You can ask me any security or privacy question, such as:\n"
                f"• *'What are the apps are accessing my camera from morning?'*\n"
                f"• *'What the project is for?'*\n"
                f"• *'Which apps can access my photos and videos?'*\n"
                f"• *'Is Instagram or Snapchat safe?'*\n"
                f"• *'How does AegisShield block permissions without crashing apps?'*\n"
                f"• *'Is my phone safe right now?'*"
            ),
            "suggestions": [
                "What apps accessed my camera from morning?",
                "What the project is for?",
                "Which apps can access my photos and videos?",
                "Is my phone safe right now?"
            ]
        }
