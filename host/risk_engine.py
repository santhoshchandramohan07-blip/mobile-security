"""
AegisShield Mobile Security - Risk & Anomaly Scoring Engine
Evaluates real-time sensor usage and permission requests to detect spyware-like behavior.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

class AppCategory:
    CALCULATOR = "CALCULATOR"        # Math Calculator - NEVER needs Camera/Mic
    AUDIO_RECORDER = "AUDIO_RECORDER"# Voice Recorder - NEEDS Microphone!
    FINANCE = "FINANCE"              # Google Pay, PhonePe - Needs Camera (QR), Location
    AI_ASSISTANT = "AI_ASSISTANT"    # ChatGPT - Needs Camera (Vision), Mic (Voice)
    UTILITY = "UTILITY"              # General Tools, Flashlight, Clock, Notes
    MEDIA_CAMERA = "MEDIA_CAMERA"    # Camera apps, Photo Editors, Scanner apps
    COMMUNICATION = "COMMUNICATION"  # WhatsApp, Telegram, Phone, Dialer, SMS
    SOCIAL = "SOCIAL"                # Snapchat, Instagram, Facebook
    BROWSER = "BROWSER"              # Chrome, Firefox
    NAVIGATION = "NAVIGATION"        # Google Maps, Waze, Delivery (Swiggy, Zomato)
    ENTERTAINMENT = "ENTERTAINMENT"  # Spotify, Netflix, YouTube
    GAME = "GAME"                    # Mobile games
    SYSTEM = "SYSTEM"                # Android OS, Google Play Services
    UNKNOWN = "UNKNOWN"

class SensorType:
    CAMERA = "CAMERA"
    MICROPHONE = "MICROPHONE"
    LOCATION = "LOCATION"
    PHOTOS_VIDEOS = "PHOTOS_VIDEOS"
    BACKGROUND_DATA = "BACKGROUND_DATA"
    CONTACTS = "CONTACTS"
    SMS = "SMS"

class RiskLevel:
    SAFE = "SAFE"             # 0 - 29 (Green)
    LOW = "LOW"               # 30 - 54 (Cyan/Blue)
    SUSPICIOUS = "SUSPICIOUS" # 55 - 74 (Amber/Orange)
    CRITICAL = "CRITICAL"     # 75 - 100 (Red)

@dataclass
class RiskEvaluation:
    package_name: str
    app_name: str
    category: str
    sensor: str
    is_background: bool
    risk_score: int
    risk_level: str
    reasons: List[str]
    recommend_block: bool
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class RiskEngine:
    def __init__(self):
        self.category_keywords = {
            AppCategory.CALCULATOR: ["calculator", "calc", "popupcalculator"],
            AppCategory.AUDIO_RECORDER: ["voicenote", "soundrecorder", "recorder", "dictaphone"],
            AppCategory.FINANCE: ["paisa", "pay", "phonepe", "paytm", "gpay", "bhim", "banking", "wallet"],
            AppCategory.AI_ASSISTANT: ["chatgpt", "openai", "copilot", "gemini", "claude", "assistant"],
            AppCategory.MEDIA_CAMERA: ["camera", "gallery", "photo", "scanner", "picsart", "camscanner", "lens"],
            AppCategory.SOCIAL: ["snapchat", "instagram", "facebook", "twitter", "tiktok", "threads"],
            AppCategory.COMMUNICATION: ["whatsapp", "telegram", "signal", "messenger", "dialer", "phone", "discord", "meet", "zoom"],
            AppCategory.NAVIGATION: ["maps", "navigation", "waze", "gps", "transit", "swiggy", "zomato"],
            AppCategory.BROWSER: ["chrome", "firefox", "browser", "opera", "edge", "brave"],
            AppCategory.ENTERTAINMENT: ["spotify", "music", "netflix", "youtube", "primevideo"],
            AppCategory.UTILITY: ["flashlight", "torch", "clock", "alarm", "compass", "notes", "notepad", "cleaner", "booster"],
            AppCategory.SYSTEM: ["com.google.android.gms", "com.google.android.gsf", "system_server"]
        }

        self.known_apps = {
            "com.sec.android.app.voicenote": ("Voice Recorder", AppCategory.AUDIO_RECORDER),
            "com.openai.chatgpt": ("ChatGPT", AppCategory.AI_ASSISTANT),
            "com.google.android.apps.nbu.paisa.user": ("Google Pay", AppCategory.FINANCE),
            "com.phonepe.app": ("PhonePe", AppCategory.FINANCE),
            "com.snapchat.android": ("Snapchat", AppCategory.SOCIAL),
            "com.instagram.android": ("Instagram", AppCategory.SOCIAL),
            "com.whatsapp": ("WhatsApp", AppCategory.COMMUNICATION),
            "com.picsart.studio": ("Picsart Studio", AppCategory.MEDIA_CAMERA),
            "com.google.android.apps.photos": ("Google Photos", AppCategory.MEDIA_CAMERA),
            "com.sec.android.app.popupcalculator": ("Samsung Calculator", AppCategory.CALCULATOR),
            "com.google.android.calculator": ("Calculator", AppCategory.CALCULATOR),
            "com.sec.android.app.camera": ("Samsung Camera", AppCategory.MEDIA_CAMERA),
            "com.sec.android.gallery3d": ("Samsung Gallery", AppCategory.MEDIA_CAMERA),
            "com.lemon.lvoverseas": ("CapCut", AppCategory.MEDIA_CAMERA),
            "com.spotify.music": ("Spotify", AppCategory.ENTERTAINMENT),
            "in.swiggy.android": ("Swiggy", AppCategory.NAVIGATION),
            "com.application.zomato": ("Zomato", AppCategory.NAVIGATION),
            "free.vpn.unblock.proxy.turbovpn": ("Turbo VPN", AppCategory.UTILITY),
        }

    def infer_category(self, package_name: str, app_name: str = "") -> str:
        """Categorize an app based on its package name and human-readable label."""
        if package_name in self.known_apps:
            return self.known_apps[package_name][1]

        combined = f"{package_name} {app_name}".lower()

        # Check system first
        if package_name.startswith("android.") or package_name in ["android", "system"]:
            return AppCategory.SYSTEM

        for category, keywords in self.category_keywords.items():
            for kw in keywords:
                if kw in combined:
                    return category

        return AppCategory.UNKNOWN

    def evaluate_app_permissions(
        self,
        package_name: str,
        app_name: str,
        permissions: List[str]
    ) -> Dict[str, Any]:
        """
        Fair static permission audit for installed apps.
        Scores apps accurately according to their legitimate functional purpose.
        """
        category = self.infer_category(package_name, app_name)
        score = 10
        flags = []

        # 1. Pure Calculators - Zero reason for Camera or Mic
        if category == AppCategory.CALCULATOR:
            if "CAMERA" in permissions:
                score = 95
                flags.append("CRITICAL: Math calculator has NO need for Camera hardware")
            if "MICROPHONE" in permissions:
                score = 95
                flags.append("CRITICAL: Math calculator has NO need for Audio Recording")
            if score == 10:
                score = 5
                flags.append("Safe utility without sensor access")

        # 2. Audio Voice Recorders - Microphone is core functionality!
        elif category == AppCategory.AUDIO_RECORDER:
            score = 10
            flags.append("Microphone is the primary core purpose of voice recording")
            if "CAMERA" in permissions:
                score += 35
                flags.append("Unexpected Camera permission for an audio recorder")

        # 3. Finance & Payments (Google Pay, PhonePe)
        elif category == AppCategory.FINANCE:
            score = 15
            flags.append("Camera used for QR payments; Location for UPI fraud prevention")
            if "MICROPHONE" in permissions:
                score += 15

        # 4. AI Assistants (ChatGPT)
        elif category == AppCategory.AI_ASSISTANT:
            score = 18
            flags.append("Camera used for Vision analysis; Mic for voice conversations")

        # 5. Media, Camera & Photo Editors (Picsart, Google Photos, Camera)
        elif category == AppCategory.MEDIA_CAMERA:
            score = 15
            flags.append("Legitimate photo capture & gallery media access")

        # 6. Social & Communication (Snapchat, Instagram, WhatsApp)
        elif category in [AppCategory.SOCIAL, AppCategory.COMMUNICATION]:
            score = 22
            flags.append("Standard social multimedia permissions for snaps, stories & calls")

        # 7. Navigation & Food Delivery (Google Maps, Swiggy)
        elif category == AppCategory.NAVIGATION:
            score = 12
            flags.append("Location required for navigation & delivery tracking")

        # 8. Music & Streaming (Spotify)
        elif category == AppCategory.ENTERTAINMENT:
            score = 12
            flags.append("Audio playback & voice search")

        # 9. Generic Utility (Flashlights, Cleaners)
        elif category == AppCategory.UTILITY:
            if "MICROPHONE" in permissions or "CAMERA" in permissions:
                score = 85
                flags.append("High risk: General tool requesting camera or audio recording")
            elif "LOCATION" in permissions:
                score = 55
                flags.append("Suspicious location tracking by utility tool")
            else:
                score = 10
                flags.append("Normal utility operational permissions")

        # 10. Unknown / Unverified Third Party
        else:
            if "CAMERA" in permissions and "MICROPHONE" in permissions:
                score = 45
                flags.append("Broad sensor access (Camera + Mic) by unverified app")
            elif "CAMERA" in permissions or "MICROPHONE" in permissions:
                score = 35
                flags.append(f"Sensors requested by third-party application")
            else:
                score = 15
                flags.append("Standard third-party permissions")

        # Determine level
        if score >= 75:
            level = RiskLevel.CRITICAL
        elif score >= 50:
            level = RiskLevel.SUSPICIOUS
        elif score >= 25:
            level = RiskLevel.LOW
        else:
            level = RiskLevel.SAFE

        return {
            "risk_score": score,
            "risk_level": level,
            "category": category,
            "flags": flags
        }

    def infer_app_name(self, package_name: str) -> str:
        """Derive readable application name from package identifier."""
        if package_name in self.known_apps:
            return self.known_apps[package_name][0]
        parts = package_name.split(".")
        candidate = parts[-1]
        if candidate in ["app", "android"] and len(parts) > 1:
            candidate = parts[-2]
        return candidate.replace("_", " ").title()

    def evaluate_access(
        self,
        package_name: str,
        sensor: str,
        is_background: bool = False,
        foreground_pkg: Optional[str] = None
    ) -> RiskEvaluation:
        """
        Evaluate real-time sensor access (foreground vs background, legitimacy).
        """
        app_name = self.infer_app_name(package_name)
        category = self.infer_category(package_name, app_name)
        base_score = 15
        reasons = []
        has_internet = True

        # System apps are generally trusted
        if category == AppCategory.SYSTEM:
            base_score = 5
            if is_background and sensor in [SensorType.CAMERA, SensorType.MICROPHONE]:
                base_score += 35
                reasons.append(f"System service accessing {sensor} in background")
            return RiskEvaluation(
                package_name=package_name,
                app_name=app_name,
                category=category,
                sensor=sensor,
                is_background=is_background,
                risk_score=min(base_score, 100),
                risk_level=RiskLevel.SAFE if base_score < 30 else RiskLevel.LOW,
                reasons=reasons or ["Legitimate system-level service access"],
                recommend_block=False,
                description=f"{app_name} is an authorized system service."
            )

        # 1. CATEGORY ANOMALY DETECTION
        if category in [AppCategory.CALCULATOR, AppCategory.UTILITY]:
            if sensor == SensorType.CAMERA:
                base_score += 65
                reasons.append("[ANOMALY] Utility apps (Calculator/Tool) have NO legitimate need for Camera access")
            elif sensor == SensorType.MICROPHONE:
                base_score += 65
                reasons.append("[ANOMALY] Utility apps (Calculator/Tool) have NO legitimate need for Audio Recording")
            elif sensor == SensorType.LOCATION:
                base_score += 45
                reasons.append("[SUSPICIOUS] Unexpected GPS/Location tracking for utility tool")
            elif sensor == SensorType.BACKGROUND_DATA:
                base_score += 35
                reasons.append("[SUSPICIOUS] Utility app transmitting background data to external servers")
            elif sensor == SensorType.PHOTOS_VIDEOS:
                base_score += 55
                reasons.append("[SUSPICIOUS] Utility tool requesting access to personal Photos and Videos library")
            elif sensor in [SensorType.CONTACTS, SensorType.SMS]:
                base_score += 55
                reasons.append(f"[CRITICAL] Suspicious access to private personal data ({sensor})")

        elif category == AppCategory.GAME:
            if sensor == SensorType.CAMERA:
                base_score += 50
                reasons.append("[SUSPICIOUS] Game attempting to activate Camera")
            elif sensor == SensorType.MICROPHONE:
                base_score += 35
                reasons.append("[SUSPICIOUS] Game attempting to activate Microphone")
            elif sensor == SensorType.LOCATION:
                base_score += 25
                reasons.append("Background location polling by game")

        elif category == AppCategory.MEDIA_CAMERA:
            if sensor == SensorType.CAMERA:
                base_score += 5  # Expected
            elif sensor == SensorType.MICROPHONE:
                base_score += 10 # Expected for video recording
            elif sensor in [SensorType.CONTACTS, SensorType.SMS]:
                base_score += 45
                reasons.append("Camera/Photo app requesting Contacts or SMS access")

        elif category == AppCategory.COMMUNICATION:
            if sensor in [SensorType.CAMERA, SensorType.MICROPHONE]:
                base_score += 10 # Expected during call or photo taking
            elif sensor == SensorType.BACKGROUND_DATA:
                base_score += 15

        elif category == AppCategory.UNKNOWN:
            if sensor in [SensorType.CAMERA, SensorType.MICROPHONE]:
                base_score += 50
                reasons.append(f"[ALERT] Unverified third-party app accessing high-risk sensor: {sensor}")
            elif sensor == SensorType.LOCATION:
                base_score += 30
                reasons.append("Unverified third-party app tracking location")

        # 2. BACKGROUND SENSOR ACCESS PENALTY (Critical Spyware indicator)
        if is_background:
            if sensor in [SensorType.CAMERA, SensorType.MICROPHONE]:
                base_score += 35
                reasons.append("[STEALTH] CRITICAL: Sensor accessed silently while app is in BACKGROUND")
            else:
                base_score += 20
                reasons.append("[BACKGROUND] Background telemetry activity detected")

        # 3. EXFILTRATION RISK (Sensor access + Network connectivity)
        if has_internet and sensor in [SensorType.CAMERA, SensorType.MICROPHONE] and base_score >= 50:
            base_score += 10
            reasons.append("[EXFILTRATION] App possesses Full Internet access (data exfiltration potential)")

        # Normalize score
        final_score = max(0, min(100, base_score))

        # Assign Risk Level
        if final_score >= 75:
            risk_level = RiskLevel.CRITICAL
            recommend_block = True
            desc = f"CRITICAL THREAT: {app_name} is performing anomalous {sensor} access! Recommend immediate blocking."
        elif final_score >= 55:
            risk_level = RiskLevel.SUSPICIOUS
            recommend_block = True
            desc = f"SUSPICIOUS BEHAVIOR: {app_name} is using {sensor} outside normal expected scope."
        elif final_score >= 30:
            risk_level = RiskLevel.LOW
            recommend_block = False
            desc = f"Low risk access to {sensor} by {app_name}."
        else:
            risk_level = RiskLevel.SAFE
            recommend_block = False
            desc = f"Normal operational access to {sensor} by {app_name}."

        return RiskEvaluation(
            package_name=package_name,
            app_name=app_name,
            category=category,
            sensor=sensor,
            is_background=is_background,
            risk_score=final_score,
            risk_level=risk_level,
            reasons=reasons or ["Standard behavior consistent with app profile"],
            recommend_block=recommend_block,
            description=desc
        )
