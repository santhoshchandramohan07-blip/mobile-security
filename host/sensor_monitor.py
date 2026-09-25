"""
AegisShield Mobile Security - Real-Time Sensor Monitor
Monitors Camera, Microphone, and Data access events and triggers risk evaluation.
"""

import asyncio
import time
import logging
from typing import Dict, Set, Callable, Optional, List, Any
from adb_manager import ADBManager
from risk_engine import RiskEngine, SensorType, RiskEvaluation

logger = logging.getLogger("AegisMonitor")

class SensorMonitor:
    def __init__(self, adb: ADBManager, risk_engine: RiskEngine, alert_callback: Callable):
        self.adb = adb
        self.risk_engine = risk_engine
        self.alert_callback = alert_callback
        self.is_running = False
        
        # State tracking: sensor -> set of currently active package names
        self.active_sensors: Dict[str, Set[str]] = {
            SensorType.CAMERA: set(),
            SensorType.MICROPHONE: set(),
            SensorType.LOCATION: set(),
            SensorType.PHOTOS_VIDEOS: set(),
            SensorType.BACKGROUND_DATA: set(),
        }

        # Track last sensor use timestamps & app info (populated from real live phone telemetry)
        self.last_sensor_use: Dict[str, Optional[Dict]] = {}

        # History log of detected live sensor access events
        self.event_history: List[Dict] = []

        # Continuous monitoring timers: sensor -> pkg -> float timestamp
        self.active_since: Dict[str, Dict[str, float]] = {s: {} for s in self.active_sensors}
        self.last_continuous_notif: Dict[str, Dict[str, float]] = {s: {} for s in self.active_sensors}

    async def start_monitoring(self, poll_interval: float = 0.8):
        """Continuous polling loops detecting real-time sensor activation."""
        self.is_running = True
        logger.info("Aegis Sensor Monitoring engine started.")

        await asyncio.gather(
            self._camera_mic_loop(poll_interval),
            self._photos_media_loop(poll_interval=1.5),
            return_exceptions=True
        )

    async def _camera_mic_loop(self, poll_interval: float = 0.8):
        while self.is_running:
            try:
                # 1. Check Camera (non-blocking executor)
                cams = await asyncio.to_thread(self.adb.get_active_camera_clients)
                await self._process_sensor_diff(SensorType.CAMERA, set(cams))

                # 2. Check Microphone (non-blocking executor)
                mics = await asyncio.to_thread(self.adb.get_active_audio_clients)
                await self._process_sensor_diff(SensorType.MICROPHONE, set(mics))

            except Exception as e:
                logger.error(f"Error in camera/mic polling loop: {e}")

            await asyncio.sleep(poll_interval)

    async def _photos_media_loop(self, poll_interval: float = 1.0):
        # Give a short initial settle time
        await asyncio.sleep(1.0)
        while self.is_running:
            try:
                # 3. Check Photos & Videos (apps accessing media within 40 seconds, non-blocking)
                media = await asyncio.to_thread(self.adb.get_active_media_clients, 40)
                await self._process_sensor_diff(SensorType.PHOTOS_VIDEOS, set(media))
            except Exception as e:
                logger.error(f"Error in photos/videos polling loop: {e}")

            await asyncio.sleep(poll_interval)

    async def _process_sensor_diff(self, sensor: str, current_active: Set[str]):
        """Detect transitions when apps start or stop using a sensor."""
        previous_active = self.active_sensors[sensor]

        # Newly activated apps
        newly_started = current_active - previous_active
        for pkg in newly_started:
            is_fg = await asyncio.to_thread(self.adb.is_app_in_foreground, pkg)
            is_bg = not is_fg

            evaluation = self.risk_engine.evaluate_access(
                package_name=pkg,
                sensor=sensor,
                is_background=is_bg
            )

            is_unusual = evaluation.risk_score >= 70
            time_str = time.strftime("%I:%M:%S %p")

            if sensor == SensorType.CAMERA:
                if is_unusual:
                    user_notice = f"⚠️ Warning: Your device detected Camera in an unusual app: {evaluation.app_name} on {time_str}!"
                    speech_text = f"Warning! Your device detected camera in an unusual app: {evaluation.app_name}."
                else:
                    user_notice = f"📷 Your {evaluation.app_name} is accessing your camera on {time_str}."
                    speech_text = f"Your {evaluation.app_name} is accessing your camera on {time_str}."
            elif sensor == SensorType.MICROPHONE:
                if is_unusual:
                    user_notice = f"⚠️ Warning: Your device detected Microphone in an unusual app: {evaluation.app_name} on {time_str}!"
                    speech_text = f"Warning! Your device detected microphone in an unusual app: {evaluation.app_name}."
                else:
                    user_notice = f"🎙️ Your {evaluation.app_name} is accessing your microphone on {time_str}."
                    speech_text = f"Your {evaluation.app_name} is accessing your microphone on {time_str}."
            elif sensor in [SensorType.PHOTOS_VIDEOS, "PHOTOS_VIDEOS"]:
                user_notice = f"🖼️ Your {evaluation.app_name} is accessing your photos & videos on {time_str}."
                speech_text = f"Your {evaluation.app_name} is accessing your photos and videos."
            elif sensor in [SensorType.BACKGROUND_DATA, "BACKGROUND_DATA", "DATA"]:
                user_notice = f"🌐 Your {evaluation.app_name} is accessing background data on {time_str}."
                speech_text = f"Your {evaluation.app_name} is accessing background data."
            else:
                user_notice = f"📍 Your {evaluation.app_name} is accessing location on {time_str}."
                speech_text = f"Your {evaluation.app_name} is accessing location."

            # Update last sensor use record
            self.last_sensor_use[sensor] = {
                "app_name": evaluation.app_name,
                "package_name": pkg,
                "sensor": sensor,
                "timestamp": int(time.time() * 1000),
                "time_str": time_str,
                "is_unusual": is_unusual,
                "user_notice": user_notice,
                "risk_score": evaluation.risk_score
            }

            event = {
                "type": "SENSOR_ALERT",
                "timestamp": int(time.time() * 1000),
                "time_str": time_str,
                "state": "ACTIVE",
                "sensor": sensor,
                "package_name": pkg,
                "app_name": evaluation.app_name,
                "category": evaluation.category,
                "is_background": is_bg,
                "risk_score": evaluation.risk_score,
                "risk_level": evaluation.risk_level,
                "reasons": evaluation.reasons,
                "recommend_block": evaluation.recommend_block,
                "description": evaluation.description,
                "is_unusual": is_unusual,
                "user_notice": user_notice,
                "speech_text": speech_text
            }

            self.event_history.insert(0, event)
            self.event_history.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
            if len(self.event_history) > 200:
                self.event_history.pop()

            logger.warning(
                f"[{sensor}] ACTIVE: {evaluation.app_name} ({pkg}) | "
                f"Risk: {evaluation.risk_score}/100 ({evaluation.risk_level}) | "
                f"Notice: {user_notice}"
            )

            # Trigger alert callback to push to Android app
            await self._invoke_callback(event)

            # Track start time for continuous alerts
            now_sec = time.time()
            if sensor in self.active_since:
                self.active_since[sensor][pkg] = now_sec
                self.last_continuous_notif[sensor][pkg] = now_sec

            # Post instant system heads-up notification popup directly to phone screen (non-blocking)
            try:
                notif_title = f"🚨 {evaluation.app_name}: {sensor} Active!" if is_unusual else f"AegisShield: {evaluation.app_name} ({sensor})"
                await asyncio.to_thread(
                    self.adb.post_phone_notification,
                    notif_title,
                    user_notice,
                    f"aegis_{sensor}"
                )
            except Exception as e:
                logger.debug(f"Failed to post phone notification: {e}")

        # Continuous active apps (remind phone every 20s so user is continuously notified)
        now_sec = time.time()
        for pkg in (current_active & previous_active):
            last_notif = self.last_continuous_notif.get(sensor, {}).get(pkg, 0)
            if now_sec - last_notif >= 20.0:
                if sensor in self.last_continuous_notif:
                    self.last_continuous_notif[sensor][pkg] = now_sec
                app_info = self.last_sensor_use.get(sensor, {})
                app_name = app_info.get("app_name") or pkg.split(".")[-1].capitalize()
                time_str = time.strftime("%I:%M:%S %p")
                reminder_msg = f"Your {app_name} is still actively using {sensor} on {time_str}."
                try:
                    await asyncio.to_thread(
                        self.adb.post_phone_notification,
                        f"🔴 {app_name}: {sensor} Active",
                        reminder_msg,
                        f"aegis_{sensor}"
                    )
                except Exception as e:
                    logger.debug(f"Failed to post reminder notification: {e}")

        # Stopped apps
        stopped = previous_active - current_active
        for pkg in stopped:
            if sensor in self.active_since:
                self.active_since[sensor].pop(pkg, None)
                self.last_continuous_notif[sensor].pop(pkg, None)
            logger.info(f"[{sensor}] RELEASED: {pkg}")
            stopped_event = {
                "type": "SENSOR_STATUS",
                "timestamp": int(time.time() * 1000),
                "state": "RELEASED",
                "sensor": sensor,
                "package_name": pkg
            }
            await self._invoke_callback(stopped_event)

        # Update state
        self.active_sensors[sensor] = current_active

    async def _invoke_callback(self, event: Dict[str, Any]):
        if not self.alert_callback:
            return
        try:
            if asyncio.iscoroutinefunction(self.alert_callback):
                await self.alert_callback(event)
            elif callable(self.alert_callback):
                res = self.alert_callback(event)
                if asyncio.iscoroutine(res):
                    await res
        except Exception as e:
            logger.error(f"Error in alert callback: {e}")

    def stop(self):
        self.is_running = False

    async def trigger_simulated_event(self, package_name: str, sensor: str, is_background: bool = False):
        """Simulate an access event (e.g. Calculator accessing camera) for testing/demo purposes."""
        evaluation = self.risk_engine.evaluate_access(
            package_name=package_name,
            sensor=sensor,
            is_background=is_background
        )

        is_unusual = evaluation.risk_score >= 70
        time_str = time.strftime("%I:%M:%S %p")

        if sensor == SensorType.CAMERA:
            if is_unusual:
                user_notice = f"⚠️ Warning: Your device detected Camera in an unusual app: {evaluation.app_name} on {time_str}!"
                speech_text = f"Warning! Your device detected camera in an unusual app: {evaluation.app_name}."
            else:
                user_notice = f"📷 Your {evaluation.app_name} is accessing your camera on {time_str}."
                speech_text = f"Your {evaluation.app_name} is accessing your camera on {time_str}."
        elif sensor == SensorType.MICROPHONE:
            if is_unusual:
                user_notice = f"⚠️ Warning: Your device detected Microphone in an unusual app: {evaluation.app_name} on {time_str}!"
                speech_text = f"Warning! Your device detected microphone in an unusual app: {evaluation.app_name}."
            else:
                user_notice = f"🎙️ Your {evaluation.app_name} is accessing your microphone on {time_str}."
                speech_text = f"Your {evaluation.app_name} is accessing your microphone on {time_str}."
        elif sensor in [SensorType.PHOTOS_VIDEOS, "PHOTOS_VIDEOS"]:
            user_notice = f"🖼️ Your {evaluation.app_name} is accessing your photos & videos on {time_str}."
            speech_text = f"Your {evaluation.app_name} is accessing your photos and videos."
        elif sensor in [SensorType.BACKGROUND_DATA, "BACKGROUND_DATA", "DATA"]:
            user_notice = f"🌐 Your {evaluation.app_name} is accessing background data on {time_str}."
            speech_text = f"Your {evaluation.app_name} is accessing background data."
        else:
            user_notice = f"📍 Your {evaluation.app_name} is accessing location on {time_str}."
            speech_text = f"Your {evaluation.app_name} is accessing location."

        self.last_sensor_use[sensor] = {
            "app_name": evaluation.app_name,
            "package_name": package_name,
            "sensor": sensor,
            "timestamp": int(time.time() * 1000),
            "time_str": time_str,
            "is_unusual": is_unusual,
            "user_notice": user_notice,
            "risk_score": evaluation.risk_score
        }

        event = {
            "type": "SENSOR_ALERT",
            "timestamp": int(time.time() * 1000),
            "time_str": time_str,
            "state": "ACTIVE",
            "sensor": sensor,
            "package_name": package_name,
            "app_name": evaluation.app_name,
            "category": evaluation.category,
            "is_background": is_background,
            "risk_score": evaluation.risk_score,
            "risk_level": evaluation.risk_level,
            "reasons": evaluation.reasons,
            "recommend_block": evaluation.recommend_block,
            "description": evaluation.description,
            "is_unusual": is_unusual,
            "user_notice": user_notice,
            "speech_text": speech_text
        }

        self.event_history.insert(0, event)
        self.event_history.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
        await self._invoke_callback(event)

        # Post instant system heads-up notification popup directly to phone screen
        try:
            notif_title = f"🚨 {evaluation.app_name}: {sensor} Active!" if is_unusual else f"AegisShield: {evaluation.app_name} ({sensor})"
            self.adb.post_phone_notification(
                title=notif_title,
                message=user_notice,
                tag=f"aegis_{sensor}"
            )
        except Exception as e:
            logger.debug(f"Failed to post phone notification: {e}")

        return event
