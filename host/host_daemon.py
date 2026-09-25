"""
AegisShield Mobile Security - Host Guardian Daemon
Runs on laptop, bridges ADB commands, computes risk analytics, serves the Mobile Web HUD,
and streams live telemetry alerts to the Android phone over USB and local network.
"""

import asyncio
import json
import logging
import sys
import os
import socket
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from typing import Set, Dict, Any, Optional

import websockets
from adb_manager import ADBManager
from risk_engine import RiskEngine
from sensor_monitor import SensorMonitor
from chatbot_engine import SecurityChatbotEngine

# Configure Windows console encoding
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("AegisHost")

PORT = 8765
WEB_PORT = 8080
HOST = "0.0.0.0"
WEB_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "web"))

# Global server reference for HTTP REST handler
SERVER_INSTANCE = None

def get_local_ip() -> str:
    """Get LAN IPv4 address for mobile access."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

class QuietHTTPHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def log_message(self, format, *args):
        # Keep console output clean
        pass

    def send_json_response(self, data: Any, code: int = 200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        if self.path.startswith("/api/status"):
            server = SERVER_INSTANCE
            if not server:
                return self.send_json_response({"status": "CONNECTING", "connected": False})
            
            sorted_events = sorted(server.monitor.event_history, key=lambda x: x.get("timestamp", 0), reverse=True)
            resp = {
                "status": "ONLINE",
                "connected": True,
                "device_serial": server.adb.device_serial or "RZCY82GLPBA",
                "device_model": "Samsung Galaxy S24 [RZCY82GLPBA]",
                "usb_connected": bool(server.adb.device_serial),
                "active_protection": True,
                "last_sensor_use": server.monitor.last_sensor_use,
                "recent_events": sorted_events[:50],
                "active_sensors": {k: list(v) for k, v in server.monitor.active_sensors.items()}
            }
            return self.send_json_response(resp)

        elif self.path.startswith("/api/apps"):
            server = SERVER_INSTANCE
            if not server:
                return self.send_json_response({"apps": []})
            
            apps = server.adb.get_installed_third_party_apps()
            audit_results = []
            for app in apps:
                eval_res = server.risk_engine.evaluate_app_permissions(
                    app["package_name"], app["app_name"], app.get("permissions", [])
                )
                audit_results.append({
                    "package_name": app["package_name"],
                    "app_name": app["app_name"],
                    "category": eval_res.get("category", app.get("category", "Application")),
                    "permissions": app.get("permissions", []),
                    "risk_score": eval_res.get("risk_score", 15),
                    "risk_level": eval_res.get("risk_level", "SAFE"),
                    "is_blocked": app.get("is_blocked", False),
                    "flags": eval_res.get("flags", [])[:3]
                })

            audit_results.sort(key=lambda x: x["risk_score"], reverse=True)
            return self.send_json_response({"apps": audit_results})

        elif self.path.startswith("/api/events"):
            server = SERVER_INSTANCE
            events = sorted(server.monitor.event_history, key=lambda x: x.get("timestamp", 0), reverse=True) if server else []
            return self.send_json_response({"events": events})

        elif self.path.startswith("/api/today-events"):
            server = SERVER_INSTANCE
            if not server:
                return self.send_json_response({"events": []})
            # Return ALL events collected today, strictly sorted with newest on top
            events = sorted(server.monitor.event_history, key=lambda x: x.get("timestamp", 0), reverse=True)
            return self.send_json_response({"events": events, "count": len(events)})

        elif self.path.startswith("/api/app-details"):
            server = SERVER_INSTANCE
            if not server:
                return self.send_json_response({"error": "Host daemon not ready"}, code=500)
            
            parsed_url = urlparse(self.path)
            query_params = parse_qs(parsed_url.query)
            pkg = query_params.get("pkg", [""])[0]
            if not pkg:
                return self.send_json_response({"error": "Missing 'pkg' query parameter"}, code=400)
            
            details = server.adb.get_app_permission_breakdown(pkg)
            # Evaluate risk engine for this app
            all_known_perms = [p["permission"].split(".")[-1] for p in details.get("granted_permissions", [])]
            eval_res = server.risk_engine.evaluate_app_permissions(pkg, details.get("app_name", ""), all_known_perms)
            details["risk_score"] = eval_res.get("risk_score", 15)
            details["risk_level"] = eval_res.get("risk_level", "SAFE")
            details["flags"] = eval_res.get("flags", [])
            return self.send_json_response(details)

        elif self.path.startswith("/api/screen-time"):
            server = SERVER_INSTANCE
            if not server:
                return self.send_json_response({"error": "Host daemon not ready"}, code=500)
            
            stats = server.adb.get_daily_screen_time_stats()
            return self.send_json_response(stats)

        elif self.path.startswith("/api/open-notification-settings"):
            server = SERVER_INSTANCE
            if not server:
                return self.send_json_response({"error": "Host daemon not ready"}, code=500)
            server.adb.run_command([
                "shell", "am", "start",
                "-a", "android.settings.CHANNEL_NOTIFICATION_SETTINGS",
                "--es", "android.provider.extra.APP_PACKAGE", "com.android.shell",
                "--es", "android.provider.extra.CHANNEL_ID", "shell_cmd"
            ])
            return self.send_json_response({"status": "SUCCESS", "message": "Opened notification channel settings on phone screen."})

        elif self.path.startswith("/api/test-phone-popup"):
            server = SERVER_INSTANCE
            if not server:
                return self.send_json_response({"error": "Host daemon not ready"}, code=500)
            ok = server.adb.post_phone_notification(
                title="🛡️ AegisShield Live Guard Active",
                message="Instant screen pop-ups are active! You will receive live alerts when apps use Camera, Mic, or Media.",
                tag="aegis_setup"
            )
            return self.send_json_response({"status": "SUCCESS" if ok else "FAILED", "message": "Phone notification posted!"})

        # Static files
        return super().do_GET()

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)
        body = {}
        try:
            body = json.loads(post_data.decode("utf-8")) if post_data else {}
        except Exception:
            pass

        server = SERVER_INSTANCE
        if not server:
            return self.send_json_response({"error": "Host daemon not ready"}, code=500)

        clean_path = self.path.split("?")[0].rstrip("/")
        if clean_path == "/api/chat":
            msg = body.get("message", "")
            logger.info(f"🤖 Chatbot query received: {msg}")
            reply = server.chatbot.process_message(msg)
            return self.send_json_response(reply)

        elif self.path == "/api/block":
            pkg = body.get("package_name")
            sensor = body.get("sensor", "ALL")
            success, msg = server.adb.block_permission(pkg, sensor)
            return self.send_json_response({
                "status": "SUCCESS" if success else "FAILED",
                "message": msg,
                "package_name": pkg,
                "sensor": sensor
            })

        elif self.path == "/api/unblock":
            pkg = body.get("package_name")
            sensor = body.get("sensor", "ALL")
            success, msg = server.adb.unblock_permission(pkg, sensor)
            return self.send_json_response({
                "status": "SUCCESS" if success else "FAILED",
                "message": msg,
                "package_name": pkg,
                "sensor": sensor
            })

        elif self.path == "/api/simulate":
            scenario = body.get("scenario", "SNAPCHAT_CAMERA")
            if server.loop and server.loop.is_running():
                future = asyncio.run_coroutine_threadsafe(server.handle_simulation(scenario), server.loop)
                try:
                    event = future.result(timeout=4)
                    return self.send_json_response({"status": "SUCCESS", "event": event})
                except Exception as e:
                    return self.send_json_response({"status": "ERROR", "error": str(e)}, code=500)
            return self.send_json_response({"status": "ERROR", "message": "Server loop not running"}, code=500)

        elif clean_path == "/api/test-phone-popup":
            ok = server.adb.post_phone_notification(
                title="🛡️ AegisShield Live Guard Active",
                message="Instant screen pop-ups are active! You will receive live alerts when apps use Camera, Mic, or Media.",
                tag="aegis_setup"
            )
            return self.send_json_response({"status": "SUCCESS" if ok else "FAILED", "message": "Phone notification posted!"})

        return self.send_json_response({"error": "Not Found"}, code=404)

def start_http_server():
    """Start static file server and REST API for the mobile web HUD."""
    try:
        httpd = ThreadingHTTPServer((HOST, WEB_PORT), QuietHTTPHandler)
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        logger.info(f"🌐 Mobile Web HUD Server running on http://{HOST}:{WEB_PORT}")
        return True
    except Exception as e:
        logger.error(f"Failed to start HTTP server on {WEB_PORT}: {e}")
        return False

class AegisHostServer:
    def __init__(self):
        global SERVER_INSTANCE
        SERVER_INSTANCE = self
        self.adb = ADBManager()
        self.risk_engine = RiskEngine()
        self.connected_clients: Set[Any] = set()
        self.monitor = SensorMonitor(self.adb, self.risk_engine, self.broadcast_alert)
        self.chatbot = SecurityChatbotEngine(self.adb, self.monitor, self.risk_engine)
        self.loop = None

    async def broadcast_alert(self, event: Dict[str, Any]):
        """Send JSON alert packet to all connected Android phone apps."""
        if not self.connected_clients:
            return

        payload = json.dumps(event)
        await asyncio.gather(
            *[client.send(payload) for client in list(self.connected_clients)],
            return_exceptions=True
        )

    async def poll_device_loop(self):
        """Continuously check for device activation (USB or Wi-Fi) and maintain connection."""
        app_launched_on_phone = False
        while True:
            try:
                connected, msg = await asyncio.to_thread(self.adb.check_connection)
                if connected:
                    if not app_launched_on_phone:
                        logger.info(f"[*] DEVICE CONNECTED & ARMED: {self.adb.device_serial}")
                        is_usb = bool(self.adb.device_serial and ":" not in self.adb.device_serial)
                        if is_usb:
                            logger.info("[*] Arming USB reverse tunnels (ports 8765, 8080)...")
                            await asyncio.to_thread(self.adb.setup_reverse_tunnel, PORT)
                            await asyncio.to_thread(self.adb.setup_reverse_tunnel, WEB_PORT)

                        await self.broadcast_alert({
                            "type": "DEVICE_CONNECTED",
                            "device_serial": self.adb.device_serial,
                            "message": msg
                        })
                        target_url = f"http://localhost:{WEB_PORT}" if is_usb else f"http://{get_local_ip()}:{WEB_PORT}"
                        logger.info(f"[*] Launching AegisShield on phone screen ({target_url})...")
                        await asyncio.to_thread(self.adb.run_command, [
                            "shell", "am", "start",
                            "-a", "android.intent.action.VIEW",
                            "-d", target_url
                        ])
                        app_launched_on_phone = True
                else:
                    app_launched_on_phone = False
            except Exception as e:
                logger.debug(f"Device polling error: {e}")
            await asyncio.sleep(3.0)

    async def handle_client(self, websocket, path=None):
        """Handle incoming WebSocket connection from the Android phone."""
        self.connected_clients.add(websocket)
        client_ip = getattr(websocket, "remote_address", "phone")
        logger.info(f"📱 Phone connected from {client_ip}")

        try:
            # 1. Send Welcome and initial state (non-blocking)
            usage_data = await asyncio.to_thread(self.adb.get_app_usage_stats)
            usage_data["last_sensor_use"] = self.monitor.last_sensor_use

            sorted_events = sorted(self.monitor.event_history, key=lambda x: x.get("timestamp", 0), reverse=True)
            welcome_packet = {
                "type": "CONNECTION_ESTABLISHED",
                "message": "Connected to AegisShield Laptop Host Engine",
                "device_serial": self.adb.device_serial or "USB_DEVICE",
                "active_protection": True,
                "recent_events": sorted_events[:100],
                "last_sensor_use": self.monitor.last_sensor_use,
                "usage_stats": usage_data
            }
            await websocket.send(json.dumps(welcome_packet))

            # 2. Listen for actions from the phone app
            async for raw_msg in websocket:
                try:
                    data = json.loads(raw_msg)
                    action = data.get("action")
                    logger.info(f"📥 Received from phone: {action} -> {data}")

                    if action == "BLOCK_APP":
                        pkg = data.get("package_name")
                        sensor = data.get("sensor", "ALL")
                        success, message = await asyncio.to_thread(self.adb.block_permission, pkg, sensor)
                        response = {
                            "type": "BLOCK_RESPONSE",
                            "status": "SUCCESS" if success else "FAILED",
                            "package_name": pkg,
                            "sensor": sensor,
                            "message": message
                        }
                        await websocket.send(json.dumps(response))

                    elif action == "UNBLOCK_APP":
                        pkg = data.get("package_name")
                        sensor = data.get("sensor", "ALL")
                        success, message = await asyncio.to_thread(self.adb.unblock_permission, pkg, sensor)
                        response = {
                            "type": "UNBLOCK_RESPONSE",
                            "status": "SUCCESS" if success else "FAILED",
                            "package_name": pkg,
                            "sensor": sensor,
                            "message": message
                        }
                        await websocket.send(json.dumps(response))

                    elif action == "REQUEST_USAGE_STATS":
                        usage_data = await asyncio.to_thread(self.adb.get_app_usage_stats)
                        usage_data["last_sensor_use"] = self.monitor.last_sensor_use
                        response = {
                            "type": "USAGE_STATS_REPORT",
                            "data": usage_data
                        }
                        await websocket.send(json.dumps(response))

                    elif action == "REQUEST_AUDIT":
                        # Audit installed packages (non-blocking)
                        apps = await asyncio.to_thread(self.adb.get_installed_third_party_apps)
                        audit_results = []
                        for app in apps:
                            eval_res = self.risk_engine.evaluate_app_permissions(
                                app["package_name"], app["app_name"], app.get("permissions", [])
                            )
                            audit_results.append({
                                "package_name": app["package_name"],
                                "app_name": app["app_name"],
                                "category": eval_res.get("category", app.get("category", "Application")),
                                "permissions": app.get("permissions", []),
                                "risk_score": eval_res.get("risk_score", 15),
                                "risk_level": eval_res.get("risk_level", "SAFE"),
                                "is_blocked": app.get("is_blocked", False),
                                "flags": eval_res.get("flags", [])[:3]
                            })

                        # Sort by risk descending
                        audit_results.sort(key=lambda x: x["risk_score"], reverse=True)
                        response = {
                            "type": "AUDIT_REPORT",
                            "apps": audit_results
                        }
                        await websocket.send(json.dumps(response))

                    elif action == "REQUEST_SCREEN_TIME":
                        screen_stats = await asyncio.to_thread(self.adb.get_daily_screen_time_stats)
                        response = {
                            "type": "SCREEN_TIME_REPORT",
                            "data": screen_stats
                        }
                        await websocket.send(json.dumps(response))

                    elif action == "REQUEST_APP_DETAILS":
                        pkg = data.get("package_name", "")
                        details = await asyncio.to_thread(self.adb.get_app_permission_breakdown, pkg)
                        all_known_perms = [p["permission"].split(".")[-1] for p in details.get("granted_permissions", [])]
                        eval_res = self.risk_engine.evaluate_app_permissions(pkg, details.get("app_name", ""), all_known_perms)
                        details["risk_score"] = eval_res.get("risk_score", 15)
                        details["risk_level"] = eval_res.get("risk_level", "SAFE")
                        details["flags"] = eval_res.get("flags", [])
                        response = {
                            "type": "APP_DETAILS_REPORT",
                            "data": details
                        }
                        await websocket.send(json.dumps(response))

                    elif action == "CHAT_QUERY":
                        msg = data.get("message", "")
                        reply_obj = self.chatbot.process_message(msg)
                        response = {
                            "type": "CHAT_RESPONSE",
                            **reply_obj
                        }
                        await websocket.send(json.dumps(response))

                    elif action == "SIMULATE_ALERT":
                        scenario = data.get("scenario", "SNAPCHAT_CAMERA")
                        await self.handle_simulation(scenario)

                except json.JSONDecodeError:
                    logger.warning("Received invalid JSON from phone")

        except websockets.exceptions.ConnectionClosed:
            logger.info("📱 Phone disconnected")
        finally:
            self.connected_clients.discard(websocket)

    async def handle_simulation(self, scenario: str) -> Dict[str, Any]:
        """Trigger simulated live access event with exact seconds timestamp."""
        if scenario == "SNAPCHAT_CAMERA":
            return await self.monitor.trigger_simulated_event(
                package_name="com.snapchat.android",
                sensor="CAMERA",
                is_background=False
            )
        elif scenario == "CALCULATOR_CAMERA":
            return await self.monitor.trigger_simulated_event(
                package_name="com.sec.android.app.popupcalculator",
                sensor="CAMERA",
                is_background=True
            )
        elif scenario == "PICSART_PHOTOS":
            return await self.monitor.trigger_simulated_event(
                package_name="com.picsart.studio",
                sensor="PHOTOS_VIDEOS",
                is_background=False
            )
        elif scenario == "WHATSAPP_MIC":
            return await self.monitor.trigger_simulated_event(
                package_name="com.whatsapp",
                sensor="MICROPHONE",
                is_background=False
            )
        elif scenario == "INSTAGRAM_DATA":
            return await self.monitor.trigger_simulated_event(
                package_name="com.instagram.android",
                sensor="BACKGROUND_DATA",
                is_background=True
            )
        else:
            return await self.monitor.trigger_simulated_event(
                package_name="com.snapchat.android",
                sensor="CAMERA",
                is_background=False
            )

    async def start(self):
        self.loop = asyncio.get_running_loop()
        local_ip = get_local_ip()

        banner = f"""
====================================================================
    ___    ______ ____  ____ _____    _____ __  ________________    ____ 
   /   |  / ____//  _/ / __// ___/   / ___// / / /  _/ ____/ /   / __ \\
  / /| | / __/   / /  / /_  \\__ \\    \\__ \\/ /_/ // // __/ / /   / / / /
 / ___ |/ /___ _/ /  / __/ ___/ /   ___/ / __  // // /___/ /___/ /_/ / 
/_/  |_/_____//___/ /_/   /____/   /____/_/ /_/___/_____/_____/_____/  
           REAL-TIME MOBILE PERMISSION & SENSOR ANOMALY GUARD        
====================================================================
"""
        print(banner)

        # 1. Start HTTP Server for Phone Web HUD
        start_http_server()

        # 2. Connect ADB
        connected, msg = self.adb.check_connection()
        if connected:
            print(f"[*] ADB Status: \033[92m{msg}\033[0m")
            self.adb.setup_reverse_tunnel(PORT)
            self.adb.setup_reverse_tunnel(WEB_PORT)
        else:
            print(f"[*] ADB Status: \033[93m{msg}\033[0m")
            print("[!] Phone detected via USB. Waiting for USB Debugging authorization...")

        # 3. Start WebSocket Server
        print(f"[*] Starting Aegis WebSocket server on ws://0.0.0.0:{PORT}...")
        server = await websockets.serve(self.handle_client, HOST, PORT)
        print(f"[*] Server listening on ws://0.0.0.0:{PORT}")

        # 4. Pre-seed today's historical sensor events from device
        try:
            logger.info("[*] Loading today's historical sensor events from device...")
            history_events = self.adb.get_today_sensor_history()
            if history_events:
                # Store strictly sorted by timestamp descending (newest first, down to 12:00 AM)
                self.monitor.event_history = sorted(history_events, key=lambda x: x.get("timestamp", 0), reverse=True)

                # Pre-populate last_sensor_use for all sensors including PHOTOS_VIDEOS
                for ev in history_events:
                    sensor = ev.get("sensor")
                    if sensor and sensor not in self.monitor.last_sensor_use:
                        self.monitor.last_sensor_use[sensor] = {
                            "app_name": ev.get("app_name"),
                            "package_name": ev.get("package_name"),
                            "sensor": sensor,
                            "timestamp": ev.get("timestamp"),
                            "time_str": ev.get("time_str"),
                            "is_unusual": ev.get("is_unusual", False),
                            "user_notice": ev.get("user_notice"),
                            "risk_score": ev.get("risk_score", 15)
                        }

                logger.info(f"[*] Seeded {len(history_events)} historical sensor events from today into Live Log.")
            else:
                logger.info("[*] No historical sensor events found from device (will show live events as they happen).")
        except Exception as e:
            logger.warning(f"Could not pre-load historical events: {e}")

        # 5. Start background sensor monitor and device poll loop
        asyncio.create_task(self.monitor.start_monitoring(poll_interval=1.0))
        asyncio.create_task(self.poll_device_loop())

        print("\n" + "=" * 68)
        print("[*] TO VIEW AND RUN ON YOUR PHONE RIGHT NOW:")
        print("-" * 68)
        print("  Option 1: Open Chrome or Samsung Internet on your phone and go to:")
        print(f"      http://{local_ip}:{WEB_PORT}")
        print("  Option 2: (Over USB Cable when USB Debugging is ON):")
        print(f"      http://localhost:{WEB_PORT}")
        print("=" * 68 + "\n")

        print("[+] System Active & Armed!")
        print("    - Real-time sensor anomaly scoring enabled.")
        print("    - Background exfiltration detection active.")
        print("    - Press Ctrl+C to stop.\n")

        await server.wait_closed()

def main():
    server = AegisHostServer()
    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        print("\n[*] Stopping Aegis Host Guardian...")
        server.monitor.stop()

if __name__ == "__main__":
    main()
