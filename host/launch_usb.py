"""
AegisShield USB Auto-Launcher
Monitors the USB connection for the connected Samsung Galaxy S24,
automatically arms reverse port tunnels, and opens AegisShield on the phone.
"""

import sys
import os
import time
import subprocess

from adb_manager import ADBManager

def main():
    print("=" * 60, flush=True)
    print("   AEGISSHIELD USB AUTO-LAUNCHER", flush=True)
    print("   Connecting to Samsung Galaxy S24 via USB Cable...", flush=True)
    print("=" * 60, flush=True)

    adb = ADBManager()
    print(f"[*] Using ADB binary: {adb.adb_path}", flush=True)

    # Loop waiting for USB connection
    print("[*] Waiting for USB Debugging handshake on phone...", flush=True)
    notified_charging = False

    while True:
        connected, msg = adb.check_connection()
        if connected:
            device = adb.device_serial
            print(f"\n[+] SUCCESS! Connected to Samsung Galaxy S24 [{device}]")
            
            # 1. Reverse Port 8080 (Web HUD) and 8765 (WebSocket Telemetry)
            print("[*] Arming USB reverse tunnels...")
            adb.setup_reverse_tunnel(8080)
            adb.setup_reverse_tunnel(8765)
            
            # 2. Automatically launch AegisShield on the phone screen
            print("[*] Sending launch intent to open AegisShield on phone screen...")
            success, out = adb.run_command([
                "shell", "am", "start",
                "-a", "android.intent.action.VIEW",
                "-d", "http://localhost:8080"
            ])
            
            if success:
                print("\n[+] ========================================================", flush=True)
                print("[+] AEGISSHIELD IS NOW OPEN ON YOUR PHONE SCREEN!", flush=True)
                print("[+] Live sensor telemetry, fair risk scores, and AI Copilot active.", flush=True)
                print("[+] ========================================================\n", flush=True)
            else:
                print(f"[!] Launch command output: {out}", flush=True)
            break
        else:
            # Check if Windows sees the Samsung device in Charging mode
            try:
                pnp = subprocess.run(
                    ["powershell", "-Command", "Get-PnpDevice -PresentOnly | Where-Object { $_.FriendlyName -match 'SAMSUNG Mobile USB' } | Select-Object -ExpandProperty FriendlyName"],
                    capture_output=True, text=True, timeout=3
                )
                if "SAMSUNG" in pnp.stdout and not notified_charging:
                    print("\n[!] Phone is plugged in via USB, but is currently in 'Charging only' mode.", flush=True)
                    print("[!] To allow automatic launch:", flush=True)
                    print("    1. Unlock your phone.", flush=True)
                    print("    2. Swipe down from top -> tap 'Charging only' notification -> choose 'Transferring files'.", flush=True)
                    print("    3. Or go to Settings -> Developer options -> turn ON 'USB debugging'.", flush=True)
                    print("    4. Tap 'ALLOW' on the 'Allow USB debugging?' screen.\n", flush=True)
                    notified_charging = True
            except Exception:
                pass

            time.sleep(2)

if __name__ == "__main__":
    main()
