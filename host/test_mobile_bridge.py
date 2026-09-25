"""
Automated end-to-end test simulating the mobile phone connecting to the host daemon,
receiving a sensor anomaly alert (Calculator -> Camera), and sending a BLOCK action.
"""

import asyncio
import json
import websockets
import sys

async def test_end_to_end_flow():
    uri = "ws://127.0.0.1:8765"
    print(f"[*] Connecting simulated Android App to {uri}...")

    try:
        async with websockets.connect(uri, open_timeout=5) as ws:
            # 1. Receive Welcome Packet
            welcome_raw = await asyncio.wait_for(ws.recv(), timeout=5)
            welcome = json.loads(welcome_raw)
            print(f"[+] Phone received Welcome packet: {welcome.get('message')}")
            assert welcome.get("type") == "CONNECTION_ESTABLISHED"

            # 2. Trigger Simulation: Calculator accessing Camera
            print("[*] Simulating threat event: Calculator accessing Camera...")
            trigger_payload = {
                "action": "SIMULATE_ALERT",
                "scenario": "CALCULATOR_CAMERA"
            }
            await ws.send(json.dumps(trigger_payload))

            # 3. Receive SENSOR_ALERT
            alert_raw = await asyncio.wait_for(ws.recv(), timeout=5)
            alert = json.loads(alert_raw)
            print(f"[+] Phone received SENSOR_ALERT:")
            print(f"    - App: {alert.get('app_name')} ({alert.get('package_name')})")
            print(f"    - Sensor: {alert.get('sensor')}")
            print(f"    - Risk Score: {alert.get('risk_score')}/100 ({alert.get('risk_level')})")
            print(f"    - Reasons: {alert.get('reasons')}")
            print(f"    - Recommend Block: {alert.get('recommend_block')}")

            assert alert.get("risk_score", 0) >= 75, "Expected risk score >= 75 for Calculator accessing Camera"
            assert alert.get("risk_level") == "CRITICAL"
            assert alert.get("recommend_block") is True

            # 4. Send BLOCK action from phone
            print("\n[*] Phone user presses 'BLOCK APP IMMEDIATELY'...")
            block_payload = {
                "action": "BLOCK_APP",
                "package_name": alert.get("package_name"),
                "sensor": alert.get("sensor")
            }
            await ws.send(json.dumps(block_payload))

            # 5. Receive BLOCK_RESPONSE
            block_res_raw = await asyncio.wait_for(ws.recv(), timeout=5)
            block_res = json.loads(block_res_raw)
            print(f"[+] Phone received BLOCK_RESPONSE:")
            print(f"    - Status: {block_res.get('status')}")
            print(f"    - Message: {block_res.get('message')}")

            assert block_res.get("type") == "BLOCK_RESPONSE"
            print("\n[SUCCESS] END-TO-END FLOW (Connect -> Detect -> Alert -> Block) VERIFIED SUCCESSFULLY!")

    except Exception as e:
        print(f"[-] Test failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(test_end_to_end_flow())
