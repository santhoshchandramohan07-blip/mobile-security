import re
from datetime import datetime
from adb_manager import ADBManager

adb = ADBManager()
adb.device_serial = 'RZCY82GLPBA'

# 1. Test screen time parser
s, o = adb.run_command(['shell', 'dumpsys', 'usagestats'])
pattern = r'time="([^"]+)"\s+type=(ACTIVITY_RESUMED|ACTIVITY_PAUSED)\s+package=([a-zA-Z0-9_\.]+)'
matches = re.findall(pattern, o)

package_times = {}
package_last_seen = {}
active_resumed = {}

for time_str, event_type, pkg in matches:
    try:
        dt = datetime.strptime(time_str[:19], "%Y-%m-%d %H:%M:%S")
        package_last_seen[pkg] = time_str
        if event_type == "ACTIVITY_RESUMED":
            active_resumed[pkg] = dt
        elif event_type == "ACTIVITY_PAUSED" and pkg in active_resumed:
            dur = (dt - active_resumed[pkg]).total_seconds()
            if 0 < dur < 14400:
                package_times[pkg] = package_times.get(pkg, 0) + dur
            del active_resumed[pkg]
    except Exception:
        pass

total_secs = sum(package_times.values())
total_hrs = int(total_secs // 3600)
total_mins = int((total_secs % 3600) // 60)
print(f"Total Device Screen Time: {total_hrs}h {total_mins}m ({int(total_secs)}s)")
print(f"Total Apps Tracked: {len(package_times)}")

# 2. Test detailed permission breakdown on Instagram
s_p, dump = adb.run_command(['shell', 'dumpsys', 'package', 'com.instagram.android'])
granted = []
denied = []
in_runtime = False

FRIENDLY_PERMS = {
    "android.permission.CAMERA": ("Camera Hardware", "Sensors", True),
    "android.permission.RECORD_AUDIO": ("Microphone / Audio", "Sensors", True),
    "android.permission.READ_MEDIA_IMAGES": ("Photos Gallery", "Media", True),
    "android.permission.READ_MEDIA_VIDEO": ("Videos Gallery", "Media", True),
    "android.permission.READ_MEDIA_AUDIO": ("Music & Audio Files", "Media", False),
    "android.permission.ACCESS_FINE_LOCATION": ("Precise GPS Location", "Location", True),
    "android.permission.ACCESS_COARSE_LOCATION": ("Approximate Location", "Location", True),
    "android.permission.READ_CONTACTS": ("Contacts Book", "Privacy", True),
    "android.permission.WRITE_CONTACTS": ("Modify Contacts", "Privacy", True),
    "android.permission.POST_NOTIFICATIONS": ("Push Notifications", "Alerts", False),
    "android.permission.BLUETOOTH_CONNECT": ("Bluetooth Devices", "Connection", False),
    "android.permission.NEARBY_WIFI_DEVICES": ("Nearby Wi-Fi", "Connection", False),
    "android.permission.READ_EXTERNAL_STORAGE": ("External Storage", "Storage", True),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("Write Storage", "Storage", True),
    "android.permission.CALL_PHONE": ("Make Phone Calls", "Phone", True),
    "android.permission.READ_CALL_LOG": ("Call Logs", "Privacy", True),
    "android.permission.READ_PHONE_STATE": ("Phone State / SIM", "Identity", True),
    "android.permission.READ_CALENDAR": ("Read Calendar", "Calendar", True),
    "android.permission.WRITE_CALENDAR": ("Write Calendar", "Calendar", True)
}

for line in dump.splitlines():
    line_s = line.strip()
    if line_s.startswith("runtime permissions:"):
        in_runtime = True
        continue
    elif line_s.startswith("Queries:") or line_s.startswith("Dexopt state:") or line_s.startswith("User 0:"):
        in_runtime = False
        
    if in_runtime and "android.permission." in line_s:
        perm_part = line_s.split(":")[0].strip()
        info = FRIENDLY_PERMS.get(perm_part, (perm_part.split(".")[-1].replace("_", " ").title(), "General", False))
        item = {
            "permission": perm_part,
            "title": info[0],
            "category": info[1],
            "is_dangerous": info[2]
        }
        if "granted=true" in line_s:
            granted.append(item)
        elif "granted=false" in line_s:
            denied.append(item)

print(f"\nInstagram Granted Permissions: {len(granted)}")
for g in granted[:5]:
    print(f"  [GRANTED] {g['title']} ({g['permission']})")

print(f"\nInstagram Denied/Not Given Permissions: {len(denied)}")
for d in denied[:5]:
    print(f"  [NOT GIVEN] {d['title']} ({d['permission']})")
