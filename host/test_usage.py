import re
from datetime import datetime
from adb_manager import ADBManager

adb = ADBManager()
adb.device_serial = 'RZCY82GLPBA'
s, o = adb.run_command(['shell', 'dumpsys', 'usagestats'])

pattern = r'time="([^"]+)"\s+type=(ACTIVITY_RESUMED|ACTIVITY_PAUSED)\s+package=([a-zA-Z0-9_\.]+)'
matches = re.findall(pattern, o)
print(f"Total Activity Transitions: {len(matches)}")

# Calculate total screen time per package
package_times = {} # pkg -> total seconds
package_last_seen = {} # pkg -> last timestamp
active_resumed = {} # pkg -> resume datetime

for time_str, event_type, pkg in matches:
    try:
        # time format e.g. "2026-09-24 10:41:34"
        dt = datetime.strptime(time_str[:19], "%Y-%m-%d %H:%M:%S")
        package_last_seen[pkg] = time_str
        if event_type == "ACTIVITY_RESUMED":
            active_resumed[pkg] = dt
        elif event_type == "ACTIVITY_PAUSED" and pkg in active_resumed:
            dur = (dt - active_resumed[pkg]).total_seconds()
            if 0 < dur < 14400: # sanity check: less than 4 hours in single session
                package_times[pkg] = package_times.get(pkg, 0) + dur
            del active_resumed[pkg]
    except Exception as e:
        pass

sorted_usage = sorted(package_times.items(), key=lambda x: x[1], reverse=True)
print("\n=== TOP APPS BY SCREEN TIME ===")
for pkg, secs in sorted_usage[:15]:
    mins = int(secs // 60)
    hrs = mins // 60
    rem_mins = mins % 60
    time_display = f"{hrs}h {rem_mins}m" if hrs > 0 else f"{mins}m"
    print(f"{pkg}: {time_display} ({int(secs)}s) - Last seen: {package_last_seen.get(pkg, 'N/A')}")
