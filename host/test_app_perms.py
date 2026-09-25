from adb_manager import ADBManager

adb = ADBManager()
adb.device_serial = 'RZCY82GLPBA'

s, dump = adb.run_command(['shell', 'dumpsys', 'package', 'com.instagram.android'])

print("=== PARSING PERMISSIONS FOR INSTAGRAM ===")
# Look for requested permissions and runtime permissions
requested = []
granted = []
denied = []

# Section: requested permissions:
in_requested = False
in_runtime = False

for line in dump.splitlines():
    line_s = line.strip()
    if line_s.startswith("requested permissions:"):
        in_requested = True
        in_runtime = False
        continue
    elif line_s.startswith("install permissions:") or line_s.startswith("runtime permissions:"):
        in_requested = False
        in_runtime = True
        continue
    elif line_s.startswith("Queries:") or line_s.startswith("Dexopt state:") or line_s.startswith("User 0:"):
        in_requested = False
        
    if in_requested and line_s.startswith("android.permission."):
        perm = line_s.split(":")[0].strip()
        requested.append(perm)
        
    if in_runtime and "android.permission." in line_s:
        # e.g. "android.permission.CAMERA: granted=true" or "granted=false"
        perm_part = line_s.split(":")[0].strip()
        if "granted=true" in line_s:
            granted.append(perm_part)
        elif "granted=false" in line_s:
            denied.append(perm_part)

print(f"Total Requested: {len(requested)}")
print(f"Granted: {len(granted)} -> {granted[:8]}")
print(f"Denied / Not Given: {len(denied)} -> {denied[:8]}")
