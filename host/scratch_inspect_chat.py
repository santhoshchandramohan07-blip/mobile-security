from adb_manager import ADBManager

adb = ADBManager()
adb.check_connection()

print("=== DUMPSYS ACTIVITY TOP ===")
ok, out = adb.run_command(['shell', 'dumpsys activity top | head -n 45'])
if ok and out:
    for l in out.splitlines():
        print(" ", l.strip())
