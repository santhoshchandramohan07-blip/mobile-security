from adb_manager import ADBManager

adb = ADBManager()
adb.check_connection()

print("=== LOGCAT AROUND 11:17:29 (ModalActivity) ===")
ok, out = adb.run_command(['shell', 'logcat -d -t "09-25 11:17:20.000"'])
if ok and out:
    lines = [l.strip() for l in out.splitlines() if any(k in l for k in ['ModalActivity', 'instagram', 'gallery', 'photo', 'media', 'picker', 'send', 'Image', 'Video', 'ContentResolver']) and not 'Aegis' in l]
    print(f"Total matching lines: {len(lines)}")
    for l in lines[:40]:
        print(" ", l)
