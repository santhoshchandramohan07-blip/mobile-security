"""
Unit test suite for Aegis Risk Engine.
Validates category-sensor mismatch detection and risk score computation.
"""

from risk_engine import RiskEngine, SensorType, RiskLevel

def test_risk_calculations():
    engine = RiskEngine()

    print("==================================================")
    print("Testing Aegis Risk Engine Anomaly Detection Rules")
    print("==================================================")

    # 1. Calculator accessing Camera (The exact user scenario!)
    calc_cam = engine.evaluate_access(
        package_name="com.google.android.calculator",
        app_name="Calculator",
        sensor=SensorType.CAMERA,
        is_background=False
    )
    print(f"\n[Test 1] Calculator -> Camera:")
    print(f"  Risk Score: {calc_cam.risk_score}/100 ({calc_cam.risk_level})")
    print(f"  Reasons: {calc_cam.reasons}")
    print(f"  Recommend Block: {calc_cam.recommend_block}")
    assert calc_cam.risk_score >= 75, f"Expected Critical Risk >= 75, got {calc_cam.risk_score}"
    assert calc_cam.recommend_block is True

    # 2. Calculator accessing Camera in BACKGROUND
    calc_cam_bg = engine.evaluate_access(
        package_name="com.google.android.calculator",
        app_name="Calculator",
        sensor=SensorType.CAMERA,
        is_background=True
    )
    print(f"\n[Test 2] Calculator -> Camera in BACKGROUND:")
    print(f"  Risk Score: {calc_cam_bg.risk_score}/100 ({calc_cam_bg.risk_level})")
    print(f"  Reasons: {calc_cam_bg.reasons}")
    assert calc_cam_bg.risk_score >= 90, f"Expected Risk >= 90, got {calc_cam_bg.risk_score}"
    assert calc_cam_bg.recommend_block is True

    # 3. Flashlight accessing Microphone
    flash_mic = engine.evaluate_access(
        package_name="com.dev.flashlight.torch",
        app_name="Flashlight",
        sensor=SensorType.MICROPHONE,
        is_background=False
    )
    print(f"\n[Test 3] Flashlight -> Microphone:")
    print(f"  Risk Score: {flash_mic.risk_score}/100 ({flash_mic.risk_level})")
    print(f"  Reasons: {flash_mic.reasons}")
    assert flash_mic.risk_score >= 75
    assert flash_mic.recommend_block is True

    # 4. WhatsApp accessing Camera in Foreground (Normal user action)
    wa_cam_fg = engine.evaluate_access(
        package_name="com.whatsapp",
        app_name="WhatsApp",
        sensor=SensorType.CAMERA,
        is_background=False
    )
    print(f"\n[Test 4] WhatsApp -> Camera in Foreground:")
    print(f"  Risk Score: {wa_cam_fg.risk_score}/100 ({wa_cam_fg.risk_level})")
    assert wa_cam_fg.risk_score <= 30
    assert wa_cam_fg.recommend_block is False

    # 5. WhatsApp accessing Camera in BACKGROUND (Spyware behavior)
    wa_cam_bg = engine.evaluate_access(
        package_name="com.whatsapp",
        app_name="WhatsApp",
        sensor=SensorType.CAMERA,
        is_background=True
    )
    print(f"\n[Test 5] WhatsApp -> Camera in BACKGROUND:")
    print(f"  Risk Score: {wa_cam_bg.risk_score}/100 ({wa_cam_bg.risk_level})")
    assert wa_cam_bg.risk_score >= 55

    print("\n[SUCCESS] ALL RISK ENGINE VALIDATION TESTS PASSED!")

if __name__ == "__main__":
    test_risk_calculations()
