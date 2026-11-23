from app.guards.pii_regex import RegexPIIGuard

guard = RegexPIIGuard()


def test_detects_pan_and_masks():
    v = guard.check("My PAN is ABCDE1234F")
    assert not v.passed
    assert v.modified_text == "My PAN is [PAN]"


def test_detects_aadhaar():
    assert not guard.check("Aadhaar: 2345 6789 0123").passed


def test_clean_text_passes():
    assert guard.check("What is the weather today?").passed