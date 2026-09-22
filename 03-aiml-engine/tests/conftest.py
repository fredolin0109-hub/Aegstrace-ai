"""
AEGISTRACE 03-AIML-ENGINE Test Fixtures and Shared Configuration.
"""

import sys
from pathlib import Path
import pytest

# Ensure 03-aiml-engine and its src are on sys.path
TESTS_DIR = Path(__file__).resolve().parent
ENGINE_DIR = TESTS_DIR.parent
SRC_DIR = ENGINE_DIR / "src"

for path in [str(SRC_DIR), str(ENGINE_DIR)]:
    if path not in sys.path:
        sys.path.insert(0, path)


@pytest.fixture
def sample_urls():
    """Provides representative URLs across benign, suspicious, and phishing categories."""
    return {
        "benign": [
            "https://www.google.com",
            "https://github.com/torvalds/linux",
            "https://scikit-learn.org/stable/modules/ensemble.html",
            "https://en.wikipedia.org/wiki/Phishing",
            "http://example.com/index.html",
        ],
        "suspicious": [
            "http://sub1.sub2.sub3.login-account-update.xyz/verify",
            "http://update-billing-info.stream/checkpoint?dest=http://portal.com",
            "http://security-paypal-alert.online/confirm",
        ],
        "phishing": [
            "http://192.168.1.100/login-paypal-verify.php?auth=true",
            "http://user:secret@10.0.0.1/admin//login",
            "http://metamask-recovery-seed-wallet.cf/validate?token=89437298472",
            "http://appleid-security-verification.buzz/account/login.php",
        ],
        "edge_cases": [
            "",
            "   ",
            "http://",
            "localhost",
            "127.0.0.1",
            "http://[::1]:8080/test",
            "https://a.b.c.d.e.f.g.h.example.com",
            "https://domain.com/" + "a" * 300,
        ],
    }


@pytest.fixture
def sample_features():
    """Provides sample pre-extracted feature dictionary."""
    from feature_extraction import extract_features
    return extract_features("http://192.168.1.50/login-paypal-verify.php?auth=true")
