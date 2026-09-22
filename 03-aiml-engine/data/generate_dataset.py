"""
AEGISTRACE 03-AIML-ENGINE
Representative Benchmark Dataset Generator.
Generates a deterministic, reproducible dataset of labeled URLs for phishing detection:
- Safe / Legitimate URLs
- Suspicious / Greyware URLs
- High-Risk Phishing / Credential Theft URLs
"""

import csv
import random
from collections import Counter
from pathlib import Path

random.seed(42)

DATA_DIR = Path(__file__).resolve().parent
OUTPUT_CSV = DATA_DIR / "urls_dataset.csv"

# 1. Base benign domains and paths
BENIGN_DOMAINS = [
    "google.com", "microsoft.com", "apple.com", "amazon.com", "github.com",
    "wikipedia.org", "cloudflare.com", "mozilla.org", "python.org", "stackoverflow.com",
    "reddit.com", "linkedin.com", "netflix.com", "spotify.com", "nytimes.com",
    "cnn.com", "bbc.com", "reuters.com", "mit.edu", "stanford.edu", "harvard.edu",
    "nih.gov", "nasa.gov", "who.int", "un.org", "adobe.com", "dropbox.com",
    "slack.com", "salesforce.com", "zoom.us", "oracle.com", "ibm.com", "intel.com",
    "cisco.com", "atlassian.com", "docker.com", "gitlab.com", "bitbucket.org",
    "apache.org", "ubuntu.com", "debian.org", "kernel.org", "fastapi.tiangolo.com",
    "pydantic.dev", "sqlalchemy.org", "scikit-learn.org", "pandas.pydata.org",
    "numpy.org", "archive.org", "medium.com", "quora.com", "twitch.tv", "vimeo.com"
]

BENIGN_PATHS = [
    "",
    "/",
    "/about",
    "/contact",
    "/pricing",
    "/docs",
    "/docs/v2/overview",
    "/articles/2026/cybersecurity-best-practices",
    "/search?q=machine+learning+tutorial",
    "/explore/trending",
    "/community/forum/topic/10429",
    "/releases/tag/v2.4.0",
    "/blog/engineering-updates",
    "/help/faq",
    "/policies/privacy",
    "/terms-of-service",
    "/products/enterprise-solutions",
    "/resources/whitepapers/cloud-governance.pdf",
    "/learn/python-basics/module-3",
    "/projects/open-source/contributors",
    "/weather/forecast?city=seattle&days=7",
    "/store/catalog/category?id=8831&sort=popularity",
]

# 2. Suspicious generators
SUSPICIOUS_DOMAINS = [
    "freepages-hosting.net", "dynamic-dns.org", "ngrok-free.app", "duckdns.org",
    "temp-file-share.xyz", "crypto-airdrop-rewards.club", "prize-winner-claim.top",
    "account-verification-service.work", "online-bonus-spins.buzz", "stream-hd-movies.cam",
    "wallet-connect-portal.live", "file-download-fast.rest", "cloud-storage-anon.link",
    "secure-portal-auth0.xyz", "customer-support-desk24.top", "login-portal-center.club",
    "verify-billing-notice.buzz", "network-speed-test.guru", "software-crack-free.pw",
    "vip-deal-exclusive.icu", "bonus-token-claim.site", "urgent-update-notice.top"
]

SUSPICIOUS_SUBDOMAINS = [
    "secure.account.update",
    "auth.user.login.confirm",
    "portal.access.security.verify",
    "banking.online.app.validate",
    "wallet.web3.connect.restore",
    "billing.service.customer.desk",
    "id.apple.security.check",
    "support.microsoft.account.recovery",
    "chase.secure.banking.alert",
    "paypal.account.resolution.center",
]

SUSPICIOUS_PATHS = [
    "/verification/step1",
    "/auth/check-session?token=8471928471",
    "/account/update-details.php",
    "/claim/reward?user_id=99281&promo=spring",
    "/portal/login?return_to=dashboard",
    "/download/setup_installer.exe",
    "/redirect.php?url=https://legitimate-looking.com",
    "/notice/suspended?action=resolve",
    "/support/ticket/review",
    "/webscr?cmd=_flow&dispatch=5885d80a13c0db1f8e263663d3faee8d4",
]

# 3. Phishing lures and targets
PHISHING_BRANDS = [
    "paypal", "chase", "bankofamerica", "wellsfargo", "appleid",
    "microsoft365", "netflix", "amazon", "binance", "coinbase",
    "metamask", "citibank", "usps-delivery", "fedex-tracking", "dhl-parcel"
]

PHISHING_KEYWORDS_COMBOS = [
    "verify-account-security",
    "login-credential-update",
    "billing-suspended-reactivate",
    "recover-restricted-profile",
    "urgent-security-checkpoint",
    "confirm-identity-access",
    "auth-token-validation",
    "password-reset-notice",
    "unusual-activity-warning",
]

PHISHING_TLDS = ["xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "club", "pw", "icu"]

PHISHING_IPS = [
    "185.220.101.5", "194.26.29.112", "45.154.255.88", "192.168.1.100",
    "10.0.0.55", "103.109.102.14", "91.240.118.172", "193.106.191.22",
    "212.192.241.8", "79.137.199.120", "178.159.37.45", "195.123.245.89"
]


def generate_dataset(total_target: int = 1200):
    urls = []
    seen = set()

    def add_url(url: str, label: int, category: str):
        if url not in seen:
            seen.add(url)
            urls.append({
                "url": url,
                "label": label,
                "category": category,
                "source": "synthetic_benchmark"
            })

    # A. Generate Safe / Legitimate URLs (~450)
    for dom in BENIGN_DOMAINS:
        for p in BENIGN_PATHS[:5]:
            scheme = "https" if random.random() > 0.05 else "http"
            u = f"{scheme}://{dom}{p}"
            add_url(u, 0, "SAFE")
            if random.random() > 0.4:
                u_sub = f"{scheme}://www.{dom}{p}"
                add_url(u_sub, 0, "SAFE")

    # Additional varied benign URLs
    for _ in range(150):
        dom = random.choice(BENIGN_DOMAINS)
        sub = random.choice(["blog", "api", "docs", "dev", "status", "support", "community"])
        p = random.choice(BENIGN_PATHS)
        add_url(f"https://{sub}.{dom}{p}", 0, "SAFE")

    # B. Generate Suspicious URLs (~350)
    for _ in range(350):
        dom = random.choice(SUSPICIOUS_DOMAINS)
        sub = random.choice(SUSPICIOUS_SUBDOMAINS) if random.random() > 0.3 else "secure"
        p = random.choice(SUSPICIOUS_PATHS)
        scheme = "http" if random.random() > 0.4 else "https"
        u = f"{scheme}://{sub}.{dom}{p}"
        add_url(u, 1, "SUSPICIOUS")

    # C. Generate Phishing URLs (~400)
    # 1. IP address based phishing
    for _ in range(100):
        ip = random.choice(PHISHING_IPS)
        brand = random.choice(PHISHING_BRANDS)
        combo = random.choice(PHISHING_KEYWORDS_COMBOS)
        port = f":{random.choice([8080, 8443, 8000, 3000])}" if random.random() > 0.7 else ""
        ext = random.choice([".php", ".html", ".cgi", "/index.php", "/login.aspx"])
        u = f"http://{ip}{port}/{brand}/{combo}{ext}?client_id={random.randint(10000, 99999)}"
        add_url(u, 1, "PHISHING")

    # 2. Typosquatting / brand combo domains
    for _ in range(150):
        brand = random.choice(PHISHING_BRANDS)
        combo = random.choice(PHISHING_KEYWORDS_COMBOS)
        tld = random.choice(PHISHING_TLDS)
        p = random.choice([
            f"/login?session={random.randint(100000, 999999)}",
            f"/auth/verify.php?target={brand}",
            "/checkpoint/identity-challenge",
            "/secure-login.html",
            "/signin.php?action=login",
        ])
        scheme = "http" if random.random() > 0.3 else "https"
        u = f"{scheme}://{brand}-{combo}.{tld}{p}"
        add_url(u, 1, "PHISHING")

    # 3. Obfuscation techniques: @ symbols, double slash, redirect tokens, encoded hex
    for _ in range(150):
        brand = random.choice(PHISHING_BRANDS)
        tld = random.choice(PHISHING_TLDS)
        technique = random.choice(["at_symbol", "double_slash", "redirect_token", "hex_encoded"])
        
        if technique == "at_symbol":
            u = f"http://{brand}.com@login-verify-{random.randint(100,999)}.{tld}/account/login.php"
        elif technique == "double_slash":
            u = f"http://update-{brand}.{tld}//auth/login/step1?session_token=a9f8b2c4e1"
        elif technique == "redirect_token":
            u = f"http://secure-gateway.{tld}/redirect.php?url=http://login-{brand}-auth.xyz/confirm"
        else:
            u = f"http://{brand}-security-update.{tld}/%2e%2e/%73%65%63%75%72%65/login?auth=true"
        add_url(u, 1, "PHISHING")

    # Shuffle dataset
    random.shuffle(urls)

    # Save to CSV
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_CSV, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "label", "category", "source"])
        writer.writeheader()
        writer.writerows(urls)

    print(f"Generated {len(urls)} URLs into {OUTPUT_CSV}")
    counts = Counter(row["category"] for row in urls)
    print("Class breakdown:", dict(counts))
    return OUTPUT_CSV


if __name__ == "__main__":
    generate_dataset()
