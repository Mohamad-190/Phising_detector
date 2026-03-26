from spf_check import check_spf
from dkim_check import check_dkim
from dmarc_check import check_dmarc

# Test 1: Alles okay
headers_legit = [
    {"name": "From", "value": "support@google.com"},
    {"name": "Return-Path", "value": "<support@google.com>"},
    {"name": "Received", "value": "from mail.google.com [142.250.74.27] by mx.gmail.com"},
    {"name": "DKIM-Signature", "value": "v=1; a=rsa-sha256; d=google.com; s=20230601;"},
]

# Test 2: SPF fail – Server passt nicht zur Domain
headers_spf_fail = [
    {"name": "From", "value": "support@paypal.com"},
    {"name": "Return-Path", "value": "<hacker@evil-server.com>"},
    {"name": "Received", "value": "from evil-server.com [185.234.72.99] by mx.gmail.com"},
    {"name": "DKIM-Signature", "value": "v=1; a=rsa-sha256; d=evil-server.com; s=default;"},
]

# Test 3: DMARC fail – From stimmt nicht mit SPF/DKIM überein
headers_dmarc_fail = [
    {"name": "From", "value": "support@paypal.com"},
    {"name": "Return-Path", "value": "<newsletter@marketing-tool.com>"},
    {"name": "Received", "value": "from marketing-tool.com [91.200.12.55] by mx.gmail.com"},
    {"name": "DKIM-Signature", "value": "v=1; a=rsa-sha256; d=marketing-tool.com; s=default;"},
]

print("=== Test 1: Legit ===")
spf_r, spf_e = check_spf(headers_legit)
print(f"SPF: {spf_r} – {spf_e}")

print("\n=== Test 2: SPF Fail ===")
spf_r, spf_e = check_spf(headers_spf_fail)
print(f"SPF: {spf_r} – {spf_e}")

print("\n=== Test 3: DMARC Fail ===")
spf_r, spf_e = check_spf(headers_dmarc_fail)
dkim_r = "pass"  # simuliert
dmarc_r, dmarc_e = check_dmarc(headers_dmarc_fail, spf_r, dkim_r)
print(f"DMARC: {dmarc_r} – {dmarc_e}")