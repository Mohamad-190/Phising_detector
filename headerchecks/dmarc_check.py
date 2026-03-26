import re
import dns.resolver

def extrahiere_domain(email):
    match  = re.search(r'@([\w.-]+)', email)
    if match:
        return match.group(1).lower()
    return None

def get_dmarc_policy(domain):
    try:
        ergebnis = dns.resolver.resolve(f"_dmarc.{domain}", "TXT") #Im DNS nach TXT Record fragen
        for record in ergebnis:
            txt = record.to_text().strip('"')
            if txt.startswith("v=DMARC1"):
                # Policy extrahieren
                if "p=reject" in txt:
                    return "reject"
                elif "p=quarantine" in txt:
                    return "quarantine"
                else:
                    return "none"
    except:
        return None

def check_dmarc(headers, spf_result, dkim_result):
    #From-Domain holen
    from_header = next(
        (h["value"] for h in headers if h["name"].lower() == "from"),
        ""
    )
    from_domain = extrahiere_domain(from_header)

    #ReturnPath Domain holen (für SPF)
    return_path = next(
        (h["value"] for h in headers if h["name"].lower() == "return-path"),
        ""
    )
    return_path_domain = extrahiere_domain(return_path)

    #DKIM Domain holen aus DKIM Signature Header
    dkim_sig = next(
        (h["value"] for h in headers if h["name"].lower() == "dkim-signature"),
        ""
    )
    dkim_domain_match = re.search(r'd=([\w.-]+)', dkim_sig)
    dkim_domain = dkim_domain_match.group(1).lower() if dkim_domain_match else None

    if not from_domain:
        return "none", "From-Domain nicht gefunden"

    #SPF Alignment: FromDomain == ReturnPathDomain?
    spf_aligned = (
        spf_result == "pass" and
        return_path_domain and
        (return_path_domain == from_domain or return_path_domain.endswith(f".{from_domain}"))
    )

    #DKIM Alignment: FromDomain == DKIMDomain?
    dkim_aligned = (
        dkim_result == "pass" and
        dkim_domain and
        (dkim_domain == from_domain or dkim_domain.endswith(f".{from_domain}"))
    )

    #DMARC Policy holen
    policy = get_dmarc_policy(from_domain)

    # Ergebnis
    if spf_aligned or dkim_aligned:
        return "pass", f"DMARC pass (Policy: {policy})"
    else:
        return "fail", f"DMARC fail – From-Domain stimmt nicht überein (Policy: {policy})"
