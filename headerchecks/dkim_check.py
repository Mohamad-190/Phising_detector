import dkim


def check_dkim(rohe_bytes):
    try:
        ergebnis = dkim.verify(rohe_bytes)  

        if ergebnis:
            return "pass", "DKIM Signatur gültig"
        else:
            return "fail", "DKIM Signatur ungültig"

    except Exception as e:
        return "error", f"DKIM lesen fehlgeschlagen:{str(e)}"   