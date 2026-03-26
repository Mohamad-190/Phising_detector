import os
import joblib
from bs4 import BeautifulSoup
import base64
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import time
from headerchecks import check_spf, check_dkim, check_dmarc
print("Lade Modell...")
modell = joblib.load("./models/phishing_model.pkl")
print("Modell geladen")

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

def connect_gmail():
    creds = None

    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)

        with open("token.json", "w") as token:
            token.write(creds.to_json())

    service = build("gmail", "v1", credentials=creds)
    return service


def extract_text(payload):
    text = ""

    if "parts" in payload:
        for part in payload["parts"]:
            if part["mimeType"] == "text/plain":
                data = part["body"].get("data", "")
                text += base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")
            elif part["mimeType"] == "text/html":
                data = part["body"].get("data", "")
                html = base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")
                soup = BeautifulSoup(html, "html.parser")
                text += soup.get_text()
    else:
        data = payload["body"].get("data", "")
        text += base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")

    return text



def check_heuristics(headers, text):
    score = 0
    text_lower = text.lower()
    betreff = next((h["value"] for h in headers if h["name"] == "Subject"), "").lower()
    absender = next((h["value"] for h in headers if h["name"] == "From"), "").lower()

    # 1. Dringlichkeit
    urgency_words = ["hurry", "sofort", "immediately", "urgent", "dringend", 
                     "innerhalb", "within", "expire", "suspend"]
    for word in urgency_words:
        if word in text_lower:
            score += 0.1
            break

    # 2. Passwort/Link-Aufforderung
    action_words = ["change your password", "click the link", "verify your account",
                    "confirm your identity", "update your information",
                    "passwort ändern", "konto bestätigen", "link klicken"]
    for phrase in action_words:
        if phrase in text_lower:
            score += 0.15
            break


    return min(score, 1.0)



def check_mails(service, modell):
    results = service.users().messages().list(
        userId="me",
        labelIds=["INBOX"],
        maxResults=20
    ).execute()

    messages = results.get("messages", [])

    for msg in messages:
        #Geparst
        mail_data = service.users().messages().get(
            userId="me",
            id=msg["id"],
            format="full"
        ).execute()

        #Rohe Version für DKIM
        raw_mail = service.users().messages().get(
            userId="me",
            id=msg["id"],
            format="raw"
        ).execute()

        rohe_bytes = base64.urlsafe_b64decode(raw_mail["raw"])


        headers = mail_data["payload"]["headers"]
       
        betreff = next((h["value"] for h in headers if h["name"] == "Subject"), "")
        absender = next((h["value"] for h in headers if h["name"] == "From"), "")

        text = extract_text(mail_data["payload"])
        gesamt_text = betreff + " " + absender + " " + text

        wahrscheinlichkeit = modell.predict_proba([gesamt_text])[0][1]
        wahrscheinlichkeit_angepasst = wahrscheinlichkeit
        
        spf_result, spf_explanation  = check_spf(headers)

        # SPF-Ergebnis beeinflusst die Wahrscheinlichkeit
        if spf_result == "fail":
            print(f"🚨 SPF FAIL – Absender nicht autorisiert: {spf_explanation }")
            wahrscheinlichkeit_angepasst = min(wahrscheinlichkeit + 0.3, 1.0)
        elif spf_result == "softfail":
            print(f"⚠️ SPF Softfail – verdächtig: {spf_explanation }")
            wahrscheinlichkeit_angepasst = min(wahrscheinlichkeit + 0.15, 1.0)
        elif spf_result == "pass":
            print(f"✅ SPF Pass")
           
        else:
            print(f"ℹ️ SPF: {spf_result} – {spf_explanation }")
            wahrscheinlichkeit_angepasst = min(wahrscheinlichkeit + 0.1, 1.0)

        #DKIM
        dkim_result, dkim_explanation = check_dkim(rohe_bytes)
        if dkim_result == "pass":
           print("✅ DKIM pass")
          
        elif dkim_result == "fail":
            print(f"🚨 DKIM fail")
            wahrscheinlichkeit_angepasst = min(wahrscheinlichkeit_angepasst + 0.25, 1.0)
        elif dkim_result == "error":
            print(f" ℹ️DKIM error: {(dkim_explanation)}")
            wahrscheinlichkeit_angepasst = min(wahrscheinlichkeit_angepasst + 0.1, 1.0)

        #DMARC
        dmarc_result, dmarc_explanation = check_dmarc(headers, spf_result, dkim_result)    

        if dmarc_result == "fail":
            print(f"🚨 DMARC fail: {dmarc_explanation}")
            wahrscheinlichkeit_angepasst = min(wahrscheinlichkeit_angepasst + 0.35, 1.0)
        else:
            print("✅ DMARC pass")
           

        # Wenn ALLE drei Header-Checks bestehen → leicht senken
        if spf_result == "pass" and dkim_result == "pass" and dmarc_result == "pass":
            wahrscheinlichkeit_angepasst = max(wahrscheinlichkeit_angepasst - 0.10, 0.0)   

        heuristic_score = check_heuristics(headers, text)
        wahrscheinlichkeit_angepasst = min(wahrscheinlichkeit_angepasst + heuristic_score, 1.0)

        if wahrscheinlichkeit_angepasst >= 0.5:
            print(f"🚨 Phishing ({wahrscheinlichkeit_angepasst:.0%}): {betreff}\n --------------------")
        else:
            print(f"✅ Legitim ({wahrscheinlichkeit_angepasst:.0%}): {betreff}\n --------------------")


service = connect_gmail()
print("Mit Gmail erfolgreich verbunden")

print("KI läuft...")
check_mails(service, modell)
print("Fertig!")