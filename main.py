import os
import joblib
from bs4 import BeautifulSoup
import base64
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import time
from headerchecks import prüfe_spf
print("Lade Modell...")
modell = joblib.load("./models/phishing_model.pkl")
print("Modell geladen")

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

def verbinde_gmail():
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


def extrahiere_text(payload):
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



def prüfe_mails(service, modell):
    results = service.users().messages().list(
        userId="me",
        labelIds=["INBOX"],
        maxResults=2
    ).execute()

    messages = results.get("messages", [])

    for msg in messages:
        mail_data = service.users().messages().get(
            userId="me",
            id=msg["id"],
            format="full"
        ).execute()

        headers = mail_data["payload"]["headers"]
       
        betreff = next((h["value"] for h in headers if h["name"] == "Subject"), "")
        absender = next((h["value"] for h in headers if h["name"] == "From"), "")

        text = extrahiere_text(mail_data["payload"])
        gesamt_text = betreff + " " + absender + " " + text

        ergebnis = modell.predict([gesamt_text])[0]
        wahrscheinlichkeit = modell.predict_proba([gesamt_text])[0][1]
        wahrscheinlichkeit_angepasst = wahrscheinlichkeit
        
        spf_result, spf_erklärung = prüfe_spf(headers)

        # SPF-Ergebnis beeinflusst die Wahrscheinlichkeit
        if spf_result == "fail":
            print(f"🚨 SPF FAIL – Absender nicht autorisiert: {spf_erklärung}")
            wahrscheinlichkeit_angepasst = min(wahrscheinlichkeit + 0.3, 1.0)
        elif spf_result == "softfail":
            print(f"⚠️ SPF Softfail – verdächtig: {spf_erklärung}")
            wahrscheinlichkeit_angepasst = min(wahrscheinlichkeit + 0.15, 1.0)
        elif spf_result == "pass":
            print(f"✅ SPF Pass")
            wahrscheinlichkeit_angepasst = wahrscheinlichkeit 
        else:
            print(f"ℹ️ SPF: {spf_result} – {spf_erklärung}")
            wahrscheinlichkeit_angepasst = min(wahrscheinlichkeit + 0.1, 1.0)
     
        if wahrscheinlichkeit_angepasst >= 0.5:
            print(f"🚨 Phishing ({wahrscheinlichkeit_angepasst:.0%}): {betreff}")
        else:
            print(f"✅ Legitim ({wahrscheinlichkeit_angepasst:.0%}): {betreff}")


service = verbinde_gmail()
print("Mit Gmail erfolgreich verbunden")

print("KI läuft prüfe alle 60 Sekunden...")
while True:
    prüfe_mails(service, modell)
    time.sleep(60)