import os
import joblib
from bs4 import BeautifulSoup
import base64
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import time
import requests
import re
import pandas as pd
import tldextract


print("Lade Modell...")
modell = joblib.load("./models/phishing_model.pkl")
print("Modell geladen")

# Tranco Liste laden
tranco = pd.read_csv("./data/top-1m.csv", names=["rank", "domain"])
bekannte_domains = set(tranco["domain"].tolist())
print("Tranco Liste geladen")

# Freemailer die jeder benutzen kann → neutral behandeln
FREEMAILER = {
    "gmail.com", "outlook.com", "yahoo.com",
    "hotmail.com", "web.de", "gmx.de", "gmx.at",
    "icloud.com", "live.com"
}

def prüfe_domain(url):
    ext = tldextract.extract(url)
    domain = ext.top_domain_under_public_suffix
    if domain in bekannte_domains:
        return True
    else:
        return False

def prüfe_absender(absender):
    match = re.search(r'@([\w\.-]+)', absender)
    if not match:
        return "unbekannt"

    domain = match.group(1).lower()
    ext = tldextract.extract(domain)
    registered_domain = ext.top_domain_under_public_suffix

    if registered_domain in FREEMAILER:
        return "freemailer"

    if registered_domain in bekannte_domains:
        return "vertrauenswürdig"

    return "verdächtig"


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
        maxResults=30
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
        reply_to = next((h["value"] for h in headers if h["name"] == "Reply-To"), "")

        text = extrahiere_text(mail_data["payload"])
        gesamt_text = betreff + " " + absender + " " + text

        ergebnis = modell.predict([gesamt_text])[0]
        wahrscheinlichkeit = modell.predict_proba([gesamt_text])[0][1]
        wahrscheinlichkeit_angepasst = wahrscheinlichkeit

        # Absender prüfen 
        absender_status = prüfe_absender(absender)

        if absender_status == "verdächtig":
            wahrscheinlichkeit_angepasst += 0.20
        
        # Reply-To prüfen 
        if reply_to and reply_to != absender:
            wahrscheinlichkeit_angepasst += 0.30

        # URLs prüfen 
        gefundene_urls = re.findall(r'https?://[^\s]+', gesamt_text)
        domain_score = 0

        for url in gefundene_urls:
            if not prüfe_domain(url):
                domain_score += 1

        if domain_score >= 1:
            wahrscheinlichkeit_angepasst += 0.10
        if domain_score >= 3:
            wahrscheinlichkeit_angepasst += 0.20

        # Maximum bei 100% halten
        wahrscheinlichkeit_angepasst = min(wahrscheinlichkeit_angepasst, 1.0)


        # Vertrauenswürdiger Absender = niemals Phishing
        if absender_status == "vertrauenswürdig":
            print(f" Legitim ({wahrscheinlichkeit_angepasst:.0%}): {betreff}")
            print(f"   Absender Status: {absender_status}")

        # Unbekannter oder verdächtiger Absender = KI entscheidet
        elif ergebnis == 1 or wahrscheinlichkeit_angepasst >= 0.7:
            print(f" PHISHING! ({wahrscheinlichkeit_angepasst:.0%} sicher)")
            print(f"   Von: {absender}")
            print(f"   Betreff: {betreff}")
            print(f"   Absender Status: {absender_status}")

        else:
            print(f"✅ Legitim ({wahrscheinlichkeit_angepasst:.0%}): {betreff}")
            print(f"   Absender Status: {absender_status}")


service = verbinde_gmail()
print("Mit Gmail erfolgreich verbunden")

print("KI läuft prüfe alle 60 Sekunden...")
while True:
    prüfe_mails(service, modell)
    time.sleep(60)