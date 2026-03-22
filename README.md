# Phishing Detector

Ein Machine-Learning-basierter Phishing-Detektor, der dein Gmail-Postfach in Echtzeit überwacht und verdächtige E-Mails identifiziert.

## Überblick

Dieses Projekt kombiniert einen trainierten Random-Forest-Klassifikator mit regelbasierten Heuristiken, um Phishing-Versuche zuverlässig zu erkennen. Das System analysiert eingehende E-Mails automatisch und warnt bei verdächtigen Nachrichten.

## Features

- **ML-basierte Erkennung**: TF-IDF Vektorisierung mit Random Forest Classifier
- **Multi-Source Training**: Trainiert auf kombinierten Datensätzen (Reddit, VZ, englische Phishing-Mails)
- **Absender-Analyse**: Prüfung gegen Tranco Top 1M Domains
- **Heuristik-Layer**: Zusätzliche Prüfungen für Reply-To Diskrepanzen und verdächtige URLs
- **Echtzeit-Monitoring**: Automatische Prüfung alle 60 Sekunden
- **Gmail Integration**: Direkte Anbindung über Google API

## Technologie-Stack

| Komponente | Technologie |
|------------|-------------|
| Sprache | Python 3 |
| ML Framework | scikit-learn |
| Text Processing | TF-IDF Vectorizer (n-grams) |
| Klassifikator | Random Forest |
| E-Mail API | Google Gmail API |
| HTML Parsing | BeautifulSoup4 |
| Domain Extraction | tldextract |

## Installation

### 1. Repository klonen

```bash
git clone https://github.com/Mohamad-190/Phising_detector.git
cd Phising_detector
```

### 2. Abhängigkeiten installieren

```bash
pip install pandas scikit-learn joblib beautifulsoup4 google-auth google-auth-oauthlib google-api-python-client tldextract
```

### 3. Gmail API einrichten

1. Gehe zur [Google Cloud Console](https://console.cloud.google.com/)
2. Erstelle ein neues Projekt
3. Aktiviere die Gmail API
4. Erstelle OAuth 2.0 Credentials (Desktop App)
5. Lade `credentials.json` herunter und platziere sie im Projektordner

### 4. Daten vorbereiten

Stelle sicher, dass folgende Dateien im `data/` Ordner vorhanden sind:
- `phishing_emails.csv` – Englische Phishing-Mails mit Spalten `subject`, `body`, `label`
- `reddit.json` – Reddit Phishing-Posts
- `vz.json` – VZ Phishing-Daten
- `top-1m.csv` – Tranco Top 1 Million Domains

## Verwendung

### Modell trainieren

```bash
python train.py
```

Ausgabe:
```
Lade Daten...
→ X E-Mails geladen
→ Phishing: Y
→ Legitim: Z
Training abgeschlossen!
Genauigkeit: XX.XX%
Modell gespeichert!
```

Das trainierte Modell wird unter `./models/phishing_model.pkl` gespeichert.

### Phishing-Detektor starten

```bash
python main.py
```

Bei erstmaligem Start öffnet sich ein Browser-Fenster zur Gmail-Authentifizierung. Danach prüft das System automatisch alle 60 Sekunden deine letzten 30 E-Mails. (Kann man natürlich erhöhen oder verkleinern)

## Funktionsweise

### Erkennungs-Pipeline

```
E-Mail eingehend
       ↓
┌──────────────────────┐
│  Text extrahieren    │  (Betreff + Absender + Body)
└──────────────────────┘
       ↓
┌──────────────────────┐
│  ML-Modell Prediction│  (TF-IDF → Random Forest)
└──────────────────────┘
       ↓
┌──────────────────────┐
│  Heuristik-Anpassung │
│  • Absender-Domain   │  (+20% wenn verdächtig)
│  • Reply-To Check    │  (+30% wenn abweichend)
│  • URL-Prüfung       │  (+10-30% bei unbekannten Domains)
└──────────────────────┘
       ↓
┌──────────────────────┐
│  Finale Bewertung    │  (≥70% → Phishing-Warnung)
└──────────────────────┘
```

### Absender-Klassifizierung

| Status | Beschreibung |
|--------|-------------|
| `vertrauenswürdig` | Domain in Tranco Top 1M |
| `freemailer` | Gmail, Outlook, Yahoo, etc. (neutral) |
| `verdächtig` | Unbekannte Domain |

## Projektstruktur

```
Phising_detector/
├── main.py              # Hauptanwendung (Gmail-Monitoring)
├── train.py             # Modell-Training
├── data/
│   ├── phishing_emails.csv
│   ├── reddit.json
│   ├── vz.json
│   └── top-1m.csv       # Tranco Domain-Liste
├── models/
│   └── phishing_model.pkl
├── credentials.json     # Google OAuth (nicht committen!)
├── token.json           # Auth Token (nicht committen!)
└── README.md
```

## Sicherheitshinweise

⚠️ **Wichtig**: Füge `credentials.json` und `token.json` zu deiner `.gitignore` hinzu, um sensible Daten nicht zu veröffentlichen.
