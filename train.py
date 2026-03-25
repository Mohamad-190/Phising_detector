import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os
import json
print("Lade Daten...")

def lade_json_datensatz(dateipfad):
    with open(dateipfad, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    rows = []
    for post in data:
        # Überspringen wenn der Schlüssel nicht existiert
        if "text_extraction_and_analysis" not in post:
            continue
        
        # Überspringen wenn extracted_text fehlt
        if "extracted_text" not in post["text_extraction_and_analysis"]:
            continue
            
        text = post["text_extraction_and_analysis"]["extracted_text"]
        
        # Überspringen wenn Text leer ist
        if not text:
            continue
        
        phishing = post["annotation"]["phishing_label"]
        if isinstance(phishing, str):
            label = 1 if phishing.lower() == "true" else 0
        else:
            label = int(phishing)
        
        rows.append({"text": text, "label": label})
    
    return pd.DataFrame(rows)

df_reddit = lade_json_datensatz("./data/reddit.json")
df_vz = lade_json_datensatz("./data/vz.json")

# Alle 3 Datasets kombinieren
df_englisch = pd.read_csv("data/phishing_emails.csv")
df_englisch["text"] = df_englisch["subject"].fillna("").astype(str) + " " + df_englisch["body"].fillna("").astype(str)
df_englisch = df_englisch[["text", "label"]]   
df_kombiniert = pd.concat([df_englisch, df_reddit, df_vz], ignore_index=True)
df_kombiniert.to_csv("data/combined_emails.csv", index=False)

df = pd.read_csv("data/combined_emails.csv")

print(f"→ {len(df)} E-Mails geladen")
print(f"→ Phishing:  {df['label'].sum()}")
print(f"→ Legitim:   {(df['label'] == 0).sum()}")


X = df["text"]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)
print(f"→ {len(X_train)} Mails zum Trainieren")
print(f"→ {len(X_test)} Mails zum Testen")

pipeline = Pipeline([
    ("tfidf", TfidfVectorizer(max_features=20000, ngram_range=(1, 2), sublinear_tf=True)),
    ("modell", LogisticRegression(max_iter=1000, random_state=42))
])

pipeline.fit(X_train, y_train)
print("Training abgeschlossen!")

predictions = pipeline.predict(X_test)
accuracy = accuracy_score(y_test, predictions)

print(f"Genauigkeit: {accuracy:.2%}")
print(classification_report(y_test, predictions,
      target_names=["Legitim", "Phishing"]))

joblib.dump(pipeline, "./models/phishing_model.pkl")
print("Modell gespeichert!")