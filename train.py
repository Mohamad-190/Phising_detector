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

df = pd.read_csv("data/phishing_emails.csv")
df["text"] = df["subject"].fillna("").astype(str) + " " + df["body"].fillna("").astype(str)

print(f"→ {len(df)} E-Mails geladen")
print(f"→ Phishing:  {df['label'].sum()}")
print(f"→ Legitim:   {(df['label'] == 0).sum()}")


X = df["text"]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.1, random_state=42
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

print(f"Genauigkeit: {accuracy:.2%}") #Prozent mit 2 Nachkommastellen
print(classification_report(y_test, predictions,
      target_names=["Legitim", "Phishing"]))

joblib.dump(pipeline, "./models/phishing_model.pkl")
print("Modell gespeichert!")