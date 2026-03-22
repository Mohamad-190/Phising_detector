import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os

print("Lade Daten...")
df = pd.read_csv("./data/phishing_emails.csv")       

print(f"→ {len(df)} E-Mails geladen")
print(f"→ Phishing:  {df['label'].sum()}")
print(f"→ Legitim:   {(df['label'] == 0).sum()}")

df["subject"] = df["subject"].fillna("")
df["body"] = df["body"].fillna("")
df["sender"] = df["sender"].fillna("")
df["urls"] = df["urls"].fillna("")

df["text"] = (
    df["subject"].astype(str) + " " +
    df["body"].astype(str) + " " +
    df["sender"].astype(str) + " " +
    df["urls"].astype(str)
)

X = df["text"]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)
print(f"→ {len(X_train)} Mails zum Trainieren")
print(f"→ {len(X_test)} Mails zum Testen")

pipeline = Pipeline([
    ("tfidf", TfidfVectorizer(
        max_features=10000,
        ngram_range=(1, 2),
        sublinear_tf=True
    )),
    ("modell", RandomForestClassifier(
        n_estimators=100,
        random_state=42
    ))
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