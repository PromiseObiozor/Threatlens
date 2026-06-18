import joblib
from pathlib import Path

MODEL_PATH = Path(__file__).resolve().parent / "models" / "threatlens_baseline_model.joblib"
model = joblib.load(MODEL_PATH)

def predict_ml_score(subject: str, body: str) -> dict:
    text = f"{subject or ''} {body or ''}"

    probability = model.predict_proba([text])[0][1]
    ml_score = round(probability * 100)

    return {
        "ml_score": ml_score,
        "ml_probability": round(probability, 4)
    }
