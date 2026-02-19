import os

import joblib

MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'ml_model.pkl')
ml_model = joblib.load(MODEL_PATH)


def check_ml_prediction(features: list) -> int:
    """
    Takes a list of eight features and returns the ML prediction.
    Assumes the model outputs 1 for malicious and 0 for valid.
    """
    prediction = ml_model.predict([features])[0]
    return prediction
