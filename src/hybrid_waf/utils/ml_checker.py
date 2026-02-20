import os
import logging

logger = logging.getLogger(__name__)

MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'ml_model.pkl')

_ml_model = None
_load_attempted = False


def _load_model():
    global _ml_model, _load_attempted
    if _load_attempted:
        return _ml_model
    _load_attempted = True
    try:
        import joblib
        _ml_model = joblib.load(MODEL_PATH)
        logger.info("ML model loaded from %s", MODEL_PATH)
    except FileNotFoundError:
        logger.warning("[WAFinity] Warning: ML model not loaded — file not found at %s", MODEL_PATH)
    except Exception as exc:
        logger.error("Failed to load ML model: %s", exc)
    return _ml_model


def check_ml_prediction(features: list) -> int:
    """
    Run the ML model on extracted features.

    Returns
    -------
    1  – predicted malicious
    0  – predicted valid
    -1 – model unavailable
    """
    model = _load_model()
    if model is None:
        return -1

    try:
        # Gracefully handle feature count mismatches (model may expect 8, we now send 10)
        expected = getattr(model, 'n_features_in_', None)
        if expected is not None and len(features) != expected:
            features = (features + [0.0] * expected)[:expected]

        return int(model.predict([features])[0])
    except Exception as exc:
        logger.error("ML prediction error: %s", exc)
        return -1