from functools import lru_cache
from pathlib import Path
import pickle
import sys
import warnings

import numpy as np
from sklearn.tree import _tree

import featureExtraction

warnings.filterwarnings(
    "ignore",
    message=r"Trying to unpickle estimator .* from version .*",
)

MODEL_PATH = Path(__file__).with_name("RandomForestModel.sav")


def _load_compatible_model():
    """
    Load the old Random Forest model safely with compatibility fixes
    for newer scikit-learn versions.
    """
    import sklearn.ensemble._forest as forest
    import sklearn.tree._classes as tree_classes

    # Old pickles may refer to modules that were renamed in newer sklearn.
    sys.modules["sklearn.ensemble.forest"] = forest
    sys.modules["sklearn.tree.tree"] = tree_classes

    class CompatibleTree(_tree.Tree):
        def __setstate__(self, state):
            nodes = state.get("nodes") if isinstance(state, dict) else None

            # Old sklearn tree dtype does not contain this field.
            if nodes is not None and "missing_go_to_left" not in nodes.dtype.names:
                converted = np.zeros(nodes.shape, dtype=_tree.NODE_DTYPE)
                for name in nodes.dtype.names:
                    converted[name] = nodes[name]

                state = dict(state)
                state["nodes"] = converted

            return super().__setstate__(state)

    class CompatibleUnpickler(pickle.Unpickler):
        def find_class(self, module, name):
            if module == "sklearn.tree._tree" and name == "Tree":
                return CompatibleTree
            return super().find_class(module, name)

    if not MODEL_PATH.exists():
        raise FileNotFoundError("RandomForestModel.sav was not found.")

    with MODEL_PATH.open("rb") as model_file:
        model = CompatibleUnpickler(model_file).load()

    # Random Forest API changed from base_estimator to estimator.
    if not hasattr(model, "estimator") and hasattr(model, "base_estimator"):
        model.estimator = model.base_estimator

    # Newer sklearn tree validation expects this attribute.
    for estimator in getattr(model, "estimators_", []):
        if not hasattr(estimator, "monotonic_cst"):
            estimator.monotonic_cst = None

    return model


@lru_cache(maxsize=1)
def get_model():
    return _load_compatible_model()


def _normalize_url(url: str) -> str:
    url = url.strip()

    if not url:
        raise ValueError("Please enter a URL.")

    if "://" not in url:
        url = "https://" + url

    parsed = featureExtraction.urlparse(url)

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.netloc:
        raise ValueError("Please enter a valid website URL.")

    return url


def _model_vote_score(features):
    """
    The saved model is binary:
        0 = legitimate
        1 = phishing

    We convert the percentage of trees voting for phishing into a
    0-100 model score. This allows the UI to show:
        Safe / Suspicious / Risky
    without changing the saved trained model.
    """
    model = get_model()
    matrix = features.to_numpy(dtype=float)

    votes = []
    for estimator in model.estimators_:
        vote = int(estimator.predict(matrix)[0])
        votes.append(vote)

    if not votes:
        prediction = int(model.predict(matrix)[0])
        score = 100 if prediction else 0
    else:
        score = round((sum(votes) / len(votes)) * 100)

    return score


def _category(score):
    if score >= 70:
        return "Risky", "High-risk URL patterns detected."
    if score >= 40:
        return "Suspicious", "Some suspicious URL patterns were detected."
    return "Safe", "The trained model detected few phishing-like signals."


def analyze_url(url):
    normalized = _normalize_url(url)
    features = featureExtraction.getAttributess(normalized)

    score = _model_vote_score(features)
    label, message = _category(score)

    feature_values = {
        name: int(value)
        for name, value in features.iloc[0].to_dict().items()
    }

    return {
        "url": normalized,
        "label": label,
        "score": score,
        "confidence": max(score, 100 - score),
        "message": message,
        "features": feature_values,
    }
