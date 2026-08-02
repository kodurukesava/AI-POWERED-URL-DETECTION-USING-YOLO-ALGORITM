from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.metrics import accuracy_score, classification_report, roc_auc_score
from sklearn.model_selection import train_test_split

from ucimlrepo import fetch_ucirepo

from .config import DATASET_PATH, MODEL_PATH
from .features import FEATURE_NAMES


@dataclass(frozen=True)
class ModelBundle:
    model: object
    metrics: dict[str, float]
    feature_names: list[str]


def _load_dataset() -> pd.DataFrame:
    if DATASET_PATH.exists():
        return pd.read_csv(DATASET_PATH)

    dataset = fetch_ucirepo(id=327)
    frame = dataset.data.features.copy()
    frame["result"] = dataset.data.targets["result"].astype(int)
    DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(DATASET_PATH, index=False)
    return frame


def train_model(seed: int = 7) -> ModelBundle:
    frame = _load_dataset()
    x = frame[FEATURE_NAMES].astype(int).to_numpy()
    y = (frame["result"].astype(int) == 1).astype(int).to_numpy()

    x_train, x_test, y_train, y_test = train_test_split(
        x, y, test_size=0.2, random_state=seed, stratify=y
    )

    model = ExtraTreesClassifier(
        n_estimators=500,
        random_state=seed,
        class_weight="balanced",
        max_features="sqrt",
        min_samples_leaf=1,
        n_jobs=-1,
    )
    model.fit(x_train, y_train)

    predictions = model.predict(x_test)
    probabilities = model.predict_proba(x_test)[:, 1]
    metrics = {
        "accuracy": float(accuracy_score(y_test, predictions)),
        "roc_auc": float(roc_auc_score(y_test, probabilities)),
    }
    return ModelBundle(model=model, metrics=metrics, feature_names=list(FEATURE_NAMES))


def save_model(bundle: ModelBundle, path: Path = MODEL_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path)
    return path


def load_model(path: Path = MODEL_PATH) -> ModelBundle | None:
    if not path.exists():
        return None
    loaded = joblib.load(path)
    if isinstance(loaded, ModelBundle):
        return loaded
    if isinstance(loaded, dict) and "model" in loaded:
        return ModelBundle(
            model=loaded["model"],
            metrics=loaded.get("metrics", {}),
            feature_names=loaded.get("feature_names", list(FEATURE_NAMES)),
        )
    return None


def load_or_train_model() -> ModelBundle:
    bundle = load_model()
    if bundle is not None:
        return bundle
    bundle = train_model()
    save_model(bundle)
    return bundle
