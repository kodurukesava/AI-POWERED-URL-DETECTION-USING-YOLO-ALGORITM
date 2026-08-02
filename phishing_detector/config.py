from __future__ import annotations

from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = PACKAGE_DIR.parent
ARTIFACTS_DIR = PROJECT_DIR / "artifacts"
MODEL_PATH = ARTIFACTS_DIR / "phishing_model_uci.joblib"
DATASET_PATH = ARTIFACTS_DIR / "uci_phishing_websites.csv"

DEFAULT_THRESHOLD = 0.5
