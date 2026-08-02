from __future__ import annotations

import random
import string
from pathlib import Path

import pandas as pd

from .features import FEATURE_NAMES, extract_url_features

BENIGN_TLDS = ("com", "org", "net", "edu", "gov", "io")
BENIGN_WORDS = (
    "example",
    "portal",
    "docs",
    "support",
    "company",
    "community",
    "learning",
    "health",
    "finance",
    "cloud",
    "studio",
    "news",
    "research",
    "service",
)
BENIGN_PATHS = ("about", "contact", "help", "pricing", "docs", "blog", "careers", "products")
PHISH_WORDS = (
    "login",
    "verify",
    "confirm",
    "account",
    "secure",
    "update",
    "password",
    "billing",
    "support",
    "unlock",
    "auth",
    "signin",
)
PHISH_TLDS = ("zip", "top", "xyz", "click", "pw", "work", "gq", "cf")


def _rand_word(rng: random.Random, min_len: int = 4, max_len: int = 10) -> str:
    length = rng.randint(min_len, max_len)
    return "".join(rng.choice(string.ascii_lowercase) for _ in range(length))


def _benign_url(rng: random.Random) -> str:
    tld = rng.choice(BENIGN_TLDS)
    prefix = "www." if rng.random() < 0.7 else ""
    domain = rng.choice(BENIGN_WORDS)
    second = rng.choice(BENIGN_WORDS + ("platform", "hub", "center"))
    if rng.random() < 0.35:
        domain = f"{domain}-{second}"
    if rng.random() < 0.2:
        domain = f"{domain}{rng.randint(1, 99)}"
    path = "/" + "/".join(rng.choices(BENIGN_PATHS + (_rand_word(rng),), k=rng.randint(0, 2)))
    path = path if path != "/" else ""
    scheme = "https" if rng.random() < 0.85 else "http"
    query = ""
    if rng.random() < 0.15:
        query = f"?ref={rng.choice(BENIGN_WORDS)}&source={rng.choice(BENIGN_WORDS)}"
    return f"{scheme}://{prefix}{domain}.{tld}{path}{query}"


def _phishing_url(rng: random.Random) -> str:
    tld = rng.choice(PHISH_TLDS)
    word_a = rng.choice(PHISH_WORDS)
    word_b = rng.choice(PHISH_WORDS + BENIGN_WORDS)
    scheme = "http" if rng.random() < 0.75 else "https"
    if rng.random() < 0.2:
        host = f"{rng.randint(10, 250)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    else:
        subdomains = [rng.choice(PHISH_WORDS), rng.choice(("secure", "login", "auth", "verify", "account"))]
        if rng.random() < 0.5:
            subdomains.insert(0, _rand_word(rng))
        domain = f"{word_a}-{word_b}-{rng.randint(10, 999)}"
        host = ".".join(subdomains + [f"{domain}.{tld}"])
        if rng.random() < 0.2:
            host = f"{host}@{rng.choice(BENIGN_WORDS)}.{rng.choice(BENIGN_TLDS)}"
    path_parts = [
        rng.choice(("login", "verify", "confirm", "account", "password", "reset", "secure", "update")),
        rng.choice((word_a, word_b, "session", "signin", "billing", "access")),
    ]
    path = "/" + "/".join(path_parts[: rng.randint(1, 2)])
    if rng.random() < 0.4:
        path += f"/{_rand_word(rng, 6, 14)}"
    query = ""
    if rng.random() < 0.7:
        query = f"?redirect={rng.choice(BENIGN_WORDS)}&token={_rand_word(rng, 10, 24)}"
    return f"{scheme}://{host}{path}{query}"


def generate_dataset(samples: int = 4000, seed: int = 7) -> pd.DataFrame:
    rng = random.Random(seed)
    rows = []
    for index in range(samples):
        label = 1 if index % 2 else 0
        url = _phishing_url(rng) if label else _benign_url(rng)
        features = extract_url_features(url)
        row = {name: value for name, value in zip(FEATURE_NAMES, features.values)}
        row["url"] = url
        row["label"] = label
        rows.append(row)
    frame = pd.DataFrame(rows)
    return frame.sample(frac=1.0, random_state=seed).reset_index(drop=True)


def dataset_path() -> Path:
    return Path(__file__).resolve().parent.parent / "artifacts" / "synthetic_phishing_dataset.csv"


def save_dataset(frame: pd.DataFrame) -> Path:
    path = dataset_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(path, index=False)
    return path
