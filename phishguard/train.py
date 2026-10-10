"""Entraîne le classifieur d'URLs de phishing (données SYNTHÉTIQUES)."""
import argparse
import json
import random
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, roc_auc_score
from sklearn.model_selection import train_test_split

from phishguard import __version__
from phishguard.features import FEATURE_NAMES, RISKY_TLDS, SUSPICIOUS_WORDS, extract_features

LEGIT_WORDS = [
    "github", "wikipedia", "python", "openai", "mozilla", "stackoverflow", "bbc",
    "nytimes", "amazon", "microsoft", "apple", "linux", "docker", "kubernetes",
    "university", "library", "weather", "recipes", "news", "travel", "shop",
]


def _legit_url(rng):
    scheme = "https" if rng.random() < 0.92 else "http"
    sub = rng.choice(["", "www.", "docs.", "blog."])
    tld = rng.choice(["com", "org", "net", "edu", "io"])
    path = rng.choice(["", "/", "/about", f"/products/{rng.randint(1, 999)}",
                       f"/blog/2024/{rng.choice(LEGIT_WORDS)}"])
    if rng.random() < 0.08:  # bruit : les vrais sites ont aussi des pages login
        path = "/login"
    return f"{scheme}://{sub}{rng.choice(LEGIT_WORDS)}.{tld}{path}"


def _phish_url(rng):
    brand, word = rng.choice(LEGIT_WORDS), rng.choice(SUSPICIOUS_WORDS)
    risky = sorted(RISKY_TLDS)
    style = rng.random()
    if style < 0.2:
        host = ".".join(str(rng.randint(1, 254)) for _ in range(4))
    elif style < 0.6:
        host = f"{brand}-{word}.{rng.choice(risky)}"
    else:
        host = (f"{word}.{brand}.{rng.choice(['com', 'net', 'info'])}."
                f"{rng.choice(['secure-check', 'verify-id', 'acc-update'])}."
                f"{rng.choice(risky + ['com'])}")
    scheme = "http" if rng.random() < 0.7 else "https"
    path = (f"/{word}/{rng.randint(1000, 99999)}"
            f"?id={rng.randint(1, 9999)}&token=%{rng.randint(10, 99)}")
    if rng.random() < 0.15:  # bruit : certaines URLs de phishing semblent simples
        path = "/"
    at = f"{brand}.com@" if rng.random() < 0.1 else ""
    return f"{scheme}://{at}{host}{path}"


def generate_dataset(n, seed):
    rng = random.Random(seed)
    urls, y = [], []
    for _ in range(n):
        if rng.random() < 0.5:
            urls.append(_legit_url(rng))
            y.append(0)
        else:
            urls.append(_phish_url(rng))
            y.append(1)
    X = np.array([extract_features(u) for u in urls])
    return X, np.array(y), urls


def train_and_save(out_dir, n=6000, seed=42):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    X, y, _ = generate_dataset(n, seed)
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, random_state=seed, stratify=y)

    clf = RandomForestClassifier(n_estimators=150, max_depth=12,
                                 random_state=seed, n_jobs=-1)
    clf.fit(X_tr, y_tr)

    proba = clf.predict_proba(X_te)[:, 1]
    metrics = {
        "accuracy": round(float(accuracy_score(y_te, (proba >= 0.5).astype(int))), 4),
        "roc_auc": round(float(roc_auc_score(y_te, proba)), 4),
    }

    joblib.dump(clf, out / "model.joblib")

    meta = {
        "name": "phishguard-rf", "code_version": __version__,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "n_samples": n, "data_source": "synthetic", "metrics": metrics,
        "features": FEATURE_NAMES,
    }
    (out / "metadata.json").write_text(json.dumps(meta, indent=2))

    # Statistiques de référence, utilisées plus tard pour détecter le drift
    baseline = {name: {"mean": float(X_tr[:, i].mean()), "std": float(X_tr[:, i].std())}
                for i, name in enumerate(FEATURE_NAMES)}
    (out / "baseline.json").write_text(json.dumps(baseline, indent=2))

    return metrics


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="models")
    ap.add_argument("--samples", type=int, default=6000)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    print("metrics:", train_and_save(args.out, args.samples, args.seed))


if __name__ == "__main__":
    main()
