"""
AEGISTRACE 03-AIML-ENGINE
Model Training Module for Phishing Detection.
Trains an interpretable Random Forest model with calibrated probability estimates,
computes cross-validation scores, and persists artifacts to models/.
"""

import sys
import json
import datetime
from pathlib import Path
from typing import Optional, Union, Dict, Any, Tuple
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score

# Ensure 03-aiml-engine and its src are on sys.path
CURRENT_DIR = Path(__file__).resolve().parent
ENGINE_DIR = CURRENT_DIR.parent
if str(ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(ENGINE_DIR))
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from feature_extraction import FEATURE_NAMES
from preprocessing import prepare_data

DEFAULT_MODELS_DIR = ENGINE_DIR / "models"


def train_model(
    csv_path: Optional[Union[str, Path]] = None,
    models_dir: Optional[Union[str, Path]] = None,
    random_state: int = 42
) -> Tuple[RandomForestClassifier, Dict[str, Any], Any]:
    """
    Trains an interpretable Random Forest classifier on URL features.
    Saves model artifact (.joblib) and metadata (.json) to models_dir.
    Returns (model, metadata, (X_train, X_test, y_train, y_test)).
    """
    target_models_dir = Path(models_dir) if models_dir else DEFAULT_MODELS_DIR
    target_models_dir.mkdir(parents=True, exist_ok=True)

    print("[*] Preparing dataset and extracting URL feature matrix...")
    X_train, X_test, y_train, y_test, feature_names = prepare_data(
        csv_path=csv_path,
        random_state=random_state
    )

    print(f"[*] Training samples: {len(X_train)}, Testing samples: {len(X_test)}")

    # Initialize Random Forest Classifier
    hyperparameters = {
        "n_estimators": 120,
        "max_depth": 10,
        "min_samples_split": 4,
        "min_samples_leaf": 2,
        "class_weight": "balanced",
        "random_state": random_state,
        "n_jobs": -1
    }
    model = RandomForestClassifier(**hyperparameters)

    # 5-Fold Cross Validation
    print("[*] Running 5-Fold Cross-Validation on training data...")
    cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring="f1")
    cv_mean = float(cv_scores.mean())
    cv_std = float(cv_scores.std())
    print(f"[*] 5-Fold CV F1 Score: {cv_mean:.4f} (+/- {cv_std:.4f})")

    # Fit final model on full training split
    print("[*] Fitting final Random Forest model...")
    model.fit(X_train, y_train)

    # Calculate feature importances
    importances = model.feature_importances_
    feature_importance_dict = {
        name: round(float(imp), 4)
        for name, imp in sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True)
    }

    # Prepare metadata payload
    metadata = {
        "model_type": "RandomForestClassifier",
        "version": "1.0.0",
        "trained_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "random_state": random_state,
        "hyperparameters": {k: v for k, v in hyperparameters.items() if k != "n_jobs"},
        "feature_names": feature_names,
        "feature_importances": feature_importance_dict,
        "training_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "cv_f1_mean": round(cv_mean, 4),
        "cv_f1_std": round(cv_std, 4),
    }

    # Save artifacts
    model_path = target_models_dir / "phishing_model.joblib"
    metadata_path = target_models_dir / "model_metadata.json"

    print(f"[*] Saving model to {model_path}...")
    joblib.dump(model, model_path)

    print(f"[*] Saving model metadata to {metadata_path}...")
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print("[+] Model training complete!")
    return model, metadata, (X_train, X_test, y_train, y_test)


if __name__ == "__main__":
    train_model()
