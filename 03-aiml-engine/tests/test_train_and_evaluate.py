"""
AEGISTRACE 03-AIML-ENGINE
Unit tests for Model Training and Evaluation Pipeline.
"""

import tempfile
import json
from pathlib import Path
import pytest

from train import train_model
from evaluate import evaluate_model


def test_train_and_evaluate_pipeline():
    """Verify end-to-end training and evaluation into a temporary directory."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_models_dir = Path(tmp_dir)

        # 1. Execute Training
        model, metadata, test_splits = train_model(
            models_dir=tmp_models_dir,
            random_state=42
        )

        assert model is not None
        assert (tmp_models_dir / "phishing_model.joblib").exists()
        assert (tmp_models_dir / "model_metadata.json").exists()

        assert metadata["model_type"] == "RandomForestClassifier"
        assert metadata["training_samples"] > 0
        assert metadata["test_samples"] > 0
        assert metadata["cv_f1_mean"] > 0.90
        assert "feature_importances" in metadata
        assert len(metadata["feature_importances"]) == 20

        # 2. Execute Evaluation on the trained model
        X_train, X_test, y_train, y_test = test_splits
        report = evaluate_model(
            model=model,
            test_data=(X_test, y_test),
            models_dir=tmp_models_dir,
            save_report=True
        )

        assert report is not None
        assert "metrics" in report
        metrics = report["metrics"]

        # Benchmarks: Accuracy and F1 must exceed 90%
        assert metrics["accuracy"] >= 0.90
        assert metrics["precision"] >= 0.90
        assert metrics["recall"] >= 0.90
        assert metrics["f1_score"] >= 0.90
        assert metrics["roc_auc"] >= 0.95

        # Check confusion matrix
        cm = report["confusion_matrix"]
        assert cm["true_positives"] > 0
        assert cm["true_negatives"] > 0

        # Check saved report file
        report_file = tmp_models_dir / "evaluation_report.json"
        assert report_file.exists()
        with open(report_file, "r", encoding="utf-8") as f:
            saved_data = json.load(f)
            assert "metrics" in saved_data
