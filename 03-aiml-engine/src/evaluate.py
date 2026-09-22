"""
AEGISTRACE 03-AIML-ENGINE
Model Evaluation Module for Phishing Detection.
Computes real, un-fabricated performance metrics (Accuracy, Precision, Recall, F1, ROC-AUC, Confusion Matrix)
and saves evaluation report to models/evaluation_report.json.
"""

import sys
import json
import datetime
from pathlib import Path
from typing import Optional, Union, Dict, Any, Tuple
import joblib
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)

# Ensure 03-aiml-engine and its src are on sys.path
CURRENT_DIR = Path(__file__).resolve().parent
ENGINE_DIR = CURRENT_DIR.parent
if str(ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(ENGINE_DIR))
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from preprocessing import prepare_data

DEFAULT_MODELS_DIR = ENGINE_DIR / "models"


def evaluate_model(
    model: Optional[Any] = None,
    test_data: Optional[Tuple[pd.DataFrame, pd.Series]] = None,
    csv_path: Optional[Union[str, Path]] = None,
    models_dir: Optional[Union[str, Path]] = None,
    save_report: bool = True
) -> Dict[str, Any]:
    """
    Evaluates the model on test split and generates detailed evaluation metrics.
    """
    target_models_dir = Path(models_dir) if models_dir else DEFAULT_MODELS_DIR

    # Load model if not supplied
    if model is None:
        model_path = target_models_dir / "phishing_model.joblib"
        if not model_path.exists():
            raise FileNotFoundError(f"Trained model not found at {model_path}. Run train.py first.")
        print(f"[*] Loading model from {model_path}...")
        model = joblib.load(model_path)

    # Prepare test split if not supplied
    if test_data is None:
        print("[*] Generating test split for evaluation...")
        _, X_test, _, y_test, _ = prepare_data(csv_path=csv_path)
    else:
        X_test, y_test = test_data

    # Predictions and probability estimation
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    # Compute metrics
    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    auc = float(roc_auc_score(y_test, y_proba))

    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    cm_dict = {
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_positives": int(tp),
    }

    class_report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)

    # Threshold analysis for operational calibration
    threshold_metrics = {}
    for th in [0.35, 0.50, 0.70]:
        th_pred = (y_proba >= th).astype(int)
        threshold_metrics[f"threshold_{th:.2f}"] = {
            "precision": round(float(precision_score(y_test, th_pred, zero_division=0)), 4),
            "recall": round(float(recall_score(y_test, th_pred, zero_division=0)), 4),
            "f1_score": round(float(f1_score(y_test, th_pred, zero_division=0)), 4),
        }

    report = {
        "evaluated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "test_samples": int(len(X_test)),
        "metrics": {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(auc, 4),
        },
        "confusion_matrix": cm_dict,
        "classification_report": class_report,
        "threshold_analysis": threshold_metrics,
    }

    print("\n" + "=" * 55)
    print("           AEGISTRACE MODEL EVALUATION REPORT")
    print("=" * 55)
    print(f" Test Set Size:       {len(X_test)} samples")
    print(f" Accuracy:            {acc * 100:.2f}%")
    print(f" Precision:           {prec * 100:.2f}%")
    print(f" Recall:              {rec * 100:.2f}%")
    print(f" F1-Score:            {f1 * 100:.2f}%")
    print(f" ROC-AUC:             {auc:.4f}")
    print(f" Confusion Matrix:    TN={tn} | FP={fp} | FN={fn} | TP={tp}")
    print("=" * 55 + "\n")

    if save_report:
        report_path = target_models_dir / "evaluation_report.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"[+] Evaluation report persisted to {report_path}")

    return report


if __name__ == "__main__":
    evaluate_model()
