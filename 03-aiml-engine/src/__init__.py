"""
AEGISTRACE 03-AIML-ENGINE source package.
"""

from .feature_extraction import (
    extract_features,
    extract_feature_vector,
    calculate_shannon_entropy,
    FEATURE_NAMES,
    SUSPICIOUS_TLDS,
    SUSPICIOUS_KEYWORDS,
)
from .preprocessing import (
    load_dataset,
    extract_features_dataframe,
    prepare_data,
)
from .train import train_model
from .evaluate import evaluate_model
from .predict import predict_url, get_model, fallback_predict

__all__ = [
    "extract_features",
    "extract_feature_vector",
    "calculate_shannon_entropy",
    "FEATURE_NAMES",
    "SUSPICIOUS_TLDS",
    "SUSPICIOUS_KEYWORDS",
    "load_dataset",
    "extract_features_dataframe",
    "prepare_data",
    "train_model",
    "evaluate_model",
    "predict_url",
    "get_model",
    "fallback_predict",
]
