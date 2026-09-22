"""
AEGISTRACE 03-AIML-ENGINE
Real-Time Phishing URL Prediction Interface.
Loads persisted Random Forest model and provides explainable risk scoring,
feature attribution, and recommended security actions with graceful fallback.
"""

import sys
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union
import pandas as pd
import joblib

# Ensure 03-aiml-engine and its src are on sys.path
CURRENT_DIR = Path(__file__).resolve().parent
ENGINE_DIR = CURRENT_DIR.parent
if str(ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(ENGINE_DIR))
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from feature_extraction import extract_features, FEATURE_NAMES

logger = logging.getLogger("aegistrace.aiml.predict")

DEFAULT_MODEL_PATH = ENGINE_DIR / "models" / "phishing_model.joblib"
DEFAULT_METADATA_PATH = ENGINE_DIR / "models" / "model_metadata.json"

_CACHED_MODEL = None
_CACHED_METADATA = None


def get_model(
    model_path: Optional[Path] = None,
    metadata_path: Optional[Path] = None
) -> Tuple[Optional[Any], Optional[Dict[str, Any]]]:
    """
    Retrieves or lazily loads the trained model artifact and its metadata.
    Returns (model, metadata) or (None, None) if files do not exist.
    """
    global _CACHED_MODEL, _CACHED_METADATA

    if model_path is None and metadata_path is None and _CACHED_MODEL is not None:
        return _CACHED_MODEL, _CACHED_METADATA

    target_model = Path(model_path) if model_path else DEFAULT_MODEL_PATH
    target_meta = Path(metadata_path) if metadata_path else DEFAULT_METADATA_PATH

    loaded_model = None
    loaded_metadata = None

    if target_model.exists():
        try:
            loaded_model = joblib.load(target_model)
            if target_meta.exists():
                with open(target_meta, "r", encoding="utf-8") as f:
                    loaded_metadata = json.load(f)
            else:
                loaded_metadata = {"model_type": type(loaded_model).__name__, "version": "1.0.0"}
            logger.info("AIML Phishing model loaded successfully from %s", target_model)
        except Exception as exc:
            logger.warning("Failed to load AIML model from %s: %s. Using fallback.", target_model, exc)
            loaded_model = None
            loaded_metadata = None
    else:
        logger.warning("AIML model file %s not found. Prediction will use fallback heuristics.", target_model)

    if model_path is None and metadata_path is None:
        _CACHED_MODEL = loaded_model
        _CACHED_METADATA = loaded_metadata

    return loaded_model, loaded_metadata


def generate_explanations(features: Dict[str, Any], risk_score: float) -> List[str]:
    """
    Generates human-readable explanations of top contributing risk factors
    ranked by diagnostic importance.
    """
    explanations: List[str] = []

    if features.get("is_ip_address", 0) == 1:
        explanations.append("Host is a raw IP address rather than a verified registered domain")

    if features.get("has_at_symbol", 0) == 1:
        explanations.append("Contains '@' authority delimiter used in credential/URL spoofing")

    if features.get("is_suspicious_tld", 0) == 1:
        explanations.append("Uses high-abuse top-level domain frequently associated with spam or phishing")

    kw_count = features.get("suspicious_keyword_count", 0)
    if kw_count >= 2:
        explanations.append(f"Multiple credential/financial keywords detected ({kw_count} keywords)")
    elif kw_count == 1:
        explanations.append("Security or authentication lure keyword detected in URL")

    if features.get("has_redirect_token", 0) == 1:
        explanations.append("Contains redirect or destination parameter token indicative of open relay lures")

    if features.get("has_double_slash_path", 0) == 1:
        explanations.append("Anomalous double slashes ('//') found in URL path")

    subdomains = features.get("subdomain_count", 0)
    if subdomains >= 3:
        explanations.append(f"Excessive subdomain nesting ({subdomains} subdomains) indicative of domain shadowing")

    hyphens = features.get("hyphen_count_hostname", 0)
    if hyphens >= 2:
        explanations.append(f"Multiple hyphens in domain name ({hyphens} hyphens) suggesting brand impersonation")

    entropy = features.get("entropy", 0.0)
    if entropy > 4.5:
        explanations.append(f"Elevated Shannon entropy ({entropy:.2f} bits) suggests randomized or obfuscated tokens")

    digit_ratio = features.get("digit_ratio", 0.0)
    if digit_ratio > 0.25:
        explanations.append(f"High numeric density ({int(digit_ratio * 100)}% digits in URL)")

    url_len = features.get("url_length", 0)
    if url_len > 90:
        explanations.append(f"Anomalously long URL ({url_len} characters)")

    if features.get("is_https", 0) == 0 and (kw_count > 0 or features.get("is_ip_address", 0) == 1):
        explanations.append("Insecure HTTP protocol used in conjunction with sensitive keywords or raw IP")

    if not explanations:
        if risk_score < 0.35:
            explanations.append("URL exhibits standard structural characteristics, legitimate protocol, and low entropy")
        else:
            explanations.append("Structural lexical anomalies detected across URL components")

    return explanations


def fallback_predict(features: Dict[str, Any]) -> Tuple[float, float, str]:
    """
    Deterministic rule-based fallback if ML model artifact is unavailable.
    Returns (risk_score, confidence, classification).
    """
    score = 0.05
    if features.get("is_ip_address", 0):
        score += 0.40
    if features.get("has_at_symbol", 0):
        score += 0.25
    if features.get("is_suspicious_tld", 0):
        score += 0.20
    if features.get("suspicious_keyword_count", 0) >= 2:
        score += 0.30
    elif features.get("suspicious_keyword_count", 0) == 1:
        score += 0.15
    if features.get("subdomain_count", 0) >= 3:
        score += 0.15
    if features.get("has_redirect_token", 0):
        score += 0.10
    if features.get("has_double_slash_path", 0):
        score += 0.15
    if features.get("hyphen_count_hostname", 0) >= 2:
        score += 0.10
    if features.get("entropy", 0.0) > 4.5:
        score += 0.10

    clamped = round(min(1.0, max(0.0, score)), 4)
    confidence = 0.75  # Moderate confidence on heuristic fallback
    classification = "HIGH_RISK" if clamped >= 0.70 else ("SUSPICIOUS" if clamped >= 0.35 else "SAFE")
    return clamped, confidence, classification


def predict_url(
    url: str,
    model_path: Optional[Union[str, Path]] = None,
    metadata_path: Optional[Union[str, Path]] = None
) -> Dict[str, Any]:
    """
    Real-time prediction interface for a given URL string.
    Returns dictionary with risk_score, classification, confidence,
    detected_features, explanation, and recommended_action.
    """
    feats = extract_features(url)
    model, metadata = get_model(
        Path(model_path) if model_path else None,
        Path(metadata_path) if metadata_path else None
    )

    if model is not None:
        try:
            # Build 1-row DataFrame strictly matching FEATURE_NAMES
            feature_vector_df = pd.DataFrame([feats], columns=FEATURE_NAMES)
            probas = model.predict_proba(feature_vector_df)[0]
            # probas: [P(safe), P(malicious)]
            risk_score = round(float(probas[1]), 4)
            confidence = round(float(max(probas[0], probas[1])), 4)

            if risk_score >= 0.70:
                classification = "HIGH_RISK"
            elif risk_score >= 0.35:
                classification = "SUSPICIOUS"
            else:
                classification = "SAFE"

            model_version = metadata.get("version", "1.0.0") if metadata else "1.0.0"
        except Exception as err:
            logger.warning("Model inference error (%s); invoking fallback", err)
            risk_score, confidence, classification = fallback_predict(feats)
            model_version = "fallback_heuristic"
    else:
        risk_score, confidence, classification = fallback_predict(feats)
        model_version = "fallback_heuristic"

    # Determine recommended action
    if classification == "HIGH_RISK":
        recommended_action = "BLOCK"
    elif classification == "SUSPICIOUS":
        recommended_action = "INVESTIGATE" if risk_score >= 0.55 else "WARN"
    else:
        recommended_action = "ALLOW"

    explanations = generate_explanations(feats, risk_score)
    if model_version == "fallback_heuristic":
        explanations.append("[NOTE] Evaluated using rule-based ML fallback")

    return {
        "url": url,
        "risk_score": risk_score,
        "classification": classification,
        "confidence": confidence,
        "detected_features": feats,
        "explanation": explanations,
        "recommended_action": recommended_action,
        "model_version": model_version,
    }
