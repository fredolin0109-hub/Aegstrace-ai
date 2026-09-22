"""
AEGISTRACE 03-AIML-ENGINE
Preprocessing Module for Phishing Detection Pipeline.
Handles dataset loading, validation, feature matrix extraction, and stratified train/test splitting.
"""

import sys
from pathlib import Path
from typing import Tuple, List, Union, Optional
import pandas as pd
from sklearn.model_selection import train_test_split

# Ensure 03-aiml-engine and its src are on sys.path
CURRENT_DIR = Path(__file__).resolve().parent
ENGINE_DIR = CURRENT_DIR.parent
if str(ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(ENGINE_DIR))
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from feature_extraction import extract_features, FEATURE_NAMES

DEFAULT_DATASET_PATH = ENGINE_DIR / "data" / "urls_dataset.csv"


def load_dataset(csv_path: Optional[Union[str, Path]] = None) -> pd.DataFrame:
    """
    Loads and validates the URL dataset from CSV.
    Ensures required columns exist, removes duplicates and handles null values.
    """
    path = Path(csv_path) if csv_path else DEFAULT_DATASET_PATH
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found at {path}")

    df = pd.read_csv(path)
    required_cols = {"url", "label"}
    if not required_cols.issubset(df.columns):
        raise ValueError(f"Dataset missing required columns: {required_cols - set(df.columns)}")

    # Clean URL strings and drop invalid/empty rows
    df["url"] = df["url"].astype(str).str.strip()
    df = df[df["url"] != ""]
    df = df.dropna(subset=["url", "label"])
    df = df.drop_duplicates(subset=["url"])
    df["label"] = df["label"].astype(int)

    return df


def extract_features_dataframe(df: pd.DataFrame, url_col: str = "url") -> pd.DataFrame:
    """
    Extracts lexical and structural feature matrix from a DataFrame of URLs.
    Returns a DataFrame whose columns strictly match FEATURE_NAMES.
    """
    if url_col not in df.columns:
        raise KeyError(f"Column '{url_col}' not found in dataframe")

    records = [extract_features(url) for url in df[url_col]]
    feature_df = pd.DataFrame(records, columns=FEATURE_NAMES)
    return feature_df


def prepare_data(
    csv_path: Optional[Union[str, Path]] = None,
    test_size: float = 0.2,
    random_state: int = 42
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series, List[str]]:
    """
    Full preprocessing pipeline:
    1. Loads and validates dataset
    2. Extracts feature matrix X
    3. Performs stratified train/test split
    Returns (X_train, X_test, y_train, y_test, feature_names)
    """
    df = load_dataset(csv_path)
    X = extract_features_dataframe(df, url_col="url")
    y = df["label"].copy()

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y
    )

    return X_train, X_test, y_train, y_test, FEATURE_NAMES
