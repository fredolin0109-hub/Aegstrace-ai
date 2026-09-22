"""
AEGISTRACE 03-AIML-ENGINE
Unit tests for Preprocessing module (data loading, validation, DataFrame extraction, train/test split).
"""

import tempfile
from pathlib import Path
import pandas as pd
import pytest

from preprocessing import (
    load_dataset,
    extract_features_dataframe,
    prepare_data,
    DEFAULT_DATASET_PATH,
)
from feature_extraction import FEATURE_NAMES


def test_load_default_dataset():
    """Verify default dataset loads cleanly with expected columns and non-empty rows."""
    assert DEFAULT_DATASET_PATH.exists(), f"Default dataset missing at {DEFAULT_DATASET_PATH}"
    df = load_dataset()

    assert isinstance(df, pd.DataFrame)
    assert "url" in df.columns
    assert "label" in df.columns
    assert len(df) > 500
    # Labels must be binary (0 = safe, 1 = phishing)
    assert set(df["label"].unique()).issubset({0, 1})
    # No empty or whitespace URLs
    assert not (df["url"] == "").any()
    # No duplicate URLs
    assert df["url"].duplicated().sum() == 0


def test_load_dataset_missing_file():
    """Verify FileNotFoundError on non-existent path."""
    with pytest.raises(FileNotFoundError):
        load_dataset("non_existent_directory/fake_data.csv")


def test_load_dataset_invalid_columns():
    """Verify ValueError when required columns ('url', 'label') are missing."""
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as tmp:
        tmp.write("domain,threat_score\nexample.com,0.5\n")
        tmp_path = Path(tmp.name)

    try:
        with pytest.raises(ValueError, match="Dataset missing required columns"):
            load_dataset(tmp_path)
    finally:
        tmp_path.unlink(missing_ok=True)


def test_load_dataset_cleaning_duplicates_and_nulls():
    """Verify duplicate and null rows are removed properly."""
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as tmp:
        tmp.write("url,label\n")
        tmp.write("https://dup.com,0\n")
        tmp.write("https://dup.com,0\n")
        tmp.write("   ,0\n")
        tmp.write("https://unique.com,1\n")
        tmp_path = Path(tmp.name)

    try:
        df = load_dataset(tmp_path)
        assert len(df) == 2
        assert list(df["url"]) == ["https://dup.com", "https://unique.com"]
    finally:
        tmp_path.unlink(missing_ok=True)


def test_extract_features_dataframe():
    """Verify extract_features_dataframe produces correct schema and dimensions."""
    sample_df = pd.DataFrame({
        "url": ["https://google.com", "http://192.168.1.1/login.php"],
        "label": [0, 1]
    })
    feature_df = extract_features_dataframe(sample_df)

    assert isinstance(feature_df, pd.DataFrame)
    assert len(feature_df) == 2
    assert list(feature_df.columns) == FEATURE_NAMES
    assert feature_df.loc[0, "is_https"] == 1
    assert feature_df.loc[1, "is_ip_address"] == 1


def test_extract_features_dataframe_missing_col():
    """Verify KeyError when specified URL column is missing."""
    sample_df = pd.DataFrame({"target": ["https://test.com"]})
    with pytest.raises(KeyError):
        extract_features_dataframe(sample_df, url_col="url")


def test_prepare_data_stratified_split():
    """Verify prepare_data produces properly sized and stratified splits."""
    X_train, X_test, y_train, y_test, feat_names = prepare_data(test_size=0.25, random_state=42)

    assert len(X_train) == len(y_train)
    assert len(X_test) == len(y_test)
    total = len(X_train) + len(X_test)

    # Test size fraction roughly 25%
    test_ratio = len(X_test) / total
    assert 0.20 <= test_ratio <= 0.30

    assert feat_names == FEATURE_NAMES
    assert list(X_train.columns) == FEATURE_NAMES
    assert list(X_test.columns) == FEATURE_NAMES

    # Stratification check: proportion of 1s in train and test should be similar
    train_pos_rate = y_train.mean()
    test_pos_rate = y_test.mean()
    assert abs(train_pos_rate - test_pos_rate) < 0.05
