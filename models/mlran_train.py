"""
MLRan Model Training & Benchmark Pipeline for RansomShield (Tier 1).

Replicates and extends the evaluation from:
"MLRan: A behavioural dataset for ransomware analysis and detection" (JNCA 2026).

Trains and evaluates:
1. Binary Detectors: Logistic Regression, Random Forest, XGBoost (Ransomware vs Goodware)
2. Ransomware Type Classifier: (Goodware, Locker, Crypto, RaaS, Modern)
3. Ransomware Family Classifier: (64 Ransomware Families)

Saves trained models, feature rankings, and evaluation scorecards.
"""

import sys
import os
import json
import argparse
import logging
from pathlib import Path
from typing import Dict, Any, Tuple, List

import numpy as np
import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)

try:
    import xgboost as xgb
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False

from models.mlran_loader import MLRanLoader

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("ransomshield.mlran_train")


def compute_binary_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, float]:
    """Computes comprehensive binary classification metrics."""
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)

    acc = accuracy_score(y_true, y_pred)
    bal_acc = balanced_accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    fpr = float(fp) / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = float(fn) / (fn + tp) if (fn + tp) > 0 else 0.0

    return {
        "accuracy": float(acc * 100),
        "balanced_accuracy": float(bal_acc * 100),
        "precision": float(prec * 100),
        "recall": float(rec * 100),
        "f1_score": float(f1 * 100),
        "false_positive_rate": float(fpr * 100),
        "false_negative_rate": float(fnr * 100),
        "true_positives": int(tp),
        "false_positives": int(fp),
        "true_negatives": int(tn),
        "false_negatives": int(fn),
    }


def compute_multiclass_metrics(y_true: np.ndarray, y_pred: np.ndarray, target_names: List[str] = None) -> Dict[str, Any]:
    """Computes metrics for multi-class tasks (Type or Family)."""
    acc = accuracy_score(y_true, y_pred)
    bal_acc = balanced_accuracy_score(y_true, y_pred)
    f1_weighted = f1_score(y_true, y_pred, average="weighted", zero_division=0)

    return {
        "accuracy": float(acc * 100),
        "balanced_accuracy": float(bal_acc * 100),
        "weighted_f1": float(f1_weighted * 100),
    }


def train_tier1_models(
    loader: MLRanLoader,
    save_dir: Path,
    include_type: bool = True,
    include_family: bool = True,
) -> Dict[str, Any]:
    """Trains and evaluates Tier 1 ML models on MLRan dataset."""
    save_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Loading MLRan train/test partitions...")
    X_train, y_train_bin, y_train_type, y_train_fam, _ = loader.load_train_data()
    X_test, y_test_bin, y_test_type, y_test_fam, _ = loader.load_test_data()

    feature_names = loader.get_all_feature_names()
    results = {"binary": {}, "type": {}, "family": {}}

    # ==========================================
    # 1. Binary Classifiers (Ransomware vs Goodware)
    # ==========================================
    logger.info("Training Binary Model: Logistic Regression (Paper Baseline)...")
    lr = LogisticRegression(max_iter=1000, solver="lbfgs", random_state=42)
    lr.fit(X_train, y_train_bin)
    y_pred_lr = lr.predict(X_test)
    results["binary"]["logistic_regression"] = compute_binary_metrics(y_test_bin, y_pred_lr)
    joblib.dump(lr, save_dir / "binary_lr.joblib")

    logger.info("Training Binary Model: Random Forest (100 Trees)...")
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train_bin)
    y_pred_rf = rf.predict(X_test)
    results["binary"]["random_forest"] = compute_binary_metrics(y_test_bin, y_pred_rf)
    joblib.dump(rf, save_dir / "binary_rf.joblib")

    if HAS_XGBOOST:
        logger.info("Training Binary Model: XGBoost...")
        xgb_clf = xgb.XGBClassifier(
            n_estimators=100, max_depth=4, learning_rate=0.1, random_state=42, eval_metric="logloss"
        )
        xgb_clf.fit(X_train, y_train_bin)
        y_pred_xgb = xgb_clf.predict(X_test)
        results["binary"]["xgboost"] = compute_binary_metrics(y_test_bin, y_pred_xgb)
        joblib.dump(xgb_clf, save_dir / "binary_xgb.joblib")

    # ==========================================
    # 2. Ransomware Type Classifier
    # ==========================================
    if include_type:
        logger.info("Training Ransomware Type Classifier (Random Forest)...")
        rf_type = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
        rf_type.fit(X_train, y_train_type)
        y_pred_type = rf_type.predict(X_test)
        results["type"]["random_forest"] = compute_multiclass_metrics(y_test_type, y_pred_type)
        joblib.dump(rf_type, save_dir / "type_rf.joblib")

    # ==========================================
    # 3. Ransomware Family Classifier
    # ==========================================
    if include_family:
        logger.info("Training Ransomware Family Classifier (Random Forest)...")
        rf_fam = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
        rf_fam.fit(X_train, y_train_fam)
        y_pred_fam = rf_fam.predict(X_test)
        results["family"]["random_forest"] = compute_multiclass_metrics(y_test_fam, y_pred_fam)
        joblib.dump(rf_fam, save_dir / "family_rf.joblib")

    # ==========================================
    # 4. Feature Importance Extraction
    # ==========================================
    # Rank features by Random Forest importance
    importances = rf.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    top_features = []
    for rank, idx in enumerate(sorted_idx[:50], 1):
        top_features.append({
            "rank": rank,
            "feature_id": loader.feature_col_ids[idx],
            "feature_name": feature_names[idx],
            "importance": float(importances[idx]),
        })

    # Save metadata contract
    metadata = {
        "dataset": "MLRan (JNCA 2026)",
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "total_features": int(len(feature_names)),
        "feature_col_ids": loader.feature_col_ids,
        "feature_names": feature_names,
        "type_map": {str(k): v for k, v in loader.type_map.items()},
        "family_map": {str(k): v for k, v in loader.family_map.items()},
        "metrics": results,
        "top_50_features": top_features,
    }

    meta_file = save_dir / "mlran_metadata.json"
    with open(meta_file, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    logger.info(f"Models and metadata saved successfully to {save_dir}")
    return metadata


def print_scorecard(metadata: Dict[str, Any]):
    """Prints a clean ASCII scorecard comparing models."""
    metrics = metadata.get("metrics", {})
    binary_metrics = metrics.get("binary", {})

    print("\n" + "=" * 80)
    print(" RANSOMSHIELD TIER 1 (MLRan REAL-WORLD BENCHMARK SCORECARD)")
    print(" Evaluated on 975 Unseen Test Samples (510 Goodware, 465 Ransomware)")
    print("=" * 80)
    print(f"{'Model':<22} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'F1 Score':<10} | {'FPR':<8}")
    print("-" * 80)

    for name, m in binary_metrics.items():
        disp_name = name.replace("_", " ").title()
        print(
            f"{disp_name:<22} | {m['accuracy']:>9.2f}% | {m['precision']:>9.2f}% | "
            f"{m['recall']:>9.2f}% | {m['f1_score']:>9.2f}% | {m['false_positive_rate']:>7.2f}%"
        )
    print("-" * 80)

    if "random_forest" in binary_metrics:
        rf_m = binary_metrics["random_forest"]
        print(f"\n[+] Confusion Matrix (Random Forest):")
        print(f"    - True Negatives (Goodware correctly identified):   {rf_m['true_negatives']} / 510")
        print(f"    - True Positives (Ransomware correctly caught):    {rf_m['true_positives']} / 465")
        print(f"    - False Positives (Normal apps falsely flagged):   {rf_m['false_positives']}")
        print(f"    - False Negatives (Ransomware attacks missed):     {rf_m['false_negatives']}")

    type_metrics = metrics.get("type", {})
    if "random_forest" in type_metrics:
        tm = type_metrics["random_forest"]
        print(f"\n[+] Ransomware Type Classification (Locker/Crypto/RaaS/Modern):")
        print(f"    - Accuracy: {tm['accuracy']:.2f}% | Weighted F1: {tm['weighted_f1']:.2f}%")

    top_feats = metadata.get("top_50_features", [])[:5]
    print("\n[+] Top 5 Discriminative Behavioral Signatures (AI Decision Drivers):")
    for item in top_feats:
        print(f"    {item['rank']}. {item['feature_name']} (Weight: {item['importance']:.4f})")
    print("=" * 80 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Train RansomShield Tier 1 on MLRan Dataset")
    parser.add_argument(
        "--dataset-dir", type=str, default=None, help="Path to datasets/MLRan directory"
    )
    parser.add_argument(
        "--out-dir", type=str, default=None, help="Directory to save trained models"
    )
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    dataset_dir = Path(args.dataset_dir) if args.dataset_dir else project_root / "datasets" / "MLRan"
    out_dir = Path(args.out_dir) if args.out_dir else project_root / "models" / "saved" / "mlran"

    loader = MLRanLoader(dataset_dir=dataset_dir)
    metadata = train_tier1_models(loader, save_dir=out_dir)
    print_scorecard(metadata)


if __name__ == "__main__":
    main()
