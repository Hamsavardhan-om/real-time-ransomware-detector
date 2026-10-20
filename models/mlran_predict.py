"""
MLRan Predictor & Explainability Engine for RansomShield (Tier 1 Triage).

Performs inference on feature vectors or sample IDs using models trained
on the real-world MLRan dataset. Provides explainable evidence breakdowns.
"""

import json
import argparse
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import numpy as np
import joblib

from models.mlran_loader import MLRanLoader


class MLRanPredictor:
    def __init__(self, model_dir: Optional[Path] = None):
        if model_dir is None:
            self.model_dir = Path(__file__).resolve().parent.parent / "models" / "saved" / "mlran"
        else:
            self.model_dir = Path(model_dir)

        self.meta_path = self.model_dir / "mlran_metadata.json"
        if not self.meta_path.exists():
            raise FileNotFoundError(
                f"Trained model metadata not found at {self.meta_path}. "
                "Please run `python3 -m models.mlran_train` first."
            )

        with open(self.meta_path, "r", encoding="utf-8") as f:
            self.metadata = json.load(f)

        self.feature_names = self.metadata["feature_names"]
        self.feature_col_ids = self.metadata["feature_col_ids"]
        self.type_map = {int(k): v for k, v in self.metadata["type_map"].items()}
        self.family_map = {int(k): v for k, v in self.metadata["family_map"].items()}

        # Load models
        self.binary_lr = joblib.load(self.model_dir / "binary_lr.joblib")
        self.binary_rf = joblib.load(self.model_dir / "binary_rf.joblib")

        self.type_rf = None
        if (self.model_dir / "type_rf.joblib").exists():
            self.type_rf = joblib.load(self.model_dir / "type_rf.joblib")

        self.family_rf = None
        if (self.model_dir / "family_rf.joblib").exists():
            self.family_rf = joblib.load(self.model_dir / "family_rf.joblib")

        # Precompute logistic regression feature coefficients for explainability
        if hasattr(self.binary_lr, "coef_"):
            self.lr_coefs = self.binary_lr.coef_[0]
        else:
            self.lr_coefs = np.zeros(len(self.feature_names))

    def predict(
        self,
        feature_vector: np.ndarray,
        model_type: str = "lr",
    ) -> Dict[str, Any]:
        """
        Runs triage classification on a 483-dimensional feature vector.
        model_type: 'lr' (Logistic Regression) or 'rf' (Random Forest)
        """
        if feature_vector.ndim == 1:
            X = feature_vector.reshape(1, -1)
        else:
            X = feature_vector

        # Binary Prediction
        model = self.binary_lr if model_type == "lr" else self.binary_rf
        probs = model.predict_proba(X)[0]
        prob_ransomware = float(probs[1]) if len(probs) > 1 else float(probs[0])
        is_ransomware = prob_ransomware >= 0.5
        confidence = float(max(probs))

        verdict = "RANSOMWARE" if is_ransomware else "GOODWARE"

        # Type Prediction
        pred_type_name = "unknown"
        if self.type_rf is not None and is_ransomware:
            type_pred = int(self.type_rf.predict(X)[0])
            pred_type_name = self.type_map.get(type_pred, "crypto")
        elif not is_ransomware:
            pred_type_name = "goodware"

        # Family Prediction
        pred_family_name = "unknown"
        if self.family_rf is not None and is_ransomware:
            fam_pred = int(self.family_rf.predict(X)[0])
            pred_family_name = self.family_map.get(fam_pred, "unknown")
        elif not is_ransomware:
            pred_family_name = "goodware"

        # Explainability: Identify active features that contributed most
        active_indices = np.where(X[0] > 0)[0]
        feature_impacts = []
        for idx in active_indices:
            weight = float(self.lr_coefs[idx])
            feature_impacts.append({
                "feature_name": self.feature_names[idx],
                "weight": weight,
                "indicates": "ransomware" if weight > 0 else "goodware",
            })

        # Sort: for ransomware, sort by highest positive weight; for goodware, lowest negative weight
        if is_ransomware:
            feature_impacts.sort(key=lambda x: x["weight"], reverse=True)
        else:
            feature_impacts.sort(key=lambda x: x["weight"])

        return {
            "verdict": verdict,
            "is_ransomware": is_ransomware,
            "ransomware_probability": prob_ransomware,
            "confidence": confidence,
            "predicted_type": pred_type_name,
            "predicted_family": pred_family_name,
            "active_features_count": int(len(active_indices)),
            "top_contributing_features": feature_impacts[:8],
        }

    def triage_sample_id(self, sample_id: str, loader: Optional[MLRanLoader] = None) -> Dict[str, Any]:
        """Looks up a sample in MLRan by ID and runs triage."""
        if loader is None:
            loader = MLRanLoader()

        sample = loader.get_sample_by_id(sample_id)
        if sample is None:
            raise ValueError(f"Sample ID '{sample_id}' not found in MLRan dataset.")

        result = self.predict(sample["feature_vector"])
        result["sample_id"] = sample_id
        result["ground_truth"] = {
            "sample_type": "RANSOMWARE" if sample["sample_type"] == 1 else "GOODWARE",
            "family": sample["family_name"],
            "type": sample["type_name"],
        }
        return result


def print_triage_report(result: Dict[str, Any]):
    """Pretty prints triage evaluation to terminal."""
    verdict = result["verdict"]
    color = "\033[91m" if verdict == "RANSOMWARE" else "\033[92m"
    reset = "\033[0m"

    print("\n" + "=" * 70)
    print(" RANSOMSHIELD TIER 1: PRE-EXECUTION TRIAGE REPORT")
    print("=" * 70)
    if "sample_id" in result:
        print(f" Sample ID:            {result['sample_id']}")
    print(f" AI Classification:    {color}{verdict}{reset} (Confidence: {result['confidence']*100:.1f}%)")
    print(f" Ransomware Probability: {result['ransomware_probability']*100:.1f}%")

    if result.get("is_ransomware"):
        print(f" Predicted Type:       {result.get('predicted_type', 'N/A').upper()}")
        print(f" Predicted Family:     {result.get('predicted_family', 'N/A').title()}")

    if "ground_truth" in result:
        gt = result["ground_truth"]
        match = "MATCH (CORRECT)" if gt["sample_type"] == verdict else "MISMATCH"
        print(f" Ground Truth:         {gt['sample_type']} ({gt['family']}, {gt['type']}) -> {match}")

    print(f"\n Active Behavioral Traits: {result['active_features_count']} present")
    print(" Key Deciding Features (Explainable Evidence):")
    for i, feat in enumerate(result["top_contributing_features"], 1):
        ind_color = "\033[91m" if feat["indicates"] == "ransomware" else "\033[92m"
        print(f"   {i}. [{ind_color}{feat['indicates'].upper()}{reset}] {feat['feature_name']} (Weight: {feat['weight']:+.3f})")

    print("=" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(description="RansomShield Tier 1 Triage Predictor")
    parser.add_argument("--sample-id", type=str, default="11027", help="Sample ID from MLRan to triage")
    args = parser.parse_args()

    predictor = MLRanPredictor()
    result = predictor.triage_sample_id(args.sample_id)
    print_triage_report(result)


if __name__ == "__main__":
    main()
