"""
MLRan Dataset Loader for RansomShield (Tier 1 Pre-Execution Triage).

Loads and formats the real-world MLRan dataset (JNCA 2026):
- 4,880 samples (2,330 ransomware spanning 64 families, 2,550 goodware across 11 categories)
- 483 RFE-selected behavioral and structural features
- Supports binary, ransomware type, and family classification tasks.
"""

import os
import csv
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
import numpy as np


class MLRanLoader:
    def __init__(self, dataset_dir: Optional[Path] = None):
        if dataset_dir is None:
            # Locate relative to project root
            self.dataset_dir = Path(__file__).resolve().parent.parent / "datasets" / "MLRan"
        else:
            self.dataset_dir = Path(dataset_dir)

        if not self.dataset_dir.exists():
            raise FileNotFoundError(f"MLRan dataset directory not found at: {self.dataset_dir}")

        self.train_csv = self.dataset_dir / "MLRan_X_train_RFE.csv"
        self.test_csv = self.dataset_dir / "MLRan_X_test_RFE.csv"
        self.dict_json = self.dataset_dir / "RFE_selected_feature_names_dic.json"
        self.meta_csv = self.dataset_dir / "mlran_dataset_metadata.csv"

        self.feature_names_map: Dict[str, str] = {}
        self.family_map: Dict[int, str] = {}
        self.type_map: Dict[int, str] = {
            0: "goodware",
            1: "locker",
            2: "crypto",
            3: "raas",
            4: "modern",
        }
        self.feature_col_ids: List[str] = []

        self._load_metadata()

    def _load_metadata(self):
        """Loads feature dictionary and family/type mappings."""
        # Load feature name dictionary
        if self.dict_json.exists():
            with open(self.dict_json, "r", encoding="utf-8") as f:
                self.feature_names_map = json.load(f)

        # Load family mappings from metadata CSV
        if self.meta_csv.exists():
            with open(self.meta_csv, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    try:
                        fl = int(row.get("family_label", -1))
                        fn = row.get("ransomware_family", "").strip()
                        if fl >= 0 and fn and fl not in self.family_map:
                            self.family_map[fl] = fn
                    except ValueError:
                        continue
        self.family_map[0] = "goodware"

    def _read_matrix(self, csv_path: Path) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, List[str]]:
        """
        Reads CSV and parses into (X, y_binary, y_type, y_family, sample_ids).
        Columns: [sample_id, sample_type, family_label, type_label, <483 features>]
        """
        sample_ids = []
        y_binary = []
        y_family = []
        y_type = []
        x_rows = []

        with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            header = next(reader)
            if not self.feature_col_ids:
                self.feature_col_ids = header[4:]

            for row in reader:
                if not row:
                    continue
                sample_ids.append(row[0])
                y_binary.append(int(float(row[1])))
                y_family.append(int(float(row[2])))
                y_type.append(int(float(row[3])))
                x_rows.append([float(val) for val in row[4:]])

        X = np.array(x_rows, dtype=np.float32)
        y_bin = np.array(y_binary, dtype=np.int32)
        y_fam = np.array(y_family, dtype=np.int32)
        y_typ = np.array(y_type, dtype=np.int32)

        return X, y_bin, y_typ, y_fam, sample_ids

    def load_train_data(self) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, List[str]]:
        """Returns (X_train, y_train_binary, y_train_type, y_train_family, sample_ids)."""
        return self._read_matrix(self.train_csv)

    def load_test_data(self) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, List[str]]:
        """Returns (X_test, y_test_binary, y_test_type, y_test_family, sample_ids)."""
        return self._read_matrix(self.test_csv)

    def get_feature_name(self, col_id: str) -> str:
        """Returns the human-readable feature name for a column ID."""
        return self.feature_names_map.get(col_id, f"Feature_{col_id}")

    def get_all_feature_names(self) -> List[str]:
        """Returns human-readable names for all 483 feature columns."""
        if not self.feature_col_ids and self.train_csv.exists():
            with open(self.train_csv, "r", encoding="utf-8") as f:
                header = next(csv.reader(f))
                self.feature_col_ids = header[4:]
        return [self.get_feature_name(col_id) for col_id in self.feature_col_ids]

    def get_sample_by_id(self, sample_id: str) -> Optional[Dict[str, Any]]:
        """Searches test and train CSVs for a specific sample_id."""
        for target_csv in [self.test_csv, self.train_csv]:
            with open(target_csv, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.reader(f)
                header = next(reader)
                for row in reader:
                    if row and row[0] == str(sample_id):
                        features = {self.get_feature_name(header[i]): float(row[i]) for i in range(4, len(row))}
                        active_features = [name for name, val in features.items() if val > 0]
                        return {
                            "sample_id": row[0],
                            "sample_type": int(float(row[1])),
                            "family_label": int(float(row[2])),
                            "family_name": self.family_map.get(int(float(row[2])), "unknown"),
                            "type_label": int(float(row[3])),
                            "type_name": self.type_map.get(int(float(row[3])), "unknown"),
                            "feature_vector": np.array([float(x) for x in row[4:]], dtype=np.float32),
                            "active_features_count": len(active_features),
                            "active_features": active_features,
                        }
        return None


if __name__ == "__main__":
    loader = MLRanLoader()
    print("Loading MLRan training and testing datasets...")
    X_tr, y_bin_tr, y_typ_tr, y_fam_tr, ids_tr = loader.load_train_data()
    X_te, y_bin_te, y_typ_te, y_fam_te, ids_te = loader.load_test_data()

    print(f"[+] Train Matrix: {X_tr.shape} (Goodware: {np.sum(y_bin_tr == 0)}, Ransomware: {np.sum(y_bin_tr == 1)})")
    print(f"[+] Test Matrix:  {X_te.shape} (Goodware: {np.sum(y_bin_te == 0)}, Ransomware: {np.sum(y_bin_te == 1)})")
    print(f"[+] Total Features: {len(loader.get_all_feature_names())}")
    print(f"[+] Sample Features: {loader.get_all_feature_names()[:4]}")

    sample = loader.get_sample_by_id("11027")
    if sample:
        print(f"[+] Sample 11027 Lookup: Family='{sample['family_name']}', Type='{sample['type_name']}', Active Features={sample['active_features_count']}")
        print(f"    Top Active: {sample['active_features'][:3]}")
