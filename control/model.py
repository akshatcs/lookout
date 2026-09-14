"""
model.py -- the Random Forest classifier and the baseline it must beat.

============================================================================
WHAT THIS MODEL IS
============================================================================
Fed per-source aggregate counters, a Random Forest is essentially learning a
set of thresholds and how to combine them. It is not doing anything mystical.

So this module ships BOTH:

  * RandomForestDetector  -- the trained model
  * ThresholdDetector     -- a hand-tuned static-threshold classifier

============================================================================
WHY RANDOM FOREST AND NOT SOMETHING BIGGER
============================================================================
  * It is interpretable. feature_importances_ tells us WHICH signal drove a
    decision, so we can sanity-check that it learned something sensible
    rather than an artefact of how we generated traffic. A neural net gives
    us no such handle, and for a security control that matters.
  * It needs no feature scaling. Trees split on raw values, so pps in the
    millions and ratios in [0,1] coexist without normalisation -- one entire
    category of preprocessing bug removed.
  * It is tiny and fast. 40 trees of depth 8 is a few hundred KB and predicts
    a few hundred rows in well under a millisecond, so the 1 Hz control loop
    never becomes the bottleneck.
  * It handles the class imbalance and the non-linear interactions
    ("high pps is fine IF packets are large AND the source is old") that a
    single threshold cannot express.

============================================================================
RUNNING WITHOUT scikit-learn
============================================================================
scikit-learn is an optional dependency. If it is missing, or no trained model
file exists, the control plane automatically falls back to ThresholdDetector
and says so. The firewall is never dependent on the ML component -- that is
the whole point of making it the stretch goal.
"""

import json
import os

from . import schema

# scikit-learn is optional. Import lazily and degrade gracefully.
try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import (accuracy_score, classification_report,
                                 confusion_matrix, precision_recall_fscore_support)
    from sklearn.model_selection import train_test_split
    import joblib
    SKLEARN_AVAILABLE = True
    SKLEARN_ERROR = None
except ImportError as e:  # pragma: no cover
    SKLEARN_AVAILABLE = False
    SKLEARN_ERROR = str(e)

DEFAULT_MODEL_PATH = "models/rf_model.joblib"

LABEL_BENIGN = 0
LABEL_MALICIOUS = 1


# ===========================================================================
# Baseline: static thresholds
# ===========================================================================

class ThresholdDetector:
    """Hand-tuned rules. The control group for the whole ML experiment.

    Deliberately written the way a competent engineer would write it WITHOUT
    machine learning, so the comparison is fair. These are not strawman
    thresholds -- they encode the same domain knowledge the model is being
    asked to learn.
    """

    name = "threshold-baseline"

    def __init__(self, pps_limit=8000.0, syn_ratio_limit=0.85,
                 syn_fin_limit=40.0, scan_ports=24, small_pkt=100):
        self.pps_limit = pps_limit
        self.syn_ratio_limit = syn_ratio_limit
        self.syn_fin_limit = syn_fin_limit
        self.scan_ports = scan_ports
        self.small_pkt = small_pkt

    def predict_one(self, row: dict):
        """Return (label, confidence, reason)."""
        # Volumetric flood: lots of packets, all tiny. The size condition
        # matters -- a legitimate bulk transfer also pushes high pps, but with
        # full-size packets.
        if row["pps"] > self.pps_limit and row["mean_len"] < 600:
            return LABEL_MALICIOUS, 0.95, "volumetric flood"

        # SYN flood: nearly every packet is a SYN and almost nothing closes.
        if (row["syn_ratio"] > self.syn_ratio_limit
                and row["syn_fin_ratio"] > self.syn_fin_limit):
            return LABEL_MALICIOUS, 0.90, "syn flood"

        # Port scan: small packets sprayed across many destination ports.
        if row["port_spread"] > self.scan_ports and row["mean_len"] < self.small_pkt:
            return LABEL_MALICIOUS, 0.85, "port scan"

        # ICMP flood.
        if row["icmp_ratio"] > 0.9 and row["pps"] > self.pps_limit / 4:
            return LABEL_MALICIOUS, 0.85, "icmp flood"

        return LABEL_BENIGN, 0.9, "benign"

    def predict(self, rows: dict):
        """rows: {ip: feature_dict} -> {ip: (label, confidence, reason)}."""
        return {ip: self.predict_one(r) for ip, r in rows.items()}

    def predict_batch(self, vectors):
        """Predict from raw vectors, for offline evaluation against the RF."""
        out = []
        for vec in vectors:
            row = dict(zip(schema.FEATURE_NAMES, vec))
            label, _, _ = self.predict_one(row)
            out.append(label)
        return out


# ===========================================================================
# The Random Forest
# ===========================================================================

class RandomForestDetector:
    """Wraps a trained sklearn RandomForestClassifier.

    Always constructed via `load()` at runtime; `train()` is used offline by
    control/train.py.
    """

    name = "random-forest"

    def __init__(self, model, feature_names, threshold=0.75, metadata=None):
        self.model = model
        self.feature_names = feature_names
        self.threshold = threshold
        self.metadata = metadata or {}

    # -- loading -----------------------------------------------------------

    @classmethod
    def load(cls, path=DEFAULT_MODEL_PATH, threshold=0.75):
        if not SKLEARN_AVAILABLE:
            raise RuntimeError(
                f"scikit-learn is not installed ({SKLEARN_ERROR}).\n"
                f"Install it with:  pip install scikit-learn joblib numpy\n"
                f"Or run the controller with --no-ml to use the threshold "
                f"baseline."
            )
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"no trained model at {path}.\n"
                f"Train one with:  python3 -m control.train --synthetic\n"
                f"Or run the controller with --no-ml."
            )

        bundle = joblib.load(path)
        names = bundle["feature_names"]

        # Guard against silent feature reordering. If schema.FEATURE_NAMES
        # changed since training, column 3 no longer means what the trees
        # think it means, and the model produces confident nonsense. Refuse.
        if list(names) != list(schema.FEATURE_NAMES):
            raise RuntimeError(
                "feature mismatch between the trained model and the current "
                "code.\n"
                f"  model was trained on: {list(names)}\n"
                f"  code now produces   : {list(schema.FEATURE_NAMES)}\n"
                "Retrain: python3 -m control.train --synthetic"
            )

        return cls(bundle["model"], names, threshold, bundle.get("metadata"))

    # -- inference ---------------------------------------------------------

    def predict(self, rows: dict):
        """rows: {ip: feature_dict} -> {ip: (label, confidence, reason)}.

        Uses predict_proba rather than predict so we can require a confidence
        floor before acting. A forest that is 51% sure should not get an IP
        blocked; `threshold` (default 0.75) is how sure it has to be.
        """
        if not rows:
            return {}

        from .features import to_matrix
        ips, vectors = to_matrix(rows)
        probs = self.model.predict_proba(np.array(vectors, dtype=np.float64))

        # Locate the malicious column explicitly. If a training set happened
        # to contain only one class, classes_ has one entry and assuming
        # index 1 would read past the end.
        classes = list(self.model.classes_)
        if LABEL_MALICIOUS not in classes:
            return {ip: (LABEL_BENIGN, 1.0, "model saw no malicious class")
                    for ip in ips}
        mal_col = classes.index(LABEL_MALICIOUS)

        out = {}
        for ip, prob_row in zip(ips, probs):
            p = float(prob_row[mal_col])
            if p >= self.threshold:
                out[ip] = (LABEL_MALICIOUS, p, self._explain(rows[ip]))
            else:
                out[ip] = (LABEL_BENIGN, 1.0 - p, "benign")
        return out

    def _explain(self, row: dict) -> str:
        """A short human-readable reason for the verdict.

        The forest does not produce this; we derive it by naming whichever
        feature is most anomalous. It is a presentation aid, not ground truth
        about the model's internal decision path -- say so if asked. Its real
        value is that it makes the live display readable during the demo.
        """
        signals = []
        if row["syn_ratio"] > 0.8 and row["syn_fin_ratio"] > 20:
            signals.append("syn-flood shape")
        if row["port_spread"] > 20:
            signals.append(f"{int(row['port_spread'])} ports")
        if row["pps"] > 5000:
            signals.append(f"{int(row['pps'])} pps")
        if row["mean_len"] < 100:
            signals.append(f"{int(row['mean_len'])}B pkts")
        if row["icmp_ratio"] > 0.9:
            signals.append("all-icmp")
        if row["udp_ratio"] > 0.9 and row["pps"] > 2000:
            signals.append("udp flood")
        return ", ".join(signals) if signals else "model verdict"

    def feature_importances(self):
        """[(feature_name, importance)] sorted high to low.

        It is the single best evidence that the
        model learned something meaningful rather than an artefact of how the
        training traffic was generated. If `age_s` dominates, for example, the
        model has learned "new sources are attacks".
        """
        pairs = zip(self.feature_names, self.model.feature_importances_)
        return sorted(pairs, key=lambda kv: kv[1], reverse=True)


# ===========================================================================
# Training (called by control/train.py)
# ===========================================================================

def train_model(X, y, n_estimators=40, max_depth=8, test_size=0.25, seed=42):
    """Fit a forest and return (detector_bundle, metrics_dict).

    Hyperparameters are deliberately small. With eleven features and a few
    thousand rows, a bigger forest gains nothing measurable and costs memory
    and inference time. `class_weight="balanced"` matters because captured
    data is usually mostly benign, and an unweighted forest can score 95%
    accuracy by predicting "benign" for everything.
    """
    if not SKLEARN_AVAILABLE:
        raise RuntimeError(f"scikit-learn is required to train: {SKLEARN_ERROR}")

    X = np.asarray(X, dtype=np.float64)
    y = np.asarray(y, dtype=np.int64)

    # Stratify so both splits keep the same benign/malicious proportion.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=seed, stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        class_weight="balanced",
        min_samples_leaf=2,
        random_state=seed,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)

    # Evaluate the static baseline on the SAME test split. Same data, same
    # metric, no excuses -- this is the comparison that might be worth noting.
    baseline = ThresholdDetector()
    y_base = baseline.predict_batch(X_test.tolist())

    prec, rec, f1, _ = precision_recall_fscore_support(
        y_test, y_pred, average="binary", zero_division=0
    )
    bprec, brec, bf1, _ = precision_recall_fscore_support(
        y_test, y_base, average="binary", zero_division=0
    )

    metrics = {
        "n_samples": int(len(y)),
        "n_train": int(len(y_train)),
        "n_test": int(len(y_test)),
        "n_malicious": int((y == LABEL_MALICIOUS).sum()),
        "n_benign": int((y == LABEL_BENIGN).sum()),
        "rf": {
            "accuracy": float(accuracy_score(y_test, y_pred)),
            "precision": float(prec),
            "recall": float(rec),
            "f1": float(f1),
            "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
            "report": classification_report(
                y_test, y_pred, target_names=["benign", "malicious"],
                zero_division=0
            ),
        },
        "baseline": {
            "accuracy": float(accuracy_score(y_test, y_base)),
            "precision": float(bprec),
            "recall": float(brec),
            "f1": float(bf1),
            "confusion_matrix": confusion_matrix(y_test, y_base).tolist(),
        },
        "feature_importances": sorted(
            zip(schema.FEATURE_NAMES, [float(v) for v in clf.feature_importances_]),
            key=lambda kv: kv[1], reverse=True
        ),
    }

    bundle = {
        "model": clf,
        "feature_names": list(schema.FEATURE_NAMES),
        "metadata": {
            "n_estimators": n_estimators,
            "max_depth": max_depth,
            "metrics": {k: v for k, v in metrics.items() if k != "rf"},
        },
    }
    return bundle, metrics


def save_model(bundle, path=DEFAULT_MODEL_PATH):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    joblib.dump(bundle, path)
    return path


def save_metrics(metrics, path="models/metrics.json"):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    serialisable = {k: v for k, v in metrics.items()}
    serialisable["rf"] = {k: v for k, v in metrics["rf"].items() if k != "report"}
    with open(path, "w") as f:
        json.dump(serialisable, f, indent=2)
    return path


def get_detector(model_path=DEFAULT_MODEL_PATH, use_ml=True, threshold=0.75):
    """Return the best available detector, plus a note about what happened.

    This is the function the controller calls. It never raises -- if anything
    is missing it falls back to the threshold baseline and reports why, so a
    missing model file degrades the demo rather than breaking it.
    """
    if not use_ml:
        return ThresholdDetector(), "ML disabled (--no-ml): using thresholds"
    if not SKLEARN_AVAILABLE:
        return ThresholdDetector(), (
            "scikit-learn not installed: falling back to thresholds"
        )
    try:
        det = RandomForestDetector.load(model_path, threshold=threshold)
        n = len(det.model.estimators_)
        return det, f"loaded Random Forest ({n} trees) from {model_path}"
    except (FileNotFoundError, RuntimeError) as e:
        first_line = str(e).strip().split("\n")[0]
        return ThresholdDetector(), f"{first_line} -- falling back to thresholds"
