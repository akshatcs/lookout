"""
train.py -- fit the Random Forest and evaluate it against the baseline.

    # quickest path to a working model (no testbed needed)
    python3 -m control.train --synthetic

    # train on traffic we actually captured with control.collect
    python3 -m control.train --csv data/benign.csv data/attack.csv

    # both: synthetic data padded out with real captures
    python3 -m control.train --synthetic --csv data/*.csv

Everything it prints is material for the summary. The three things worth
copying into the write-up are the confusion matrix, the feature importance
table, and the per-class recall breakdown -- that last one is what shows
whether the model beat the threshold baseline anywhere that matters.
"""

import argparse
import csv
import os
import sys

from . import schema, synth
from .model import (DEFAULT_MODEL_PATH, LABEL_BENIGN, LABEL_MALICIOUS,
                    SKLEARN_AVAILABLE, SKLEARN_ERROR, ThresholdDetector,
                    save_metrics, save_model, train_model)

BOLD, DIM, GREEN, YELLOW, RESET = (
    "\033[1m", "\033[2m", "\033[32m", "\033[33m", "\033[0m"
)


def load_csv(paths):
    """Read feature CSVs written by control.collect.

    Expected columns: the eleven names in schema.FEATURE_NAMES, plus `label`
    (0 or 1) and optionally `class` (a free-text traffic class used only for
    the per-class breakdown).
    """
    X, y, names = [], [], []
    for path in paths:
        if not os.path.exists(path):
            print(f"{YELLOW}warning: {path} does not exist, skipping{RESET}")
            continue
        with open(path, newline="") as f:
            reader = csv.DictReader(f)
            missing = [c for c in schema.FEATURE_NAMES
                       if c not in (reader.fieldnames or [])]
            if missing:
                print(f"{YELLOW}warning: {path} is missing columns "
                      f"{missing}, skipping{RESET}")
                continue
            n = 0
            for row in reader:
                try:
                    X.append([float(row[c]) for c in schema.FEATURE_NAMES])
                    y.append(int(row["label"]))
                    names.append(row.get("class", "captured"))
                    n += 1
                except (ValueError, KeyError):
                    continue  # skip malformed lines rather than dying
            print(f"  loaded {n:>6} rows from {path}")
    return X, y, names


def per_class_recall(detector_preds, y_true, class_names):
    """Recall per traffic class. The most informative table.

    An aggregate recall of 0.97 can hide the fact that the model catches every
    volumetric flood and misses every low-and-slow attack. This breaks it out
    so we can see exactly where each detector succeeds and fails.
    """
    buckets = {}
    for pred, truth, cname in zip(detector_preds, y_true, class_names):
        if truth != LABEL_MALICIOUS:
            continue
        hit, total = buckets.get(cname, (0, 0))
        buckets[cname] = (hit + (1 if pred == LABEL_MALICIOUS else 0), total + 1)
    return {k: (h / t if t else 0.0, t) for k, (h, t) in buckets.items()}


def false_positive_rate_by_class(preds, y_true, class_names):
    """How often each BENIGN class is wrongly flagged.

    Watch `bulk` and `game` here: those are the hard negatives, designed to
    look like attacks to a naive threshold. A detector that flags them is one
    that would break real services.
    """
    buckets = {}
    for pred, truth, cname in zip(preds, y_true, class_names):
        if truth != LABEL_BENIGN:
            continue
        bad, total = buckets.get(cname, (0, 0))
        buckets[cname] = (bad + (1 if pred == LABEL_MALICIOUS else 0), total + 1)
    return {k: (b / t if t else 0.0, t) for k, (b, t) in buckets.items()}


def main(argv=None):
    p = argparse.ArgumentParser(prog="control.train")
    p.add_argument("--synthetic", action="store_true",
                   help="include generated training data")
    p.add_argument("--n-synthetic", type=int, default=6000)
    p.add_argument("--csv", nargs="*", default=[],
                   help="captured feature CSVs from control.collect")
    p.add_argument("--out", default=DEFAULT_MODEL_PATH)
    p.add_argument("--metrics", default="models/metrics.json")
    p.add_argument("--trees", type=int, default=40)
    p.add_argument("--depth", type=int, default=8)
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args(argv)

    if not SKLEARN_AVAILABLE:
        print(f"error: scikit-learn is required for training ({SKLEARN_ERROR})",
              file=sys.stderr)
        print("  pip install scikit-learn joblib numpy", file=sys.stderr)
        return 1

    X, y, names = [], [], []

    if args.csv:
        print(f"{BOLD}loading captured data{RESET}")
        cx, cy, cn = load_csv(args.csv)
        X += cx; y += cy; names += cn

    if args.synthetic or not X:
        if not args.synthetic:
            print(f"{YELLOW}no usable CSV data; falling back to synthetic"
                  f"{RESET}")
        print(f"{BOLD}generating {args.n_synthetic} synthetic rows{RESET}")
        sx, sy, sn = synth.generate(n=args.n_synthetic, seed=args.seed)
        X += sx; y += sy; names += sn

    if len(set(y)) < 2:
        print("error: training data contains only one class. You need both "
              "benign and attack captures.", file=sys.stderr)
        return 1

    n_mal = sum(1 for v in y if v == LABEL_MALICIOUS)
    print(f"\n{BOLD}dataset{RESET}: {len(y)} rows "
          f"({n_mal} malicious, {len(y) - n_mal} benign)")

    print(f"{BOLD}training{RESET}: RandomForest("
          f"n_estimators={args.trees}, max_depth={args.depth}, "
          f"class_weight=balanced)")
    bundle, metrics = train_model(
        X, y, n_estimators=args.trees, max_depth=args.depth, seed=args.seed
    )

    rf, base = metrics["rf"], metrics["baseline"]

    print(f"\n{BOLD}=== held-out test set ({metrics['n_test']} rows) ==={RESET}")
    print(f"{'':<22}{'accuracy':>10}{'precision':>11}{'recall':>9}{'f1':>8}")
    print(f"{'Random Forest':<22}{rf['accuracy']:>10.4f}"
          f"{rf['precision']:>11.4f}{rf['recall']:>9.4f}{rf['f1']:>8.4f}")
    print(f"{'threshold baseline':<22}{base['accuracy']:>10.4f}"
          f"{base['precision']:>11.4f}{base['recall']:>9.4f}{base['f1']:>8.4f}")

    delta = rf["f1"] - base["f1"]
    if delta > 0.01:
        print(f"\n{GREEN}The forest beats the baseline by {delta:+.4f} F1."
              f"{RESET}")
    elif delta < -0.01:
        print(f"\n{YELLOW}The baseline beats the forest by {-delta:.4f} F1. "
              f"It is a legitimate finding, and it "
              f"usually means our attack classes are all trivially "
              f"separable by packet rate.{RESET}")
    else:
        print(f"\n{YELLOW}The forest and the baseline are within 0.01 F1. "
              f"Look at the per-class table below to see where they actually "
              f"differ.{RESET}")

    print(f"\n{BOLD}confusion matrix (Random Forest){RESET}")
    (tn, fp), (fn, tp) = rf["confusion_matrix"]
    print(f"                  predicted benign   predicted malicious")
    print(f"  actual benign    {tn:>14}   {fp:>19}")
    print(f"  actual malicious {fn:>14}   {tp:>19}")
    print(f"  {DIM}false positives cost you legitimate users; "
          f"false negatives cost you the attack.{RESET}")

    print(f"\n{BOLD}feature importances{RESET}")
    for name, imp in metrics["feature_importances"]:
        bar = "#" * int(round(imp * 60))
        print(f"  {name:<16}{imp:>7.4f}  {bar}")

    # --- the table that actually answers "what did the ML buy us" ---
    import numpy as np
    from sklearn.model_selection import train_test_split
    Xa, ya = np.asarray(X, dtype=np.float64), np.asarray(y)
    na = np.asarray(names)
    _, X_test, _, y_test, _, n_test = train_test_split(
        Xa, ya, na, test_size=0.25, random_state=args.seed, stratify=ya
    )
    rf_pred = bundle["model"].predict(X_test)
    base_pred = ThresholdDetector().predict_batch(X_test.tolist())

    rf_rec = per_class_recall(rf_pred, y_test, n_test)
    base_rec = per_class_recall(base_pred, y_test, n_test)

    if rf_rec:
        print(f"\n{BOLD}recall per attack class "
              f"(the key comparison for the summary){RESET}")
        print(f"  {'class':<16}{'n':>6}{'forest':>10}{'baseline':>11}"
              f"{'delta':>9}")
        for cname in sorted(rf_rec):
            r_rf, n = rf_rec[cname]
            r_b = base_rec.get(cname, (0.0, 0))[0]
            d = r_rf - r_b
            mark = GREEN if d > 0.02 else (YELLOW if d < -0.02 else DIM)
            print(f"  {cname:<16}{n:>6}{r_rf:>10.3f}{r_b:>11.3f}"
                  f"  {mark}{d:>+7.3f}{RESET}")

    rf_fp = false_positive_rate_by_class(rf_pred, y_test, n_test)
    base_fp = false_positive_rate_by_class(base_pred, y_test, n_test)
    if rf_fp:
        print(f"\n{BOLD}false-positive rate per benign class{RESET} "
              f"{DIM}(lower is better; 'bulk' and 'game' are the hard "
              f"negatives){RESET}")
        print(f"  {'class':<16}{'n':>6}{'forest':>10}{'baseline':>11}")
        for cname in sorted(rf_fp):
            f_rf, n = rf_fp[cname]
            f_b = base_fp.get(cname, (0.0, 0))[0]
            print(f"  {cname:<16}{n:>6}{f_rf:>10.3f}{f_b:>11.3f}")

    path = save_model(bundle, args.out)
    mpath = save_metrics(metrics, args.metrics)
    size_kb = os.path.getsize(path) / 1024
    print(f"\n{GREEN}saved model{RESET}  {path}  ({size_kb:.0f} KB)")
    print(f"{GREEN}saved metrics{RESET} {mpath}")
    print(f"\nRun it:  sudo python3 -m control.controller --dry-run")
    return 0


if __name__ == "__main__":
    sys.exit(main())
