"""
generate_paper_tables.py — Automated Statistical Aggregation for TriAnSec Research Paper.

Reads multiple simulation runs across systems (TriAnSec vs Baseline vs Ablations),
computes Mean +/- Standard Deviation, and outputs publication-ready LaTeX & Markdown tables:
  - Table 1: Core Security Classification Metrics (FPR, Recall, Precision, F1)
  - Table 2: Fast-Path Latency Overhead Breakdown (P50, P90, P95, P99, Mean)
  - Table 3: Latency Decoupling (Fast-Path Decision vs Client RTT & Security Overhead %)
  - Table 4: Progressive Enforcement Distribution (% ALLOW, THROTTLE, BLOCK per User Class)
  - Table 5: Multi-Signal Identity Resolution & IP Rotation Resilience

Usage:
    python scripts/generate_paper_tables.py
    python scripts/generate_paper_tables.py --dir evidence/
"""

import os
import sys
import glob
import argparse
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple

# Ensure UTF-8 output encoding on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


def evaluate_run(csv_path: str) -> Dict[str, float]:
    """Computes comprehensive academic metrics for a single simulation CSV."""
    df = pd.read_csv(csv_path)

    # Coerce numeric types
    df["status_code"] = pd.to_numeric(df["status_code"], errors="coerce")
    df["latency_ms"] = pd.to_numeric(df["latency_ms"], errors="coerce")
    
    fp_col = None
    for candidate in ["fast_path_latency_ms", "middleware_latency_ms"]:
        if candidate in df.columns and df[candidate].notna().sum() > 0:
            df[candidate] = pd.to_numeric(df[candidate], errors="coerce")
            fp_col = candidate
            break

    if "client_rtt_ms" in df.columns:
        df["client_rtt_ms"] = pd.to_numeric(df["client_rtt_ms"], errors="coerce")

    # Enforcement actions: BLOCK, THROTTLE, or RATE_LIMIT (HTTP 429)
    enforcement_actions = {"BLOCK", "THROTTLE", "RATE_LIMIT"}

    normal_df = df[df["user_type"] == "normal"]
    minbad_df = df[df["user_type"] == "minimal_bad"]
    susp_df = df[df["user_type"] == "suspicious"]
    bad_df = df[df["user_type"] == "real_bad"]
    all_abusive_df = df[df["user_type"].isin(["real_bad", "suspicious"])]

    # 1. False Positive Rate on legitimate normal traffic
    normal_total = len(normal_df)
    normal_enforced = normal_df["decision"].isin(enforcement_actions).sum()
    fpr = (normal_enforced / normal_total * 100.0) if normal_total > 0 else 0.0

    # 2. Recall (Detection Rate) on real_bad traffic
    bad_total = len(bad_df)
    bad_enforced = bad_df["decision"].isin(enforcement_actions).sum()
    recall_real_bad = (bad_enforced / bad_total * 100.0) if bad_total > 0 else 0.0

    # 3. Overall Detection Rate across all abusive traffic (real_bad + suspicious)
    abusive_total = len(all_abusive_df)
    abusive_enforced = all_abusive_df["decision"].isin(enforcement_actions).sum()
    recall_all_abusive = (abusive_enforced / abusive_total * 100.0) if abusive_total > 0 else 0.0

    # 4. Precision (TP / (TP + FP))
    tp = bad_enforced
    fp = normal_enforced
    precision = (tp / (tp + fp) * 100.0) if (tp + fp) > 0 else 100.0

    # 5. F1-Score
    prec_ratio = precision / 100.0
    rec_ratio = recall_real_bad / 100.0
    f1 = (2 * prec_ratio * rec_ratio / (prec_ratio + rec_ratio)) if (prec_ratio + rec_ratio) > 0 else 0.0

    # 6. Fast-Path Latency (Isolated decision time)
    if fp_col:
        fp_series = df[fp_col].dropna()
    elif "latency_ms" in df.columns and df["latency_ms"].notna().sum() > 0:
        fp_series = df["latency_ms"].dropna()
    else:
        fp_series = pd.Series(dtype=float)

    if len(fp_series) > 0:
        p50_fp = float(fp_series.quantile(0.50))
        p90_fp = float(fp_series.quantile(0.90))
        p95_fp = float(fp_series.quantile(0.95))
        p99_fp = float(fp_series.quantile(0.99))
        mean_fp = float(fp_series.mean())
    else:
        p50_fp = p90_fp = p95_fp = p99_fp = mean_fp = np.nan

    # 7. Client RTT Latency (Network + Client Transport)
    if "client_rtt_ms" in df.columns and df["client_rtt_ms"].notna().sum() > 0:
        rtt_series = df["client_rtt_ms"].dropna()
        p50_rtt = float(rtt_series.quantile(0.50))
        p95_rtt = float(rtt_series.quantile(0.95))
        mean_rtt = float(rtt_series.mean())
    else:
        p50_rtt = p95_rtt = mean_rtt = np.nan

    # Overhead ratio: Fast path decision time vs client end-to-end round trip
    if not np.isnan(p50_fp) and not np.isnan(p50_rtt) and p50_rtt > 0:
        overhead_ratio = (p50_fp / p50_rtt) * 100.0
    else:
        overhead_ratio = np.nan

    # 8. Progressive Enforcement Breakdown (% ALLOW, % THROTTLE, % BLOCK per user class)
    def calc_action_distribution(sub_df):
        tot = len(sub_df)
        if tot == 0:
            return np.nan, np.nan, np.nan
        allow = (sub_df["decision"] == "ALLOW").sum() / tot * 100.0
        throttle = (sub_df["decision"] == "THROTTLE").sum() / tot * 100.0
        block = (sub_df["decision"].isin(["BLOCK", "RATE_LIMIT"])).sum() / tot * 100.0
        return allow, throttle, block

    norm_allow, norm_thr, norm_blk = calc_action_distribution(normal_df)
    minb_allow, minb_thr, minb_blk = calc_action_distribution(minbad_df)
    susp_allow, susp_thr, susp_blk = calc_action_distribution(susp_df)
    bad_allow, bad_thr, bad_blk = calc_action_distribution(bad_df)

    # 9. Multi-Signal Identity Tracking & IP Rotation Invariant
    user_ips = df.groupby("user_id")["ip"].nunique()
    total_rotations = (user_ips - 1).clip(lower=0).sum()

    sticky_users = df[df["user_type"].isin(["normal", "minimal_bad"])]
    sticky_ips = sticky_users.groupby("user_id")["ip"].nunique()
    sticky_violations = (sticky_ips > 1).sum()

    rotating_bad = df[df["user_type"].isin(["real_bad", "suspicious"])]
    if len(rotating_bad) > 0:
        rot_bad_enforced = rotating_bad["decision"].isin(enforcement_actions).sum()
        rot_bad_recall = (rot_bad_enforced / len(rotating_bad)) * 100.0
    else:
        rot_bad_recall = np.nan

    # 10. Attack Endpoint Targeting Recall
    attack_mask = df["endpoint"].astype(str).str.contains(r"admin|export|per_page=1000|limit=99999", case=False, regex=True)
    attack_df = df[attack_mask]
    if len(attack_df) > 0:
        attack_detected = attack_df["decision"].isin(enforcement_actions).sum()
        attack_recall = (attack_detected / len(attack_df)) * 100.0
    else:
        attack_recall = np.nan

    # 11. Throughput & Elapsed Duration
    if "elapsed_s" in df.columns and len(df["elapsed_s"].dropna()) > 1:
        duration_s = float(df["elapsed_s"].max() - df["elapsed_s"].min())
        throughput_rps = (len(df) / duration_s) if duration_s > 0 else np.nan
    else:
        duration_s = np.nan
        throughput_rps = np.nan

    return {
        "total_requests": len(df),
        "fpr": fpr,
        "recall_real_bad": recall_real_bad,
        "recall_all_abusive": recall_all_abusive,
        "precision": precision,
        "f1": f1,
        "p50_fast_path": p50_fp,
        "p90_fast_path": p90_fp,
        "p95_fast_path": p95_fp,
        "p99_fast_path": p99_fp,
        "mean_fast_path": mean_fp,
        "p50_client_rtt": p50_rtt,
        "p95_client_rtt": p95_rtt,
        "mean_client_rtt": mean_rtt,
        "overhead_ratio": overhead_ratio,
        "normal_allow": norm_allow,
        "normal_throttle": norm_thr,
        "normal_block": norm_blk,
        "minbad_allow": minb_allow,
        "minbad_throttle": minb_thr,
        "minbad_block": minb_blk,
        "susp_allow": susp_allow,
        "susp_throttle": susp_thr,
        "susp_block": susp_blk,
        "bad_allow": bad_allow,
        "bad_throttle": bad_thr,
        "bad_block": bad_blk,
        "total_rotations": total_rotations,
        "sticky_violations": sticky_violations,
        "rot_bad_recall": rot_bad_recall,
        "attack_recall": attack_recall,
        "duration_s": duration_s,
        "throughput_rps": throughput_rps,
    }


def aggregate_group(runs: List[Dict[str, float]]) -> Dict[str, Tuple[float, float]]:
    """Calculates Mean and Standard Deviation across runs."""
    if not runs:
        return {}
    keys = runs[0].keys()
    agg = {}
    for k in keys:
        vals = [r[k] for r in runs if not np.isnan(r[k])]
        if vals:
            agg[k] = (float(np.mean(vals)), float(np.std(vals)))
        else:
            agg[k] = (np.nan, np.nan)
    return agg


def format_stat(mean: float, std: float, unit: str = "", decimals: int = 2) -> str:
    """Formats stat as 'mean ± std unit'."""
    if np.isnan(mean):
        return "N/A"
    if std == 0.0 or np.isnan(std):
        return f"{mean:.{decimals}f}{unit}"
    return f"{mean:.{decimals}f} ± {std:.{decimals}f}{unit}"


def main():
    parser = argparse.ArgumentParser(description="Generate Research Paper Tables")
    parser.add_argument("--dir", default="evidence", help="Evidence directory containing CSVs")
    args = parser.parse_args()

    evidence_dir = args.dir

    # Group file patterns
    groups = {
        "TriAnSec (Full System)": glob.glob(os.path.join(evidence_dir, "triansec_run_*.csv")),
        "Baseline (Fixed-Window IP)": glob.glob(os.path.join(evidence_dir, "baseline_run_*.csv")),
        "Ablation A (No Client Hints)": glob.glob(os.path.join(evidence_dir, "ablation_no_hints*.csv")),
        "Ablation B (No EWMA History)": glob.glob(os.path.join(evidence_dir, "ablation_no_ewma*.csv")),
        "Ablation C (Sync Pipeline)": glob.glob(os.path.join(evidence_dir, "ablation_sync*.csv")),
    }

    # Fallback to standard run_*.csv if no prefixed files
    if not any(groups.values()):
        standard_runs = glob.glob(os.path.join(evidence_dir, "run_*.csv"))
        if standard_runs:
            print(f"ℹ️ Found {len(standard_runs)} standard run CSVs. Evaluating newest as TriAnSec run...")
            standard_runs.sort(reverse=True)
            groups["TriAnSec (Full System)"] = [standard_runs[0]]

    results = {}
    for group_name, file_list in groups.items():
        if not file_list:
            continue
        run_data = []
        print(f"\nProcessing {group_name} ({len(file_list)} runs)...")
        for f in file_list:
            print(f"  • Reading {os.path.basename(f)}")
            try:
                metrics = evaluate_run(f)
                run_data.append(metrics)
            except Exception as e:
                print(f"    ⚠️ Error evaluating {f}: {e}")
        if run_data:
            results[group_name] = aggregate_group(run_data)

    if not results:
        print("\n❌ No simulation CSV files found to evaluate.")
        print("To generate data, run the simulation:")
        print("  1. TriAnSec: python scripts/real.py -> rename evidence/run_X.csv to evidence/triansec_run_1.csv")
        print("  2. Baseline: Set ENABLE_BASELINE=1, rerun real.py -> rename to evidence/baseline_run_1.csv")
        return

    # =========================================================================
    # TABLE 1: SECURITY CLASSIFICATION METRICS
    # =========================================================================
    print("\n" + "=" * 115)
    print("RESEARCH PAPER TABLE 1: SECURITY CLASSIFICATION METRICS (Mean ± Std Dev)")
    print("=" * 115)
    headers1 = [
        f"{'System / Variant':<30}",
        f"{'FPR (Legit)':>16}",
        f"{'Recall (Bad)':>16}",
        f"{'Recall (All)':>16}",
        f"{'Precision':>16}",
        f"{'F1-Score':>14}",
    ]
    print(" | ".join(headers1))
    print("-" * 115)

    for name, stats in results.items():
        fpr_s = format_stat(stats["fpr"][0], stats["fpr"][1], "%")
        rec_s = format_stat(stats["recall_real_bad"][0], stats["recall_real_bad"][1], "%")
        rec_all_s = format_stat(stats["recall_all_abusive"][0], stats["recall_all_abusive"][1], "%")
        prec_s = format_stat(stats["precision"][0], stats["precision"][1], "%")
        f1_s = format_stat(stats["f1"][0], stats["f1"][1], decimals=3)
        row = [f"{name:<30}", f"{fpr_s:>16}", f"{rec_s:>16}", f"{rec_all_s:>16}", f"{prec_s:>16}", f"{f1_s:>14}"]
        print(" | ".join(row))

    # =========================================================================
    # TABLE 2: FAST-PATH DECISION LATENCY OVERHEAD
    # =========================================================================
    print("\n" + "=" * 115)
    print("RESEARCH PAPER TABLE 2: FAST-PATH LATENCY OVERHEAD METRICS (Mean ± Std Dev)")
    print("=" * 115)
    lat_headers = [
        f"{'System / Variant':<30}",
        f"{'P50 (ms)':>14}",
        f"{'P90 (ms)':>14}",
        f"{'P95 (ms)':>14}",
        f"{'P99 (ms)':>14}",
        f"{'Mean (ms)':>14}",
    ]
    print(" | ".join(lat_headers))
    print("-" * 115)

    for name, stats in results.items():
        p50_fp = format_stat(stats["p50_fast_path"][0], stats["p50_fast_path"][1])
        p90_fp = format_stat(stats["p90_fast_path"][0], stats["p90_fast_path"][1])
        p95_fp = format_stat(stats["p95_fast_path"][0], stats["p95_fast_path"][1])
        p99_fp = format_stat(stats["p99_fast_path"][0], stats["p99_fast_path"][1])
        mean_fp = format_stat(stats["mean_fast_path"][0], stats["mean_fast_path"][1])
        row = [f"{name:<30}", f"{p50_fp:>14}", f"{p90_fp:>14}", f"{p95_fp:>14}", f"{p99_fp:>14}", f"{mean_fp:>14}"]
        print(" | ".join(row))

    # =========================================================================
    # TABLE 3: LATENCY DECOUPLING (Fast-Path vs Client Transport RTT)
    # =========================================================================
    print("\n" + "=" * 115)
    print("RESEARCH PAPER TABLE 3: LATENCY DECOUPLING (Middleware Decision vs Client Round-Trip)")
    print("=" * 115)
    decouple_headers = [
        f"{'System / Variant':<30}",
        f"{'Fast-Path P50':>16}",
        f"{'Fast-Path P95':>16}",
        f"{'Client RTT P50':>16}",
        f"{'Client RTT P95':>16}",
        f"{'Overhead Ratio':>16}",
    ]
    print(" | ".join(decouple_headers))
    print("-" * 115)

    for name, stats in results.items():
        p50_fp = format_stat(stats["p50_fast_path"][0], stats["p50_fast_path"][1], " ms")
        p95_fp = format_stat(stats["p95_fast_path"][0], stats["p95_fast_path"][1], " ms")
        p50_rtt = format_stat(stats["p50_client_rtt"][0], stats["p50_client_rtt"][1], " ms")
        p95_rtt = format_stat(stats["p95_client_rtt"][0], stats["p95_client_rtt"][1], " ms")
        ovh_s = format_stat(stats["overhead_ratio"][0], stats["overhead_ratio"][1], "%")
        row = [f"{name:<30}", f"{p50_fp:>16}", f"{p95_fp:>16}", f"{p50_rtt:>16}", f"{p95_rtt:>16}", f"{ovh_s:>16}"]
        print(" | ".join(row))

    # =========================================================================
    # TABLE 4: PROGRESSIVE ENFORCEMENT ACTION DISTRIBUTION
    # =========================================================================
    print("\n" + "=" * 115)
    print("RESEARCH PAPER TABLE 4: PROGRESSIVE ENFORCEMENT DISTRIBUTION (% ALLOW / THROTTLE / BLOCK)")
    print("=" * 115)
    prog_headers = [
        f"{'System / Variant':<28}",
        f"{'Normal (A/T/B)':>20}",
        f"{'MinBad (A/T/B)':>20}",
        f"{'Suspicious (A/T/B)':>22}",
        f"{'RealBad (A/T/B)':>20}",
    ]
    print(" | ".join(prog_headers))
    print("-" * 115)

    for name, stats in results.items():
        n_s = f"{stats['normal_allow'][0]:.1f}% / {stats['normal_throttle'][0]:.1f}% / {stats['normal_block'][0]:.1f}%"
        m_s = f"{stats['minbad_allow'][0]:.1f}% / {stats['minbad_throttle'][0]:.1f}% / {stats['minbad_block'][0]:.1f}%"
        s_s = f"{stats['susp_allow'][0]:.1f}% / {stats['susp_throttle'][0]:.1f}% / {stats['susp_block'][0]:.1f}%"
        b_s = f"{stats['bad_allow'][0]:.1f}% / {stats['bad_throttle'][0]:.1f}% / {stats['bad_block'][0]:.1f}%"
        row = [f"{name:<28}", f"{n_s:>20}", f"{m_s:>20}", f"{s_s:>22}", f"{b_s:>20}"]
        print(" | ".join(row))

    # =========================================================================
    # TABLE 5: MULTI-SIGNAL IDENTITY TRACKING & IP ROTATION RESILIENCE
    # =========================================================================
    print("\n" + "=" * 115)
    print("RESEARCH PAPER TABLE 5: MULTI-SIGNAL IDENTITY RESOLUTION & ADVERSARIAL RESILIENCE")
    print("=" * 115)
    id_headers = [
        f"{'System / Variant':<28}",
        f"{'Total Reqs':>12}",
        f"{'IP Rotations':>14}",
        f"{'Rot-Bad Recall':>16}",
        f"{'Probe Recall':>16}",
        f"{'Throughput':>16}",
    ]
    print(" | ".join(id_headers))
    print("-" * 115)

    for name, stats in results.items():
        req_s = f"{int(stats['total_requests'][0]):,}"
        rot_s = f"{int(stats['total_rotations'][0]):,}"
        rot_rec = format_stat(stats["rot_bad_recall"][0], stats["rot_bad_recall"][1], "%")
        atk_rec = format_stat(stats["attack_recall"][0], stats["attack_recall"][1], "%")
        rps_s = format_stat(stats["throughput_rps"][0], stats["throughput_rps"][1], " req/s", decimals=1)
        row = [f"{name:<28}", f"{req_s:>12}", f"{rot_s:>14}", f"{rot_rec:>16}", f"{atk_rec:>16}", f"{rps_s:>16}"]
        print(" | ".join(row))

    # =========================================================================
    # EXPORT PUBLICATION-READY LATEX CODE
    # =========================================================================
    latex_path = os.path.join(evidence_dir, "latex_tables.tex")
    with open(latex_path, "w", encoding="utf-8") as f:
        # Table I
        f.write("% =========================================================\n")
        f.write("% Table I: Classification Performance Comparison\n")
        f.write("% =========================================================\n")
        f.write("\\begin{table}[htbp]\n\\centering\n")
        f.write("\\caption{Security Performance Comparison across Rate Limiting Architectures (Mean $\\pm$ Std Dev)}\n")
        f.write("\\label{tab:security_metrics}\n")
        f.write("\\begin{tabular}{lccccc}\n\\hline\n")
        f.write("\\textbf{Architecture} & \\textbf{FPR (\\%)} & \\textbf{Recall Real Bad (\\%)} & \\textbf{Recall All Abusive (\\%)} & \\textbf{Precision (\\%)} & \\textbf{F1-Score} \\\\ \\hline\n")
        for name, stats in results.items():
            fpr_v = f"{stats['fpr'][0]:.2f} \\pm {stats['fpr'][1]:.2f}" if stats['fpr'][1] > 0 else f"{stats['fpr'][0]:.2f}"
            rec_v = f"{stats['recall_real_bad'][0]:.2f} \\pm {stats['recall_real_bad'][1]:.2f}" if stats['recall_real_bad'][1] > 0 else f"{stats['recall_real_bad'][0]:.2f}"
            rec_all_v = f"{stats['recall_all_abusive'][0]:.2f} \\pm {stats['recall_all_abusive'][1]:.2f}" if stats['recall_all_abusive'][1] > 0 else f"{stats['recall_all_abusive'][0]:.2f}"
            prec_v = f"{stats['precision'][0]:.2f} \\pm {stats['precision'][1]:.2f}" if stats['precision'][1] > 0 else f"{stats['precision'][0]:.2f}"
            f1_v = f"{stats['f1'][0]:.3f} \\pm {stats['f1'][1]:.3f}" if stats['f1'][1] > 0 else f"{stats['f1'][0]:.3f}"
            clean_name = name.replace("&", "\\&").replace("_", "\\_")
            f.write(f"{clean_name} & ${fpr_v}$ & ${rec_v}$ & ${rec_all_v}$ & ${prec_v}$ & ${f1_v}$ \\\\\n")
        f.write("\\hline\n\\end{tabular}\n\\end{table}\n\n")

        # Table II
        f.write("% =========================================================\n")
        f.write("% Table II: Fast-Path Latency Overhead Comparison\n")
        f.write("% =========================================================\n")
        f.write("\\begin{table}[htbp]\n\\centering\n")
        f.write("\\caption{Latency Overhead Analysis of Fast-Path Security Dispatch (ms)}\n")
        f.write("\\label{tab:latency_metrics}\n")
        f.write("\\begin{tabular}{lccccc}\n\\hline\n")
        f.write("\\textbf{Architecture} & \\textbf{P50} & \\textbf{P90} & \\textbf{P95} & \\textbf{P99} & \\textbf{Mean} \\\\ \\hline\n")
        for name, stats in results.items():
            if not np.isnan(stats['p50_fast_path'][0]):
                p50_v = f"{stats['p50_fast_path'][0]:.2f} \\pm {stats['p50_fast_path'][1]:.2f}" if stats['p50_fast_path'][1] > 0 else f"{stats['p50_fast_path'][0]:.2f}"
                p90_v = f"{stats['p90_fast_path'][0]:.2f} \\pm {stats['p90_fast_path'][1]:.2f}" if stats['p90_fast_path'][1] > 0 else f"{stats['p90_fast_path'][0]:.2f}"
                p95_v = f"{stats['p95_fast_path'][0]:.2f} \\pm {stats['p95_fast_path'][1]:.2f}" if stats['p95_fast_path'][1] > 0 else f"{stats['p95_fast_path'][0]:.2f}"
                p99_v = f"{stats['p99_fast_path'][0]:.2f} \\pm {stats['p99_fast_path'][1]:.2f}" if stats['p99_fast_path'][1] > 0 else f"{stats['p99_fast_path'][0]:.2f}"
                mean_v = f"{stats['mean_fast_path'][0]:.2f} \\pm {stats['mean_fast_path'][1]:.2f}" if stats['mean_fast_path'][1] > 0 else f"{stats['mean_fast_path'][0]:.2f}"
                clean_name = name.replace("&", "\\&").replace("_", "\\_")
                f.write(f"{clean_name} & ${p50_v}$ & ${p90_v}$ & ${p95_v}$ & ${p99_v}$ & ${mean_v}$ \\\\\n")
        f.write("\\hline\n\\end{tabular}\n\\end{table}\n\n")

        # Table III
        f.write("% =========================================================\n")
        f.write("% Table III: Progressive Enforcement Action Distribution\n")
        f.write("% =========================================================\n")
        f.write("\\begin{table}[htbp]\n\\centering\n")
        f.write("\\caption{Progressive Enforcement Action Distribution across Behavioral Traffic Classes (\\%)}\n")
        f.write("\\label{tab:progressive_enforcement}\n")
        f.write("\\begin{tabular}{lcccc}\n\\hline\n")
        f.write("\\textbf{Architecture} & \\textbf{Normal (A/T/B)} & \\textbf{Minimal Bad (A/T/B)} & \\textbf{Suspicious (A/T/B)} & \\textbf{Real Bad (A/T/B)} \\\\ \\hline\n")
        for name, stats in results.items():
            n_s = f"{stats['normal_allow'][0]:.1f} / {stats['normal_throttle'][0]:.1f} / {stats['normal_block'][0]:.1f}"
            m_s = f"{stats['minbad_allow'][0]:.1f} / {stats['minbad_throttle'][0]:.1f} / {stats['minbad_block'][0]:.1f}"
            s_s = f"{stats['susp_allow'][0]:.1f} / {stats['susp_throttle'][0]:.1f} / {stats['susp_block'][0]:.1f}"
            b_s = f"{stats['bad_allow'][0]:.1f} / {stats['bad_throttle'][0]:.1f} / {stats['bad_block'][0]:.1f}"
            clean_name = name.replace("&", "\\&").replace("_", "\\_")
            f.write(f"{clean_name} & {n_s} & {m_s} & {s_s} & {b_s} \\\\\n")
        f.write("\\hline\n\\end{tabular}\n\\end{table}\n\n")

        # Table IV
        f.write("% =========================================================\n")
        f.write("% Table IV: Multi-Signal Identity Tracking & Adversarial Resilience\n")
        f.write("% =========================================================\n")
        f.write("\\begin{table}[htbp]\n\\centering\n")
        f.write("\\caption{Multi-Signal Identity Resolution Resilience under IP Rotation and Adversarial Churn}\n")
        f.write("\\label{tab:identity_resilience}\n")
        f.write("\\begin{tabular}{lccccc}\n\\hline\n")
        f.write("\\textbf{Architecture} & \\textbf{Total Requests} & \\textbf{IP Rotations} & \\textbf{Rot-Bad Recall (\\%)} & \\textbf{Probe Recall (\\%)} & \\textbf{Throughput (req/s)} \\\\ \\hline\n")
        for name, stats in results.items():
            req_s = f"{int(stats['total_requests'][0]):,}"
            rot_s = f"{int(stats['total_rotations'][0]):,}"
            rot_rec_v = f"{stats['rot_bad_recall'][0]:.2f} \\pm {stats['rot_bad_recall'][1]:.2f}" if stats['rot_bad_recall'][1] > 0 else f"{stats['rot_bad_recall'][0]:.2f}"
            atk_rec_v = f"{stats['attack_recall'][0]:.2f} \\pm {stats['attack_recall'][1]:.2f}" if stats['attack_recall'][1] > 0 else f"{stats['attack_recall'][0]:.2f}"
            rps_v = f"{stats['throughput_rps'][0]:.1f} \\pm {stats['throughput_rps'][1]:.1f}" if stats['throughput_rps'][1] > 0 else f"{stats['throughput_rps'][0]:.1f}"
            clean_name = name.replace("&", "\\&").replace("_", "\\_")
            f.write(f"{clean_name} & {req_s} & {rot_s} & ${rot_rec_v}$ & ${atk_rec_v}$ & ${rps_v}$ \\\\\n")
        f.write("\\hline\n\\end{tabular}\n\\end{table}\n")

    print(f"\n✅ All 4 publication-ready LaTeX tables successfully exported to: {latex_path}")


if __name__ == "__main__":
    main()
