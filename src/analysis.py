"""P2 stages 3-5: SQL -> DataFrame -> hypothesis tests -> figures.

One function per step so the procedure notebook can show and run each step in its own cell:
extract() builds the DataFrame, h1()..h5() each run one test and draw one figure and return
(result rows, figure), write_results() writes results.md.
Usage: python3 src/analysis.py
"""
import sqlite3
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy import stats

ROOT = Path(__file__).resolve().parent.parent
DB = Path.home() / "Library/CloudStorage/GoogleDrive-kwooler@gmail.com/My Drive/Sqlite/SCCUR26-P2.db"
FIG = ROOT / "output" / "figures"
RAW_PARTS = [ROOT / "data" / f"UNSW-NB15_{i}.csv" for i in range(1, 5)]   # for benefits()
FEATURES = ROOT / "data" / "NUSW-NB15_features.csv"


def mwu(a, b):
    u, p = stats.mannwhitneyu(a, b, alternative="two-sided")
    return u, p, 2 * u / (len(a) * len(b)) - 1          # rank-biserial r


def cramers_v(table):
    chi2, p, dof, _ = stats.chi2_contingency(table)
    n = table.to_numpy().sum()
    return chi2, p, dof, np.sqrt(chi2 / (n * (min(table.shape) - 1)))


def gini(x):
    x = np.sort(np.asarray(x, dtype=float))
    n = len(x)
    return (2 * np.arange(1, n + 1) - n - 1).dot(x) / (n * x.sum())


def fmt_p(p):
    return "< 0.001" if p < 0.001 else f"{p:.3f}"


def save(fig, name):
    FIG.mkdir(exist_ok=True)
    fig.tight_layout()
    fig.savefig(FIG / name, dpi=150)
    return fig


# ---- Stage 3: DataFrame (only the columns the tests need) -------------------
def extract():
    con = sqlite3.connect(DB)
    df = pd.read_sql_query("""
        SELECT f.label, ac.name AS family, s.name AS service, h.ip AS src_ip,
               f.dur, f.sbytes, f.dbytes, f.stime
        FROM flow f
        JOIN service s USING (service_id)
        JOIN host h ON h.host_id = f.src_host_id
        LEFT JOIN attack_category ac USING (attack_cat_id)""", con)
    con.close()
    df["hour_utc"] = pd.to_datetime(df["stime"], unit="s", utc=True).dt.hour
    attack, normal = df[df.label == 1], df[df.label == 0]
    desc = {"flows": len(df), "attack_flows": len(attack), "normal_flows": len(normal),
            "attack_share": len(attack) / len(df), "source_hosts": df["src_ip"].nunique(),
            "capture_days_utc": df["stime"].pipe(pd.to_datetime, unit="s").dt.date.nunique()}
    return {"df": df, "attack": attack, "normal": normal, "desc": desc}


# ---- Stage 4 + 5: one test and one figure per hypothesis --------------------
def h1(d):
    """Attack vs normal: bytes sent and duration (two rows: H1a, H1b)."""
    attack, normal = d["attack"], d["normal"]
    rows = []
    u, p, r = mwu(attack["sbytes"], normal["sbytes"])
    rows.append(("H1a", "Attack and normal flows differ in source bytes", "Mann-Whitney U",
                 f"{len(attack):,} / {len(normal):,}", f"U = {u:.3g}", fmt_p(p), f"rank-biserial r = {r:.3f}",
                 f"median sbytes attack {attack.sbytes.median():,.0f}, normal {normal.sbytes.median():,.0f}"))
    u, p, r = mwu(attack["dur"], normal["dur"])
    rows.append(("H1b", "Attack and normal flows differ in duration", "Mann-Whitney U",
                 f"{len(attack):,} / {len(normal):,}", f"U = {u:.3g}", fmt_p(p), f"rank-biserial r = {r:.3f}",
                 f"median dur attack {attack.dur.median():.4f}s, normal {normal.dur.median():.4f}s"))
    fig, axes = plt.subplots(1, 2, figsize=(9, 4))
    for ax, col, title in zip(axes, ["sbytes", "dur"], ["Source bytes", "Duration (s)"]):
        ax.boxplot([normal[col] + 1e-6, attack[col] + 1e-6], tick_labels=["Normal", "Attack"], showfliers=False)
        ax.set_yscale("log"); ax.set_title(title)
    fig.suptitle("H1: Attack vs normal flow behaviour")
    return rows, save(fig, "h1_attack_vs_normal.png")


def h2(d):
    """Nine attack families differ in source bytes."""
    attack = d["attack"]
    fam = attack.groupby("family")["sbytes"]
    groups = [g.to_numpy() for _, g in fam]
    h, p = stats.kruskal(*groups)
    k, n = len(groups), len(attack)
    eps2 = (h - k + 1) / (n - k)
    med = fam.median().sort_values()
    row = ("H2", "Attack families differ in source bytes", "Kruskal-Wallis H", f"{n:,} ({k} families)",
           f"H = {h:,.0f}", fmt_p(p), f"epsilon^2 = {eps2:.3f}",
           f"median sbytes lowest {med.index[0]} {med.iloc[0]:,.0f}, highest {med.index[-1]} {med.iloc[-1]:,.0f}")
    order = med.index.tolist()
    fig, ax = plt.subplots(figsize=(9, 4.5))
    ax.boxplot([attack.loc[attack.family == f, "sbytes"] + 1 for f in order], tick_labels=order, showfliers=False)
    ax.set_yscale("log"); ax.set_ylabel("Source bytes (log)"); ax.tick_params(axis="x", rotation=30)
    ax.set_title("H2: Byte profile of the nine attack families")
    return [row], save(fig, "h2_family_bytes.png")


def h3(d):
    """Service x attack."""
    df = d["df"]
    tab = pd.crosstab(df["service"], df["label"])
    chi2, p, dof, v = cramers_v(tab)
    rate = df.groupby("service")["label"].agg(["mean", "size"]).sort_values("mean")
    row = ("H3", "Attack likelihood depends on service", "Chi-square independence", f"{len(df):,}",
           f"chi2 = {chi2:,.0f} (df {dof})", fmt_p(p), f"Cramer's V = {v:.3f}",
           f"attack rate highest {rate.index[-1]} {rate['mean'].iloc[-1]:.1%}, lowest {rate.index[0]} {rate['mean'].iloc[0]:.1%}")
    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.barh(rate.index, rate["mean"], color="#C44E52")
    ax.set_xlabel("Share of flows that are attacks"); ax.set_title("H3: Attack rate by service ('-' = unidentified)")
    return [row], save(fig, "h3_attack_rate_by_service.png")


def h4(d):
    """Attack flows concentrated in few source hosts."""
    df, attack = d["df"], d["attack"]
    by_host = attack.groupby("src_ip").size().sort_values(ascending=False)
    all_hosts = df.groupby("src_ip").size()
    by_host_full = by_host.reindex(all_hosts.index, fill_value=0)
    g = gini(by_host_full.to_numpy())
    top3 = by_host.iloc[:3].sum() / by_host.sum()
    attacker_hosts = (by_host > 0).sum()
    row = ("H4", "Attack flows come from a few source hosts", "Concentration (Gini, top shares)",
           f"{len(all_hosts)} source hosts", f"Gini = {g:.3f}", "-", f"top-3 host share = {top3:.1%}",
           f"{attacker_hosts} of {len(all_hosts)} hosts sent any attack flow; top host {by_host.index[0]}")
    fig, ax = plt.subplots(figsize=(7, 4))
    top = by_host.iloc[:10]
    ax.bar(top.index, top.values, color="#8172B2"); ax.tick_params(axis="x", rotation=60)
    ax.set_ylabel("Attack flows"); ax.set_title("H4: Attack flows by source host (top 10)")
    return [row], save(fig, "h4_attack_by_host.png")


def h5(d):
    """Attack share differs by hour of day."""
    df = d["df"]
    tab = pd.crosstab(df["hour_utc"], df["label"])
    chi2, p, dof, v = cramers_v(tab)
    hr = df.groupby("hour_utc")["label"].mean()
    row = ("H5", "Attack share varies by hour of capture", "Chi-square independence", f"{len(df):,}",
           f"chi2 = {chi2:,.0f} (df {dof})", fmt_p(p), f"Cramer's V = {v:.3f}",
           f"hourly attack share {hr.min():.1%} - {hr.max():.1%} (UTC hours)")
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar(hr.index, hr.values, color="#64B5CD")
    ax.set_xlabel("Hour (UTC)"); ax.set_ylabel("Attack share"); ax.set_title("H5: Attack share by hour")
    return [row], save(fig, "h5_attack_share_by_hour.png")


def h6(d):
    """Shortcut test: how well the lab artifact (source host) alone 'detects' attacks, vs a behavior feature."""
    df = d["df"]
    y = df["label"].to_numpy() == 1
    attackers = set(d["attack"]["src_ip"])
    flag = df["src_ip"].isin(attackers).to_numpy()
    tp = int((flag & y).sum())
    recall, precision = tp / y.sum(), tp / flag.sum()
    fpr = int((flag & ~y).sum()) / int((~y).sum())
    auc_host = 0.5 * (1 + recall - fpr)                         # AUC of a 0/1 score
    u = stats.mannwhitneyu(d["normal"]["sbytes"], d["attack"]["sbytes"]).statistic
    auc_bytes = u / (len(d["normal"]) * len(d["attack"]))       # P(normal flow sends more bytes)
    row = ("H6", "The source host alone separates attacks better than a behavior feature (a lab shortcut)",
           "Rule 'flow comes from an attacking host' vs source bytes, area under the ROC curve",
           f"{len(df):,} flows", f"AUC host {auc_host:.3f} vs source bytes {auc_bytes:.3f}", "-",
           f"host rule: recall {recall:.1%}, precision {precision:.1%}",
           f"{len(attackers)} attacking hosts; false-positive rate of the host rule {fpr:.2%}")
    fig, ax = plt.subplots(figsize=(5, 4))
    ax.bar(["Source host\n(lab artifact)", "Source bytes\n(behavior)"], [auc_host, auc_bytes], color=["#C44E52", "#4C72B0"])
    ax.axhline(0.5, ls="--", color="gray"); ax.set_ylim(0, 1)
    ax.set_ylabel("Area under the ROC curve"); ax.set_title("H6: One feature alone, attack vs normal")
    return [row], save(fig, "h6_host_shortcut.png")


HYPOTHESES = [h1, h2, h3, h4, h5, h6]


def write_results(desc, rows):
    lines = ["# P2 results (generated by src/analysis.py)", "", "## Descriptives", ""]
    lines += [f"- {k}: {v:,.4g}" if isinstance(v, float) else f"- {k}: {v:,}" for k, v in desc.items()]
    lines += ["", "## Hypothesis tests (alpha = 0.05)", "",
              "| # | Hypothesis | Test | n | Statistic | p | Effect size | Detail |",
              "|---|---|---|---|---|---|---|---|"]
    lines += ["| " + " | ".join(r) + " |" for r in rows]
    (ROOT / "output" / "results.md").write_text("\n".join(lines) + "\n")
    return "\n".join(lines)


# ---- Database benefits: the same question answered from the raw parts vs the database ---------
def benefits():
    """Measure what the database adds, against reading the four raw parts directly.

    The question asked both ways is H2's: median source bytes per attack family.
    Returns rows (aspect, raw files, result, database, result, consequence) for benefits.md.
    """
    import re
    import time
    con = sqlite3.connect(DB)
    fuzz = con.execute("""SELECT v.row_count FROM attack_label_variant v JOIN attack_category c
                          USING (attack_cat_id) WHERE c.name = 'Fuzzers' ORDER BY v.row_count DESC""").fetchall()
    fk = con.execute("SELECT COUNT(*) FROM pragma_foreign_key_check").fetchone()[0]
    con.close()

    # Baseline: the four parts as delivered (names from the definition file, no repair).
    names = [re.sub(r"\s+", "", n).lower() for n in pd.read_csv(FEATURES, encoding="latin-1")["Name"]]
    t0 = time.perf_counter()
    raw = pd.concat([pd.read_csv(f, header=None, names=names, encoding="utf-8-sig", low_memory=False)
                     for f in RAW_PARTS])
    raw_groups = raw.groupby("attack_cat")["sbytes"].median()
    t_raw = time.perf_counter() - t0
    mem_raw = raw.memory_usage(deep=True).sum()
    bad_ports = sum(int((~raw[c].dropna().astype(str).str.fullmatch(r"\d+")).sum()) for c in ("sport", "dsport"))
    del raw

    # Database: one SQL join, eight typed columns, repaired families.
    t0 = time.perf_counter()
    d = extract()
    db_groups = d["attack"].groupby("family")["sbytes"].median()
    t_db = time.perf_counter() - t0
    mem_db = d["df"].memory_usage(deep=True).sum()

    return [
        ("Correctness", "raw labels", f"{len(raw_groups)} attack groups", "repaired labels",
         f"{len(db_groups)} families", f"Fuzzers counted as {len(fuzz)} groups ({' + '.join(f'{n:,}' for (n,) in fuzz)})"),
        ("Integrity", "no checks", f"{bad_ports} port values not decimal", "load + verify.sql",
         f"{fk} foreign-key violations", "hexadecimal ports decoded, '-' stored as NULL"),
        ("Time", "read 4 parts (49 columns), answer H2", f"{t_raw:.1f} s", "SQL join (8 columns), answer H2",
         f"{t_db:.1f} s", f"{t_raw / t_db:.1f}x faster"),
        ("Memory", "DataFrame of the raw parts", f"{mem_raw / 1e6:,.0f} MB", "DataFrame from the join",
         f"{mem_db / 1e6:,.0f} MB", f"{mem_raw / mem_db:.1f}x smaller"),
    ]


def write_benefits(rows):
    lines = ["# P2 database benefits (generated by `python3 src/analysis.py benefits`)", "",
             "The same question (H2: median source bytes per attack family) answered from the four raw",
             "CSV parts as delivered and from the database. Times and memory are from one run on the",
             "author's machine and vary between runs.", "",
             "| Aspect | Raw files | Result | Database | Result | Consequence |", "|---|---|---|---|---|---|"]
    lines += ["| " + " | ".join(r) + " |" for r in rows]
    (ROOT / "output" / "benefits.md").write_text("\n".join(lines) + "\n")
    return "\n".join(lines)


def main():
    import sys
    if sys.argv[1:] == ["benefits"]:
        print(write_benefits(benefits()))
        return
    d = extract()
    rows = []
    for h in HYPOTHESES:
        r, fig = h(d)
        rows += r
        plt.close(fig)
    print(write_results(d["desc"], rows))


if __name__ == "__main__":
    main()
