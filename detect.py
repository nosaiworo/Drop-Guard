"""Score every session in a drop log against the bot-detection rules.

Pipeline: load events into SQLite -> run each rule (rules.py) -> add up
weights -> flag sessions at or above THRESHOLD -> write report.md.

The ground-truth labels (data/labels.csv) are read only by the evaluation
step at the end, to measure how well the rules did.

Usage: python3 generate_data.py && python3 detect.py
"""
import csv
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path

from rules import RULES, THRESHOLD, WEBMAIL_DOMAINS

ROOT = Path(__file__).resolve().parent
STOCK = 500
COLUMNS = ["ts", "session_id", "account_id", "email", "ip", "user_agent",
           "event", "card_fp", "payment_result"]


def build_db(rows):
    """Load event rows (dicts) into an in-memory SQLite database."""
    conn = sqlite3.connect(":memory:")
    conn.execute(f"CREATE TABLE events ({', '.join(c + ' TEXT' for c in COLUMNS)})")
    conn.executemany(f"INSERT INTO events VALUES ({', '.join('?' * len(COLUMNS))})",
                     [tuple(r.get(c, "") for c in COLUMNS) for r in rows])
    conn.execute("CREATE TABLE webmail_domains (domain TEXT)")
    conn.executemany("INSERT INTO webmail_domains VALUES (?)", [(d,) for d in WEBMAIL_DOMAINS])
    return conn


def run_rules(conn, rules=RULES):
    """Return {session_id: [rule ids it tripped]}."""
    hits = defaultdict(list)
    for rule in rules:
        for (sid,) in conn.execute(rule["sql"]):
            hits[sid].append(rule["id"])
    return hits


def score_sessions(conn, hits, rules=RULES):
    weight = {r["id"]: r["weight"] for r in rules}
    sessions = [sid for (sid,) in conn.execute("SELECT DISTINCT session_id FROM events")]
    return {sid: sum(weight[r] for r in hits.get(sid, [])) for sid in sessions}


# ---------------------------------------------------------------- evaluation
def evaluate(flagged, labels):
    bots = {s for s, v in labels.items() if v["label"] == "bot"}
    tp = len(flagged & bots)
    fp = len(flagged - bots)
    fn = len(bots - flagged)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1": f1}


def stock_outcome(conn, blocked, labels):
    """Who gets the 500 units if `blocked` sessions are refused at checkout?

    Every payment the bank approved competes for stock in time order,
    including those that arrived after the drop sold out.
    """
    rows = conn.execute("""SELECT session_id FROM events
                           WHERE event = 'payment' AND payment_result IN ('approved', 'sold_out')
                           ORDER BY ts""").fetchall()
    buyers = [sid for (sid,) in rows]
    winners = [sid for sid in buyers if sid not in blocked][:STOCK]
    to_bots = sum(labels[s]["label"] == "bot" for s in winners)
    fans_blocked = len({s for s in buyers if s in blocked and labels[s]["label"] == "human"})
    return to_bots, fans_blocked


def pct(x):
    # One decimal place for small non-zero shares, so 7 of 1,461 doesn't read as 0%.
    return f"{100 * x:.1f}%" if 0 < x < 0.1 else f"{100 * x:.0f}%"


def write_report(conn, hits, scores, labels, path):
    flagged = {s for s, v in scores.items() if v >= THRESHOLD}
    m = evaluate(flagged, labels)
    bots_before, _ = stock_outcome(conn, set(), labels)
    bots_after, fans_blocked = stock_outcome(conn, flagged, labels)
    actors = Counter(v["actor"] for v in labels.values())
    n_bots = sum(1 for v in labels.values() if v["label"] == "bot")

    lines = [
        "# Drop Guard results",
        "",
        f"Synthetic drop: {STOCK} units, {len(labels)} sessions "
        f"({len(labels) - n_bots} genuine fans, {n_bots} bots from 4 operators). "
        f"Threshold: score of {THRESHOLD} or more.",
        "",
        "## Who got the stock",
        "",
        "| | Units to bots | Share of the drop | Genuine fans wrongly blocked |",
        "| --- | ---: | ---: | ---: |",
        f"| No defences | {bots_before} | {pct(bots_before / STOCK)} | 0 |",
        f"| Rules R1-R{len(RULES)} | {bots_after} | {pct(bots_after / STOCK)} | {fans_blocked} |",
        "",
        "## Detection accuracy",
        "",
        f"Precision {pct(m['precision'])} · recall {pct(m['recall'])} · F1 {m['f1']:.2f} "
        f"({m['tp']} bots caught, {m['fp']} fans flagged, {m['fn']} bots missed).",
        "",
        "| Rule | What it looks for | Threat | Weight | Sessions hit | Bots | Fans |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for r in RULES:
        hit = {s for s, ids in hits.items() if r["id"] in ids}
        bots = sum(labels[s]["label"] == "bot" for s in hit)
        lines.append(f"| {r['id']} {r['name']} | {r['why']} | {r['threat']} | {r['weight']} "
                     f"| {len(hit)} | {bots} | {len(hit) - bots} |")

    lines += ["", "## Flagged by actor", "", "| Actor | Sessions | Flagged | Share flagged |",
              "| --- | ---: | ---: | ---: |"]
    for actor in sorted(actors):
        sessions = {s for s, v in labels.items() if v["actor"] == actor}
        caught = len(sessions & flagged)
        lines.append(f"| {actor} | {len(sessions)} | {caught} | {pct(caught / len(sessions))} |")

    lines += ["", "## Choosing the threshold", "",
              "| Threshold | Precision | Recall | Fans wrongly blocked | Bots' share of stock |",
              "| ---: | ---: | ---: | ---: | ---: |"]
    for t in range(1, 7):
        f = {s for s, v in scores.items() if v >= t}
        mt = evaluate(f, labels)
        b, fans = stock_outcome(conn, f, labels)
        lines.append(f"| {t} | {pct(mt['precision'])} | {pct(mt['recall'])} | {fans} | {pct(b / STOCK)} |")

    path.write_text("\n".join(lines) + "\n")
    return m, bots_before, bots_after, fans_blocked


def main():
    with open(ROOT / "data" / "events.csv", newline="") as f:
        conn = build_db(list(csv.DictReader(f)))
    hits = run_rules(conn)
    scores = score_sessions(conn, hits)
    with open(ROOT / "data" / "labels.csv", newline="") as f:
        labels = {row["session_id"]: row for row in csv.DictReader(f)}
    m, before, after, fans = write_report(conn, hits, scores, labels, ROOT / "report.md")
    print(f"Bots' share of the drop: {pct(before / STOCK)} with no defences, {pct(after / STOCK)} with rules "
          f"({fans} fans wrongly blocked). Precision {pct(m['precision'])}, recall {pct(m['recall'])}. "
          f"Full results in report.md")


if __name__ == "__main__":
    main()
