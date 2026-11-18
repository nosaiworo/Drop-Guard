"""Generate a synthetic event log for a limited merch drop.

The drop: 500 hoodies go on sale at 10:00:00. Genuine fans and four bot
operators race to buy them. Every session is labelled human or bot, but the
labels go in a separate file (data/labels.csv). The detector reads that file
only to score itself, never to make a decision.

All IP addresses come from documentation or shared ranges (RFC 5737,
RFC 6598, RFC 3849) and all email domains are reserved names (.example,
.test), so no row describes a real person.

Usage: python3 generate_data.py
"""
import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

SEED = 2026
STOCK = 500
DROP = datetime(2026, 11, 20, 10, 0, 0)
DATA = Path(__file__).resolve().parent / "data"

COLUMNS = ["ts", "session_id", "account_id", "email", "ip", "user_agent",
           "event", "card_fp", "payment_result"]

BROWSERS = [
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/130.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/18.1 Safari/605.1.15",
]
AUTOMATION = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "HeadlessChrome/130.0.0.0 Safari/537.36",
    "python-requests/2.32.3",
]
WEBMAIL = ["webmail.example", "post.example", "inbox.example", "mailbox.example"]
FIRST = ["amara", "tunde", "chloe", "kwame", "ella", "jay", "priya", "leon", "zara", "sam",
         "ife", "noah", "maya", "dami", "ruby", "theo", "aisha", "kai", "lola", "omar"]
LAST = ["smith", "okafor", "khan", "jones", "mensah", "patel", "brown", "adeyemi", "taylor",
        "evans", "osei", "wright", "ali", "clarke", "bello", "hughes"]

UNIVERSITY_IP = "198.51.100.23"   # one campus network, many students
MOBILE_CGNAT_IP = "100.64.12.7"   # carrier-grade NAT: many phones share one address


def seconds(x):
    return timedelta(seconds=x)


class Drop:
    """Collects events and ground-truth labels while sessions are generated."""

    def __init__(self, rng):
        self.rng = rng
        self.rows = []
        self.labels = []
        self.count = 0

    def session(self, actor, email, ip, user_agent):
        self.count += 1
        sid = f"s{self.count:05d}"
        self.labels.append({"session_id": sid,
                            "label": "human" if actor == "human" else "bot",
                            "actor": actor})
        return {"session_id": sid, "account_id": f"a{self.count:05d}",
                "email": email, "ip": ip, "user_agent": user_agent}

    def log(self, s, t, event, card="", result=""):
        self.rows.append({**s, "ts": t, "event": event,
                          "card_fp": card, "payment_result": result})

    def card(self):
        # A card fingerprint (a token), never a card number.
        return "card_" + self.rng.randbytes(5).hex()

    def ipv6(self):
        r = self.rng
        return f"2001:db8:{r.randrange(0x10000):x}:{r.randrange(0x10000):x}::{r.randrange(1, 0x10000):x}"

    def fan_email(self, tag=""):
        r = self.rng
        local = f"{r.choice(FIRST)}.{r.choice(LAST)}{r.randint(1, 999)}"
        return f"{local}{tag}@{r.choice(WEBMAIL)}"


def human(drop, ip, card=None, email=None):
    r = drop.rng
    s = drop.session("human", email or drop.fan_email(), ip, r.choice(BROWSERS))
    t = DROP + seconds(r.expovariate(1 / 75))          # most fans land in the first few minutes
    views = r.randint(1, 4)
    for i in range(views):
        drop.log(s, t, "page_view")
        last_view = i == views - 1
        if last_view and views == 1 and r.random() < 0.03:
            t += seconds(r.uniform(1.2, 1.9))           # a quick fan who knows their size
        else:
            t += seconds(r.uniform(3, 25))
    if r.random() < 0.15:
        return                                          # browsed, didn't add to cart
    drop.log(s, t, "add_to_cart")
    t += seconds(r.uniform(6, 45))
    drop.log(s, t, "checkout_start")
    if r.random() < 0.10:
        return                                          # abandoned at checkout
    if r.random() < 0.04:
        t += seconds(r.uniform(3.0, 6.0))               # saved card or Apple Pay
    else:
        t += seconds(max(6.0, r.lognormvariate(3.1, 0.5)))
    first_card = card or drop.card()
    if r.random() < 0.94:
        drop.log(s, t, "payment", first_card, "approved")
    else:
        drop.log(s, t, "payment", first_card, "declined")
        t += seconds(r.uniform(10, 30))
        drop.log(s, t, "payment", drop.card(), "approved" if r.random() < 0.9 else "declined")


def bot_naive(drop, ips, cards, n):
    """Operator A: headless scripts on a few datacentre IPs, one mailbox behind every account."""
    r = drop.rng
    s = drop.session("A-naive-scalper", f"kicksplug+{n:03d}@inbox.example",
                     r.choice(ips), r.choice(AUTOMATION))
    t = DROP + seconds(r.uniform(0.0, 2.5))
    drop.log(s, t, "page_view")
    t += seconds(r.uniform(0.15, 0.9))
    drop.log(s, t, "add_to_cart")
    t += seconds(r.uniform(0.2, 1.0))
    drop.log(s, t, "checkout_start")
    t += seconds(r.uniform(0.3, 1.2))
    drop.log(s, t, "payment", r.choice(cards), "approved")


def bot_proxy(drop, cards):
    """Operator B: rotating residential proxies and real browser strings, accounts on a catch-all domain."""
    r = drop.rng
    local = "".join(r.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(8))
    s = drop.session("B-proxy-network", f"{local}@restock-hub.test", drop.ipv6(), r.choice(BROWSERS))
    t = DROP + seconds(r.uniform(0.5, 8))
    drop.log(s, t, "page_view")
    t += seconds(r.uniform(0.8, 2.6))
    drop.log(s, t, "add_to_cart")
    if r.random() < 0.15:
        return                                          # holds stock in cart and never pays
    t += seconds(r.uniform(1, 3))
    drop.log(s, t, "checkout_start")
    t += seconds(r.uniform(1, 3))
    drop.log(s, t, "payment", r.choice(cards), "approved")


def bot_carding(drop, ips):
    """Operator C: uses the drop's checkout to test stolen cards."""
    r = drop.rng
    s = drop.session("C-card-tester", drop.fan_email(), r.choice(ips), r.choice(BROWSERS))
    t = DROP + seconds(r.uniform(30, 400))
    drop.log(s, t, "page_view")
    t += seconds(r.uniform(2, 6))
    drop.log(s, t, "add_to_cart")
    t += seconds(r.uniform(3, 8))
    drop.log(s, t, "checkout_start")
    attempts = r.randint(4, 8)
    for i in range(attempts):
        t += seconds(r.uniform(2, 5))
        last = i == attempts - 1
        result = "approved" if last and r.random() < 0.25 else "declined"
        drop.log(s, t, "payment", drop.card(), result)


def bot_careful(drop):
    """Operator D: mimics people closely; its one tell is a scripted 4-second wait before paying."""
    r = drop.rng
    s = drop.session("D-careful-bot", drop.fan_email(), drop.ipv6(), r.choice(BROWSERS))
    t = DROP + seconds(r.uniform(2, 9))
    for _ in range(r.randint(1, 2)):
        drop.log(s, t, "page_view")
        t += seconds(r.uniform(3, 8))
    drop.log(s, t, "add_to_cart")
    t += seconds(r.uniform(5, 12))
    drop.log(s, t, "checkout_start")
    t += seconds(r.uniform(4.0, 4.4))
    drop.log(s, t, "payment", drop.card(), "approved")


def mark_sold_out(rows):
    """Payments the bank approved after the 500th order get 'sold_out'."""
    sold = 0
    for row in sorted(rows, key=lambda x: x["ts"]):
        if row["event"] == "payment" and row["payment_result"] == "approved":
            sold += 1
            if sold > STOCK:
                row["payment_result"] = "sold_out"


def main():
    rng = random.Random(SEED)
    drop = Drop(rng)

    # Genuine fans: mostly on their own connection...
    for _ in range(1300):
        human(drop, drop.ipv6())
    # ...some on one campus network or one mobile carrier address...
    for _ in range(12):
        human(drop, UNIVERSITY_IP)
    for _ in range(25):
        human(drop, MOBILE_CGNAT_IP)
    # ...and households that share a connection and a card.
    for size, groups, ip_choice in [(2, 50, None), (3, 6, None), (3, 2, MOBILE_CGNAT_IP)]:
        for _ in range(groups):
            ip, card = ip_choice or drop.ipv6(), drop.card()
            for _ in range(size):
                human(drop, ip, card=card)

    # Bot operators.
    a_ips = [f"203.0.113.{i}" for i in range(10, 16)]
    a_cards = [drop.card() for _ in range(4)]
    for n in range(120):
        bot_naive(drop, a_ips, a_cards, n)
    b_cards = [drop.card() for _ in range(12)]
    for _ in range(150):
        bot_proxy(drop, b_cards)
    for _ in range(30):
        bot_carding(drop, ["192.0.2.44", "192.0.2.45"])
    for _ in range(60):
        bot_careful(drop)

    mark_sold_out(drop.rows)
    DATA.mkdir(exist_ok=True)
    drop.rows.sort(key=lambda x: x["ts"])
    with open(DATA / "events.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        for row in drop.rows:
            w.writerow({**row, "ts": row["ts"].isoformat(sep=" ", timespec="milliseconds")})
    with open(DATA / "labels.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["session_id", "label", "actor"])
        w.writeheader()
        w.writerows(drop.labels)

    humans = sum(1 for x in drop.labels if x["label"] == "human")
    print(f"Wrote {len(drop.rows)} events from {len(drop.labels)} sessions "
          f"({humans} human, {len(drop.labels) - humans} bot) to {DATA}")


if __name__ == "__main__":
    main()
