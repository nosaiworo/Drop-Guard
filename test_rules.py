"""Each rule should fire on the pattern it targets and stay quiet on an ordinary fan.

Run from the project folder: python3 -m unittest discover -s tests
"""
import hashlib
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from detect import build_db, run_rules  # noqa: E402

START = datetime(2026, 11, 20, 10, 0, 0)
BROWSER = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) Version/18.1 Safari/605.1.15"


def session(sid, steps, email=None, ip=None, ua=BROWSER):
    """steps: list of (seconds_after_start, event, card, result)."""
    return [{"ts": (START + timedelta(seconds=t)).isoformat(sep=" ", timespec="milliseconds"),
             "session_id": sid, "account_id": "acct-" + sid,
             "email": email or f"{sid}@webmail.example",
             "ip": ip or "2001:db8::" + hashlib.md5(sid.encode()).hexdigest()[:4],
             "user_agent": ua, "event": event, "card_fp": card, "payment_result": result}
            for t, event, card, result in steps]


def normal_purchase(card):
    return [(0, "page_view", "", ""), (12, "add_to_cart", "", ""),
            (40, "checkout_start", "", ""), (65, "payment", card, "approved")]


class RuleTests(unittest.TestCase):
    def hits_for(self, rows):
        return run_rules(build_db(rows))

    def test_ordinary_fan_trips_nothing(self):
        hits = self.hits_for(session("fan", normal_purchase("card_fan")))
        self.assertEqual(hits.get("fan", []), [])

    def test_fast_headless_bot(self):
        steps = [(0, "page_view", "", ""), (0.4, "add_to_cart", "", ""),
                 (1.0, "checkout_start", "", ""), (1.6, "payment", "card_x", "approved")]
        hits = self.hits_for(session("bot", steps, ua="python-requests/2.32.3"))
        self.assertIn("R1", hits["bot"])
        self.assertIn("R5", hits["bot"])

    def test_crowded_ip(self):
        rows = []
        for i in range(9):
            rows += session(f"u{i}", normal_purchase(f"card_{i}"), ip="203.0.113.10")
        hits = self.hits_for(rows)
        self.assertTrue(all("R2" in hits[f"u{i}"] for i in range(9)))

    def test_shared_card(self):
        rows = []
        for i in range(3):
            rows += session(f"c{i}", normal_purchase("card_shared"))
        hits = self.hits_for(rows)
        self.assertTrue(all("R3" in hits[f"c{i}"] for i in range(3)))

    def test_card_testing(self):
        steps = [(0, "page_view", "", ""), (5, "add_to_cart", "", ""), (10, "checkout_start", "", "")]
        steps += [(12 + 3 * i, "payment", f"card_{i}", "declined") for i in range(4)]
        hits = self.hits_for(session("tester", steps))
        self.assertIn("R4", hits["tester"])

    def test_mailbox_farm(self):
        rows = []
        for i in range(3):
            rows += session(f"m{i}", normal_purchase(f"card_m{i}"), email=f"plug+{i}@inbox.example")
        hits = self.hits_for(rows)
        self.assertTrue(all("R6" in hits[f"m{i}"] for i in range(3)))

    def test_scripted_payment(self):
        steps = [(0, "page_view", "", ""), (8, "add_to_cart", "", ""),
                 (20, "checkout_start", "", ""), (24.2, "payment", "card_s", "approved")]
        hits = self.hits_for(session("scripted", steps))
        self.assertIn("R8", hits["scripted"])

    def test_catch_all_domain_but_not_webmail(self):
        rows = []
        for i in range(20):
            rows += session(f"d{i}", normal_purchase(f"card_d{i}"), email=f"x{i}@restock-hub.test")
            rows += session(f"w{i}", normal_purchase(f"card_w{i}"), email=f"y{i}@webmail.example")
        hits = self.hits_for(rows)
        self.assertTrue(all("R7" in hits[f"d{i}"] for i in range(20)))
        self.assertFalse(any("R7" in hits.get(f"w{i}", []) for i in range(20)))


if __name__ == "__main__":
    unittest.main()
