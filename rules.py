"""Bot-detection rules for a limited merch drop.

Each rule is one SQL query over the `events` table that returns the
session_ids it flags. A session's score is the sum of the weights of the
rules it trips. Sessions scoring THRESHOLD or more are treated as bots.

Threat names refer to OWASP's Automated Threats to Web Applications:
https://owasp.org/www-project-automated-threats-to-web-applications/
"""

THRESHOLD = 3

# Big webmail providers: many genuine customers share these domains.
WEBMAIL_DOMAINS = ["webmail.example", "post.example", "inbox.example", "mailbox.example"]

RULES = [
    {
        "id": "R1",
        "name": "Superhuman add-to-cart",
        "why": "Added to cart less than 2 seconds after the first page view.",
        "threat": "OAT-006 Expediting",
        "weight": 2,
        "sql": """
            SELECT session_id FROM (
                SELECT session_id,
                       MIN(CASE WHEN event = 'page_view'   THEN ts END) AS first_view,
                       MIN(CASE WHEN event = 'add_to_cart' THEN ts END) AS first_cart
                FROM events
                GROUP BY session_id
            )
            WHERE first_cart IS NOT NULL
              AND (julianday(first_cart) - julianday(first_view)) * 86400 < 2.0
        """,
    },
    {
        "id": "R2",
        "name": "Crowded IP address",
        "why": "More than 8 accounts used one IP address during the drop.",
        "threat": "OAT-005 Scalping",
        "weight": 1,
        "sql": """
            SELECT DISTINCT e.session_id
            FROM events e
            JOIN (SELECT ip FROM events GROUP BY ip
                  HAVING COUNT(DISTINCT account_id) > 8) busy
              ON e.ip = busy.ip
        """,
    },
    {
        "id": "R3",
        "name": "Card shared across accounts",
        "why": "One payment card was used by 3 or more accounts.",
        "threat": "OAT-005 Scalping",
        "weight": 2,
        "sql": """
            SELECT DISTINCT e.session_id
            FROM events e
            JOIN (SELECT card_fp FROM events WHERE card_fp != ''
                  GROUP BY card_fp HAVING COUNT(DISTINCT account_id) >= 3) shared
              ON e.card_fp = shared.card_fp
        """,
    },
    {
        "id": "R4",
        "name": "Card testing",
        "why": "3 or more declined payments using 3 or more different cards in one session.",
        "threat": "OAT-001 Carding",
        "weight": 3,
        "sql": """
            SELECT session_id FROM events
            WHERE event = 'payment'
            GROUP BY session_id
            HAVING SUM(payment_result = 'declined') >= 3
               AND COUNT(DISTINCT card_fp) >= 3
        """,
    },
    {
        "id": "R5",
        "name": "Automation signature",
        "why": "The browser identifies itself as a script or headless browser.",
        "threat": "OAT-005 Scalping",
        "weight": 3,
        "sql": """
            SELECT DISTINCT session_id FROM events
            WHERE lower(user_agent) LIKE '%headless%'
               OR lower(user_agent) LIKE '%python-requests%'
               OR lower(user_agent) LIKE '%curl/%'
               OR lower(user_agent) LIKE '%selenium%'
               OR lower(user_agent) LIKE '%phantomjs%'
        """,
    },
    {
        "id": "R6",
        "name": "Mailbox farm",
        "why": "3 or more accounts lead to one mailbox through +tags (name+1@, name+2@...).",
        "threat": "OAT-005 Scalping",
        "weight": 2,
        "sql": """
            WITH accounts AS (
                SELECT DISTINCT session_id, account_id, lower(email) AS email FROM events
            ),
            boxes AS (
                SELECT session_id, account_id,
                       CASE WHEN instr(email, '+') > 0
                            THEN substr(email, 1, instr(email, '+') - 1) || substr(email, instr(email, '@'))
                            ELSE email END AS mailbox
                FROM accounts
            )
            SELECT session_id FROM boxes
            WHERE mailbox IN (SELECT mailbox FROM boxes GROUP BY mailbox
                              HAVING COUNT(DISTINCT account_id) >= 3)
        """,
    },
    {
        "id": "R7",
        "name": "Catch-all domain",
        "why": "20 or more accounts on one email domain that isn't a big webmail provider.",
        "threat": "OAT-005 Scalping",
        "weight": 1,
        "sql": """
            WITH accounts AS (
                SELECT DISTINCT session_id, account_id,
                       lower(substr(email, instr(email, '@') + 1)) AS domain
                FROM events
            )
            SELECT session_id FROM accounts
            WHERE domain NOT IN (SELECT domain FROM webmail_domains)
              AND domain IN (SELECT domain FROM accounts GROUP BY domain
                             HAVING COUNT(DISTINCT account_id) >= 20)
        """,
    },
    {
        # Weight 3 means this rule alone is enough to block. That catches
        # bots that wait a fixed few seconds before paying, but also blocks
        # fans who pay that fast with a saved card or Apple Pay.
        "id": "R8",
        "name": "Scripted payment",
        "why": "Paid less than 4.5 seconds after starting checkout.",
        "threat": "OAT-006 Expediting",
        "weight": 3,
        "sql": """
            SELECT session_id FROM (
                SELECT session_id,
                       MIN(CASE WHEN event = 'checkout_start' THEN ts END) AS checkout,
                       MIN(CASE WHEN event = 'payment'        THEN ts END) AS first_payment
                FROM events
                GROUP BY session_id
            )
            WHERE first_payment IS NOT NULL
              AND (julianday(first_payment) - julianday(checkout)) * 86400 < 4.5
        """,
    },
]
