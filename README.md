# Drop Guard

Spotting bots in a limited merch drop, with Python and SQL.

Why I'm making this? I remember being a fan of Yeezys back in 2014 and I always failed obtaining the shoes online due to Bots. Bots destroy the experience for fans and in this day and age, they still exist. The stakes are higher now with more tokenised items (such as Pokemon) releasing but bots obtain due to the high resale value of the items. I want to help prevent this from happening. When a limited drop goes live, stock can sell out in seconds, and a large share can go to bots instead of fans. This project simulates one drop, writes bot-detection rules as SQL queries, and measures both what the rules catch and what they cost: genuine fans wrongly blocked.

## Results

A simulated drop of 500 hoodies, with 1,821 sessions: 1,461 genuine fans and 360 bots from four operators.

| | Units to bots | Share of the drop | Genuine fans wrongly blocked |
| --- | ---: | ---: | ---: |
| No defences | 306 | 61% | 0 |
| Rules R1–R8 (threshold 3) | 0 | 0% | 24 |

Precision is 94% and recall 98%. Rules R1–R7 catch three of the four operators. R8 catches the fourth, a bot built to look human, whose one tell is a scripted wait before paying. Full tables are in [report.md](report.md).

## How it works

1. **`generate_data.py` simulates the drop.** It writes a session log of page views, add-to-carts, checkouts and payments from genuine fans and four bot operators:
   - **A, naive scalper:** headless scripts on six datacentre IP addresses; every account leads to one mailbox.
   - **B, proxy network:** rotating residential proxies and real browser strings; accounts on a catch-all domain; a small pool of cards.
   - **C, card tester:** runs stolen cards through the checkout.
   - **D, careful bot:** human-like timing. Its one tell is a scripted four-second wait before paying.

   The data includes the messiness that causes false alarms: students on one campus network, phones sharing one mobile-carrier address, households sharing a card, and fans who pay in seconds with a saved card.
2. **`detect.py` loads the log into SQLite and runs the rules in `rules.py`.** Each rule is a SQL query that returns the sessions it flags, much like a correlation rule in a SIEM. Each rule has a weight, and sessions scoring 3 or more are treated as bots.
3. **The answers stay separate.** Labels saying which sessions really were bots live in their own file, which the detector reads only at the end, to score itself.
4. **A what-if replays the sale:** if flagged sessions had been refused at checkout, who would have got the 500 units?

## The rules

| Rule | Looks for | OWASP threat | Weight |
| --- | --- | --- | ---: |
| R1 Superhuman add-to-cart | Add to cart under 2 seconds after the first page view | OAT-006 Expediting | 2 |
| R2 Crowded IP address | More than 8 accounts on one IP address | OAT-005 Scalping | 1 |
| R3 Card shared across accounts | One card used by 3 or more accounts | OAT-005 Scalping | 2 |
| R4 Card testing | 3+ declined payments on 3+ cards in one session | OAT-001 Carding | 3 |
| R5 Automation signature | A headless browser or script in the user agent | OAT-005 Scalping | 3 |
| R6 Mailbox farm | 3+ accounts behind one mailbox via +tags | OAT-005 Scalping | 2 |
| R7 Catch-all domain | 20+ accounts on a domain that isn't a big webmail provider | OAT-005 Scalping | 1 |
| R8 Scripted payment | Payment under 4.5 seconds after starting checkout | OAT-006 Expediting | 3 |

Threat names come from [OWASP Automated Threats to Web Applications](https://owasp.org/www-project-automated-threats-to-web-applications/).

## The trade-offs

**R8's weight is the hardest call.** Paying within 4.5 seconds of starting checkout is all that gives the careful bot away, but 17 genuine fans paid that fast too. At weight 3, R8 can block a session on its own: bots get none of the stock, and 24 fans in total are wrongly blocked. At weight 2, R8 only adds to other evidence: bots keep 12% of the stock (60 hoodies) and 8 fans are wrongly blocked. Weight 3 puts 60 more hoodies in fans' hands at the cost of 16 more wrongly blocked fans, so the rules use it.

**The threshold decides who pays for mistakes.** At threshold 1 the rules wrongly block 67 fans. At threshold 4 they block only 1, but bots' share of the stock rises back to 12%. Threshold 3 keeps bots out entirely while blocking the fewest fans.

## Limitations

- The data is synthetic, so the bots behave exactly as the simulation defines them. Real bots adapt.
- The thresholds and R8's 4.5-second cut-off were chosen on the same data they are scored on, knowing how the bots behave, so real-world accuracy would be lower.
- The rules read the whole log after the drop, like an investigation. Blocking in real time means deciding at checkout, with less information.
- User-agent strings are easy to fake, so R5 only catches careless bots.

## Next steps

- Challenge borderline sessions with an extra check, such as a CAPTCHA, instead of refusing them, so fast-paying fans can still buy.
- Real-time scoring at checkout.
- Testing an AI shopping assistant against prompt injection, such as customers talking it into discount codes.

## Run it

Needs Python 3.9 or later. There is nothing to install.

```bash
python3 generate_data.py
python3 detect.py
python3 -m unittest discover -s tests
```

The results above came from Python 3.13. Other versions may give slightly different numbers.

## About the data

Everything is synthetic. IP addresses come from documentation and shared ranges (RFC 5737, RFC 6598, RFC 3849) and email domains use reserved names (.example, .test), so no row describes a real person or network. Card fingerprints are random tokens, not card numbers.

## Credits

Built with Claude (Anthropic) as a coding collaborator.
