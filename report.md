# Drop Guard results

Synthetic drop: 500 units, 1821 sessions (1461 genuine fans, 360 bots from 4 operators). Threshold: score of 3 or more.

## Who got the stock

| | Units to bots | Share of the drop | Genuine fans wrongly blocked |
| --- | ---: | ---: | ---: |
| No defences | 306 | 61% | 0 |
| Rules R1-R8 | 0 | 0% | 24 |

## Detection accuracy

Precision 94% · recall 98% · F1 0.96 (353 bots caught, 24 fans flagged, 7 bots missed).

| Rule | What it looks for | Threat | Weight | Sessions hit | Bots | Fans |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| R1 Superhuman add-to-cart | Added to cart less than 2 seconds after the first page view. | OAT-006 Expediting | 2 | 244 | 232 | 12 |
| R2 Crowded IP address | More than 8 accounts used one IP address during the drop. | OAT-005 Scalping | 1 | 193 | 150 | 43 |
| R3 Card shared across accounts | One payment card was used by 3 or more accounts. | OAT-005 Scalping | 2 | 257 | 245 | 12 |
| R4 Card testing | 3 or more declined payments using 3 or more different cards in one session. | OAT-001 Carding | 3 | 30 | 30 | 0 |
| R5 Automation signature | The browser identifies itself as a script or headless browser. | OAT-005 Scalping | 3 | 120 | 120 | 0 |
| R6 Mailbox farm | 3 or more accounts lead to one mailbox through +tags (name+1@, name+2@...). | OAT-005 Scalping | 2 | 120 | 120 | 0 |
| R7 Catch-all domain | 20 or more accounts on one email domain that isn't a big webmail provider. | OAT-005 Scalping | 1 | 150 | 150 | 0 |
| R8 Scripted payment | Paid less than 4.5 seconds after starting checkout. | OAT-006 Expediting | 3 | 343 | 326 | 17 |

## Flagged by actor

| Actor | Sessions | Flagged | Share flagged |
| --- | ---: | ---: | ---: |
| A-naive-scalper | 120 | 120 | 100% |
| B-proxy-network | 150 | 143 | 95% |
| C-card-tester | 30 | 30 | 100% |
| D-careful-bot | 60 | 60 | 100% |
| human | 1461 | 24 | 1.6% |

## Choosing the threshold

| Threshold | Precision | Recall | Fans wrongly blocked | Bots' share of stock |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 83% | 100% | 67 | 0% |
| 2 | 90% | 98% | 39 | 0% |
| 3 | 94% | 98% | 24 | 0% |
| 4 | 100% | 76% | 1 | 12% |
| 5 | 100% | 74% | 1 | 12% |
| 6 | 100% | 74% | 0 | 12% |
