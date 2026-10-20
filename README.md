# Funnel Attack Detection — Suricata (Edge/Internal) + Splunk — SOC Fundamentals Project

**Authors:** Hosni Nheri & Wassim Amor
**Skills demonstrated:** Network IDS (Suricata) deployment and rule management, Docker container networking, Splunk Enterprise (data onboarding, SPL correlation search, scheduled alerting), attack simulation (`nmap`, `hydra`), SMTP alert integration, infrastructure troubleshooting

## Objective

Detect a **funnel attack** — the pattern where an attacker first performs reconnaissance against the network perimeter, then pivots to exploit an internal service shortly after — by correlating alerts from two independently deployed Suricata sensors and triggering an automated email notification when the pattern fires.

## Demo & Report

- 🎬 **Demo video:** [Project IDS.mp4]

https://github.com/user-attachments/assets/df02356f-05a8-4394-8c62-2db4abc77c07


  
- 📄 **Illustrated report (HTML):** [Funnel Attack Detection — Suricata & Splunk]https://htmlpreview.github.io/?https://github.com/HosniNheri1/Soc-Funnel-Attack-Suricata-Splunk/blob/main/report.html

## Architecture

```
Kali VM (nmap / hydra)
        │
        ▼
┌───────────────────┐     ┌──────────────────────┐
│ suricata-edge      │     │ suricata-internal     │
│ (reconnaissance)    │     │ (exploitation)         │
└──────────┬─────────┘     └───────────┬───────────┘
           │                            │
           └──────────────┬─────────────┘
                           ▼
                      eve.json
                           │
                           ▼
              Splunk Enterprise (index=main,
              sourcetype=suricata:eve)
                           │
                           ▼
         SPL correlation search (same src_ip,
         Edge alert → Internal alert within 60s)
                           │
                           ▼
              Scheduled alert (cron, every minute)
                           │
                           ▼
              Email notification (SMTP, Gmail)
```

| Component | Role | Details |
|---|---|---|
| `suricata-edge` | Reconnaissance sensor | Docker container, `--network host`, Emerging Threats Open ruleset |
| `suricata-internal` | Exploitation sensor | Docker container, `--network host`, same ruleset |
| `suricata-localtest` | Validation sensor | Listens on `lo`, used to validate the funnel against `127.0.0.1` |
| `correlation-engine` | Reference prototype | Python container implementing the same correlation logic outside Splunk |
| Splunk Enterprise | Indexing & alerting | `index=main`, SPL correlation search, scheduled alert, email action |

## 1. Deploying the sensors

```bash
docker run -d --name suricata-edge --network host jasonish/suricata:latest \
  -i eth0 -l /var/log/suricata/edge

docker run -d --name suricata-internal --network host jasonish/suricata:latest \
  -i eth0 -l /var/log/suricata/internal

suricata-update   # pulls the Emerging Threats Open ruleset (~69,171 rules, ~53,211 enabled)
```

Both sensors forward their `eve.json` alert log to Splunk via a standard `inputs.conf` monitor stanza, with `sourcetype=suricata:eve`.

## 2. Simulating the attack

No distinct target machine was available on the lab network, so the attack was run in a loop against `127.0.0.1`, observed by a dedicated sensor (`suricata-localtest`) listening on the loopback interface:

```bash
nmap -sS -p22,8000,8080 -T4 --max-retries 2 127.0.0.1
hydra -l kali -P /usr/share/wordlists/rockyou.txt ssh://127.0.0.1 -t 4 -f
```

- The `nmap` scan raises Suricata "edge" style alerts (flow/protocol anomalies).
- The `hydra` brute force raises the `SURICATA SSH invalid banner` signature, classified as "internal".

> **⚠️ Gotcha — attacking the wrong target.** The first scan targeted `192.168.124.128`, assumed to be a separate lab machine. It was actually the Kali VM's own IP, so the traffic went out over the loopback interface — never seen by the sensors listening on `eth0`. Fixed by adding a sensor dedicated to the `lo` interface and re-running the test against `127.0.0.1`.

## 3. Detection logic in Splunk (SPL)

```spl
index=main source="*/localtest/eve.json" event_type="alert"
| eval sig=mvindex('alert.signature',0)
| eval phase=if(match(sig,"SSH"),"internal","edge")
| sort _time
| eval edge_ts=if(phase="edge",_time,null())
| streamstats current=t last(edge_ts) as last_edge_time
| where phase="internal"
| eval delta_time = _time - last_edge_time
| where delta_time >= 0 AND delta_time <= 60
| stats earliest(_time) as first_alert, min(delta_time) as min_delta,
        values(sig) as internal_signatures, dc(sig) as nb_alerts by src_ip, dest_ip
| eval status="CRITICAL: Funnel Attack Detected"
| table status, src_ip, dest_ip, min_delta, nb_alerts, internal_signatures
```

Each event is tagged `edge` or `internal` based on its signature, then `streamstats` carries the timestamp of the last `edge` alert forward so it can be compared against every subsequent `internal` alert for the same host. Results are kept only when the gap is between 0 and 60 seconds.

**Result on a real run:** 56 correlated `CRITICAL: Funnel Attack Detected` events, `src_ip = dest_ip = 127.0.0.1`, delta on the order of a few milliseconds.

> **⚠️ Gotcha — wrong index.** The original `inputs.conf` pointed to `index=suricata`, which didn't exist in this Splunk instance — the data was actually landing in `main`. Fixed by correcting the search (and every reference to it) to the real index.

## 4. Alerting and email notification

| Parameter | Value |
|---|---|
| Name | `Funnel Attack Detection - Edge to Internal (60s)` |
| Type | Scheduled (cron) |
| Cron expression | `* * * * *` |
| Time range | Last 5 minutes |
| Trigger condition | Number of Results > 0 |
| Trigger action | Send email (SMTP, Gmail, TLS) |

Four consecutive scheduler executions, confirmed in `index=_internal sourcetype=scheduler`: `status=success`, `result_count=1`, `alert_actions=email`.

> **⚠️ Gotcha — Gmail rejecting the standard password.** The email trigger action ran successfully (`status=success`) but no email ever arrived. Root cause: Gmail refuses SMTP authentication with the normal account password when 2-step verification is enabled. Fixed by generating a dedicated **App Password** and using it in Splunk's SMTP settings instead.

**End-to-end result:** the email is received, showing `status=CRITICAL`, `src_ip=dest_ip=127.0.0.1`, `min_delta≈0.000007s`, `internal_signatures=SURICATA SSH invalid banner`.

## 5. Troubleshooting log — real gotchas hit along the way

- **No rules loaded** (`rules_loaded=0`) — neither sensor had ever run `suricata-update`. Fixed by running it in each container (Emerging Threats Open, ~69,171 rules).
- **AF_PACKET cluster conflict** (`cluster-id 99 already in use`) — both sensors tried to bind `eth0` at the same time on restart. Fixed by restarting them sequentially instead of in parallel.
- **Attacking the wrong target** — see section 2 above (own IP instead of a distinct host).
- **Wrong Splunk index** — see section 3 above (`index=suricata` didn't exist; data was in `main`).
- **Stuck monitoring checkpoint** — after truncating `eve.json` to reset the test data, Splunk's file monitor kept its old checkpoint and stopped ingesting. Fixed by recreating the input against a fresh file.
- **Invalid cron expression** — a UI input glitch produced `*****` instead of `* * * * *`. Fixed by pasting the expression rather than typing it character by character.
- **Gmail App Password requirement** — see section 4 above.

## Tools used

`Suricata` (Emerging Threats Open ruleset), `Splunk Enterprise` (SPL, scheduled alerting), `Docker` (host-network containers), `nmap`, `Hydra`, `Kali Linux`, Gmail SMTP (App Password authentication).

## Conclusion

The full chain — reconnaissance → exploitation → correlation → alert → email — was validated end to end, confirmed by Splunk's scheduler logs and by the actual receipt of the alert email. The project's value was less in the final green checkmark than in the seven real incidents worked through along the way: each one maps to a concrete lesson about rule management, container networking, Splunk indexing, and mail-provider authentication that a SOC analyst runs into in production.

---
**Hosni Nheri** & **Wassim Amor**
[LinkedIn](https://linkedin.com/in/hosni-nheri) · [GitHub](https://github.com/HosniNheri1)
