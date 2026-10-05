# Buyer Intake Form — IoT-Ready Honeypot Security Monitoring

> How to use: copy the email below as-is (fill the placeholders), and send either the enclosed form
> inline or as a Google Form. The 12 questions are the absolute minimum needed to scope a deployment
> in one visit.

---

## Ready-to-send email

**Subject:** Your free network security review offer — [BUSINESS NAME]

[SALUTATION],

Thank you for your interest in our network monitoring service for [BUSINESS TYPE] businesses.

Small businesses are the main target of automated online attacks, and most owners never know it
is happening until something is stolen. Our service places a tiny monitoring device on your network
that **attracts and records attack attempts** — who they are, where in the world they come from,
and what they tried. You get a live dashboard with a world map, automatic alerts, and monthly
forensic reports you can hand to the police or your insurer if anything ever happens.

It costs roughly **[RM 30]** one-time for the device plus **[RM X/mo]** for the monitoring service,
and it does **not** change any of your router or firewall settings.

To confirm we can deploy it at your premises, please reply with the 12 quick questions below
(fastest: just answer A1–D1). If everything checks out, we can have it running within **2 working days**.

Best regards,

[YOUR NAME]
[PHONE] | [EMAIL]

---

## The Form — 12 Questions

### Section A — Business & contact
| # | Question | Why we ask |
|---|----------|------------|
| A1 | Company name & business type | Contract & reports |
| A2 | Contact person, email, phone | Dashboard account |
| A3 | Who manages your network and router? (owner / external IT / none) | Who approves the install |
| A4 | How many locations does your business have? | 1 device per location |

### Section B — Network & device placement
| # | Question | Why we ask |
|---|----------|------------|
| B1 | Do you have Wi-Fi? What is the network name (SSID)? | ESP32 connects to 2.4 GHz Wi-Fi |
| B2 | Does the router broadcast **2.4 GHz** (not only 5 GHz)? | ESP32 does not support 5 GHz — hard requirement |
| B3 | Can a hand-sized device be plugged into power within ~10 m of the router? | Placement for stable Wi-Fi |
| B4 | Roughly how many devices (phones, PCs, cameras, printers) are on the network? | Baseline for the risk report |

### Section C — Service scope
| # | Question | Why we ask |
|---|----------|------------|
| C1 | Monitor *(a)* inside your network, *(b)* attacks against your public internet address, or *(c)* both? | (b) needs a small cloud server — slightly higher monthly fee |
| C2 | How many staff need dashboard access? | Admin accounts |
| C3 | Do you want monthly PDF reports for insurance/regulatory use? | Included in service |
| C4 | Who is the security contact for alert follow-up? | Escalation path |

### Section D — Terms & scheduling
| # | Question | Why we ask |
|---|----------|------------|
| D1 | Which days are you available for a 30-minute acceptance test? | We demo live attacks and you sign off |
| D2 | Data consent: the device captures real attackers' IP addresses. Do you agree to store this data and receive de-identified public reports only? | Legal requirement for us |
| D3 | Do you have an existing firewall, antivirus, or monitoring tool in place? | Avoid duplicate/conflicting tools |
| D4 | Target go-live date? | Scheduling |

---

## Pre-flight checklist (you check this, before promising anything)

- [ ] Router confirmed to broadcast **2.4 GHz** — if it's 5 GHz-only, the ESP32 will not connect. Test on-site before booking install.
- [ ] Power outlet available within Wi-Fi range of the router.
- [ ] Client understands the device is a **decoy/logger** — it detects and records attacks, it does **not** block attacks on their real devices.
- [ ] Client agrees no port forwarding is needed (or wanted) — the device calls out to your cloud backend only.
- [ ] Monthly hosting cost budgeted: shared console (cheaper) vs dedicated instance (recommended).
- [ ] One-page agreement signed (see `client_agreement.md`).