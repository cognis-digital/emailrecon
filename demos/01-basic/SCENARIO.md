# Demo 01 - Basic: triaging an inbound address (offline)

This scenario shows EMAILRECON used purely **defensively**: a SOC analyst has
received a suspicious message from `admin@mailinator.com` and wants a fast,
offline triage of the address footprint plus a breach-corpus cross-check.

Everything here runs **with no network** (`--no-dns`) and against a small,
local breach corpus checked into this folder. Nothing is sent; no third-party
accounts are probed.

## Run it

```bash
# Human-readable triage
python -m emailrecon scan admin@mailinator.com \
    --no-dns --breach-corpus demos/01-basic/breach_corpus.txt

# Machine-readable for piping into a SIEM / ticket
python -m emailrecon scan admin@mailinator.com \
    --no-dns --breach-corpus demos/01-basic/breach_corpus.txt --format json
```

## What you should see

Findings of interest for this address:

* `DISPOSABLE_DOMAIN` (medium) - `mailinator.com` is a throwaway provider.
* `ROLE_ACCOUNT`     (medium) - `admin` is a functional/role local-part.
* `BREACH_HINT`      (high)   - the domain appears in the offline corpus.
* `DNS_NOT_CHECKED`  (info)   - DNS posture skipped because of `--no-dns`.

Because findings reach LOW or above, the process exits with code **3** -
handy for failing a pipeline gate or auto-escalating a ticket.

## Lawful-use note

EMAILRECON performs analysis on data you are authorized to assess. It does not
attempt to log in, enumerate accounts on external services, or send email.
