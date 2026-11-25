# CCS column — fourth column on the AP2 crosswalk fixtures (google-agentic-commerce/AP2#402)

Independent CCS receipt-layer judgment over the same pinned fixtures used by the
AER-1 × AMEP × APAF-1 three-way join:

- `sdk-bundles.json` (SHA-256 `7e1dd6d9…40b61f`)
- `sdk-bundles-v2.json` (SHA-256 `70626262…c4a63a05`)
- `bundles.json` (SHA-256 `bd530228…1c4fc` full: `bd530228cb9880d33f49016ab85f426a6c0e9668f3b6e47734b4aa779a71c4fc`)

Fixtures are NOT copied here — the CI downloads them from
[stafordtituss/amep](https://github.com/stafordtituss/amep)
(`packages/conformance/test/fixtures/ap2/`), verifies all three SHA-256 pins, then replays.

## What this column judges

- **Record layer**: every ES256 signature recomputed against the trust keys / cnf-delegated
  agent key; every SD-JWT disclosure digest resolved recursively (nested `…` and `_sd`);
  KB-JWT `sd_hash` recomputed; **plus the `issuer_jwt_hash` variant binding** (hash of the
  issuer JWT only) — see Finding F4.
- **Receipt binding rule**: `receipt.reference == base64url(sha256(KB-JWT segment))` — receipts
  matched to presentations by recomputation, never by position.
- **Decision layer**: amount_range, allowed payees, cumulative budget (major/minor unit
  conversion stated per row), closed-mandate replay, hop-expiry.
- **v2 checkout bindings**: `conditional_transaction_id == sd_hash(checkout KB)`,
  `checkout_hash == transaction_id`.
- **Dictionary**: `verified` / `violated` (with `departed` named) / `unresolved` (with `missing`
  named; unknown outcomes are held, never promoted).

## Findings

- **F1** receipt reference rule recomputes on 31/32 receipts across all three families; the one
  miss is the designed negative `s7-receipt-for-another-mandate` (caught, held `unresolved`).
- **F2** the s8 join key (`checkout_hash == transaction_id` + `conditional_transaction_id ==
  checkout kb sd_hash`) verified on every v2 row; `sdk-ref-checkout-absent` held `unresolved`.
- **F3** budget recompute catches `sdk-budget` txn-2 (349.00 > 300.00) and synthetic s6 txn-2.
- **F4** the `sdk-issuer-jwt-hash` fixture is **not a tamper case**: its KB binds via
  `issuer_jwt_hash == base64url(sha256(issuer JWT))`, a self-consistent variant that commits the
  issuer-signed JWT only (per-disclosure digests still anchor the claim set). Our first draft
  mis-scored it `violated`; the published column verifies the variant and emits a named
  observation. It is a **binding-variant conformance test, not an integrity failure**.
- **Gap (printed as a gap)**: receipts carry no amount; the settled value is not establishable
  from these artifacts.

## Replay

```
python3 column.py          # exit 0 = all 11 self-checks achieved
sha256sum -c manifest.sha256
```

Latest: `ccs-column.json` — 38 rows across three families (16 verified / 14 violated / 8 unresolved).

## License

Code MIT (see LICENSE); our outputs CC0 1.0. Fixture copyright stays with its authors.
