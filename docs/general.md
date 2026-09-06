# General idea

There are two parties.

* **Users** create limit orders. An order sells `asset_a` for `asset_b` at a
  fixed price and is represented by a single UTXO.
* **The service** keeps the order book off-chain, matches orders, and builds
  the transactions that fill them. It never holds user funds.

The service signs fills, so only it can execute an order. Users can cancel
at any time. All order-related outputs are unblinded.

## Order lifecycle

1. The user asks the service for its pubkey and creates a fresh key pair,
   a fresh payout address, and the order parameters (see below).
2. The user derives the order's taproot address and sends `amount_a` of
   `asset_a` to it. This UTXO is the order. One UTXO per order; a top-up is
   a new order with a new key.
3. The service matches the order and broadcasts a fill transaction that
   spends the order UTXO through one of the script leaves. A partial fill
   creates a smaller order UTXO with the same script; a complete fill
   consumes it.
4. The user cancels by spending the order UTXO via the key path.

## Taproot layout

* **Key path**: user's key. Refund at any time.
* **Leaf A, complete fill**: the whole remaining `amount_a` is sold.
* **Leaf B, partial fill**: part of `amount_a` is sold, the rest returns to
  the same script.

The change output has the same taproot output key as the input, which
commits to both the internal key and the script tree. The script is
therefore recursive without needing to know its own content: it compares
its own input's scriptPubKey with the change output's scriptPubKey.

## Order parameters (constants in the script)

| Constant             | Meaning                                                                        |
|----------------------|--------------------------------------------------------------------------------|
| `asset_a`            | asset being sold                                                               |
| `asset_b`            | asset being bought                                                             |
| `price_a`, `price_b` | price as a ratio: `price_a / price_b` units of `asset_b` per unit of `asset_a` |
| `min_amount_a`       | minimum fill and minimum change, in `asset_a`                                  |
| `min_amount_b`       | minimum payout, in `asset_b` (dust guard)                                      |
| `payout_spk`         | scriptPubKey that receives `asset_b`                                           |
| `service_pk`         | service pubkey that must sign every fill                                       |

The client validates at order creation:

* `price_a`, `price_b` fit in 20 bits and amounts fit in 43 bits, so every
  product fits in a signed 64-bit integer.
* `min_amount_a` is above the dust threshold of `asset_a`.
* `min_amount_b` is above the dust threshold of `asset_b`.

## Fill transaction

Inputs: one or more order UTXOs, plus an L-BTC input from the service to
pay the fee. Outputs: for each order, a payout output at index `k`
(chosen by the service and passed in the witness), and for partial fills a
change output at index `k + 1`. The fee output and the service's own change
can sit at any unused index. The script does not constrain the number of
inputs or outputs.

Values used by the script:

* `amount_a`: value of the current input.
* `amount_b`: value of output `k`.
* `change`: value of output `k + 1`.

## Leaf A: complete fill

Witness: service signature, `k`.

1. `service_pk` signature is valid.
2. Output `k` value and asset prefixes are explicit.
3. Output `k` asset equals `asset_b`.
4. Output `k` scriptPubKey equals `payout_spk`.
5. `amount_b >= min_amount_b`.
6. `amount_a * price_a <= amount_b * price_b`.

## Leaf B: partial fill

Witness: service signature, `k`.

1. `service_pk` signature is valid.
2. Output `k` value and asset prefixes are explicit.
3. Output `k` asset equals `asset_b`.
4. Output `k` scriptPubKey equals `payout_spk`.
5. `amount_b >= min_amount_b`.
6. Output `k + 1` value and asset prefixes are explicit.
7. Output `k + 1` asset equals `asset_a`.
8. Output `k + 1` scriptPubKey equals the current input's scriptPubKey.
9. `change >= min_amount_a`.
10. `amount_a - change >= min_amount_a`.
11. `(amount_a - change) * price_a <= amount_b * price_b`.
