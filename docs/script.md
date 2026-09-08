# Order scripts

Full Liquid tapscript for the two leaves described in `general.md`.
Both leaves live in the taproot tree of the order address. The key path is
the user's refund key and has no script.

## Conventions

* Elements tapscript leaf version is `0xc4`.
* `<service_pk>`: 32-byte x-only pubkey push.
* `<asset_a>`, `<asset_b>`: 32-byte asset id push in internal byte order
  (reverse of the hex shown by explorers).
* `<le64(x)>`: 8-byte signed little-endian push. Used for every amount and
  price constant so it can feed the 64-bit opcodes directly.
* `<payout_key>`: 32-byte taproot output key of `payout_spk`. The payout
  address is always taproot, so the version is checked against `OP_1`.
* Introspection opcodes push a prefix byte on top of the value they return.
  `0x01` means explicit. `OP_1 OP_EQUALVERIFY` checks it and drops it.
* `OP_ADD64`, `OP_SUB64`, `OP_MUL64` push a success flag on top of the
  result. `OP_VERIFY` consumes the flag and aborts on overflow.
* 64-bit binary ops take `b` from the top of the stack and `a` from below
  it and compute `a op b`.
* The script must finish with exactly one true item on the stack.

Witness for both leaves, bottom to top:

```
<k> <service_sig> <leaf_script> <control_block>
```

`k` is the index of the payout output as a minimal script number. The
signature is on top so `OP_CHECKSIGVERIFY` can consume it first.

## Leaf A: complete fill

```
# 1. service signature
<service_pk> OP_CHECKSIGVERIFY
                                          # stack: k

# 2-3. output k asset is explicit and equals asset_b
OP_DUP OP_INSPECTOUTPUTASSET              # k asset prefix
OP_1 OP_EQUALVERIFY                       # k asset
<asset_b> OP_EQUALVERIFY                  # k

# 4. output k scriptPubKey equals payout_spk
OP_DUP OP_INSPECTOUTPUTSCRIPTPUBKEY       # k key ver
OP_1 OP_EQUALVERIFY                       # k key
<payout_key> OP_EQUALVERIFY               # k

# 2. output k value is explicit
OP_INSPECTOUTPUTVALUE                     # amount_b prefix
OP_1 OP_EQUALVERIFY                       # amount_b

# 5. amount_b >= min_amount_b
OP_DUP <le64(min_amount_b)>
OP_GREATERTHANOREQUAL64 OP_VERIFY         # amount_b

# 6. amount_a * price_a <= amount_b * price_b
<le64(price_b)> OP_MUL64 OP_VERIFY        # rhs
OP_PUSHCURRENTINPUTINDEX
OP_INSPECTINPUTVALUE                      # rhs amount_a prefix
OP_1 OP_EQUALVERIFY                       # rhs amount_a
<le64(price_a)> OP_MUL64 OP_VERIFY        # rhs lhs
OP_GREATERTHANOREQUAL64                   # rhs >= lhs
```

## Leaf B: partial fill

```
# 1. service signature
<service_pk> OP_CHECKSIGVERIFY
                                          # stack: k

# 2-3. output k asset is explicit and equals asset_b
OP_DUP OP_INSPECTOUTPUTASSET              # k asset prefix
OP_1 OP_EQUALVERIFY                       # k asset
<asset_b> OP_EQUALVERIFY                  # k

# 4. output k scriptPubKey equals payout_spk
OP_DUP OP_INSPECTOUTPUTSCRIPTPUBKEY       # k key ver
OP_1 OP_EQUALVERIFY                       # k key
<payout_key> OP_EQUALVERIFY               # k

# 2. output k value is explicit
OP_DUP OP_INSPECTOUTPUTVALUE              # k amount_b prefix
OP_1 OP_EQUALVERIFY                       # k amount_b

# 5. amount_b >= min_amount_b
OP_DUP <le64(min_amount_b)>
OP_GREATERTHANOREQUAL64 OP_VERIFY         # k amount_b

# right-hand side of the price check
<le64(price_b)> OP_MUL64 OP_VERIFY        # k rhs
OP_SWAP OP_1ADD                           # rhs k+1

# 6-7. output k+1 asset is explicit and equals asset_a
OP_DUP OP_INSPECTOUTPUTASSET              # rhs k+1 asset prefix
OP_1 OP_EQUALVERIFY                       # rhs k+1 asset
<asset_a> OP_EQUALVERIFY                  # rhs k+1

# 8. output k+1 scriptPubKey equals the current input's scriptPubKey
OP_DUP OP_INSPECTOUTPUTSCRIPTPUBKEY       # rhs k+1 prog_out ver_out
OP_1 OP_EQUALVERIFY                       # rhs k+1 prog_out
OP_PUSHCURRENTINPUTINDEX
OP_INSPECTINPUTSCRIPTPUBKEY               # rhs k+1 prog_out prog_in ver_in
OP_1 OP_EQUALVERIFY                       # rhs k+1 prog_out prog_in
OP_EQUALVERIFY                            # rhs k+1

# 6. output k+1 value is explicit
OP_INSPECTOUTPUTVALUE                     # rhs change prefix
OP_1 OP_EQUALVERIFY                       # rhs change

# 9. change >= min_amount_a
OP_DUP <le64(min_amount_a)>
OP_GREATERTHANOREQUAL64 OP_VERIFY         # rhs change

# filled = amount_a - change
OP_PUSHCURRENTINPUTINDEX
OP_INSPECTINPUTVALUE                      # rhs change amount_a prefix
OP_1 OP_EQUALVERIFY                       # rhs change amount_a
OP_SWAP OP_SUB64 OP_VERIFY                # rhs filled

# 10. filled >= min_amount_a
OP_DUP <le64(min_amount_a)>
OP_GREATERTHANOREQUAL64 OP_VERIFY         # rhs filled

# 11. filled * price_a <= amount_b * price_b
<le64(price_a)> OP_MUL64 OP_VERIFY        # rhs lhs
OP_GREATERTHANOREQUAL64                   # rhs >= lhs
```
