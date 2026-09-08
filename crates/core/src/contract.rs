//! Order contract: the taproot output that holds a limit order.
//!
//! Key path: user's refund key.
//! Leaf A: complete fill. Leaf B: partial fill.
//! See `docs/general.md` and `docs/script.md`.

use std::fmt;

use elements::address::Payload;
use elements::opcodes::all::*;
use elements::script::Builder;
use elements::secp256k1_zkp::{Secp256k1, XOnlyPublicKey};
use elements::taproot::{LeafVersion, TaprootBuilder, TaprootBuilderError, TaprootSpendInfo};
use elements::{Address, AddressParams, AssetId, Script};

/// `price_a` and `price_b` must fit in this many bits.
pub const MAX_PRICE_BITS: u32 = 20;
/// Amounts and minimum amounts must fit in this many bits, so that
/// `amount * price` never overflows a signed 64-bit integer.
pub const MAX_AMOUNT_BITS: u32 = 43;

/// Everything needed to build an order contract.
#[derive(Debug, Clone)]
pub struct ContractParams {
    /// Asset being sold.
    pub asset_a: AssetId,
    /// Asset being bought.
    pub asset_b: AssetId,
    /// Price numerator: `price_a / price_b` units of `asset_b` per unit of `asset_a`.
    pub price_a: u64,
    /// Price denominator.
    pub price_b: u64,
    /// Minimum fill and minimum change, in `asset_a`.
    pub min_amount_a: u64,
    /// Minimum payout, in `asset_b`.
    pub min_amount_b: u64,
    /// Unblinded taproot address that receives `asset_b`.
    pub payout: Address,
    /// Service key that must sign every fill.
    pub service_pk: XOnlyPublicKey,
    /// User key for the refund key path.
    pub user_pk: XOnlyPublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractError {
    SameAsset,
    PriceOutOfRange,
    MinAmountOutOfRange,
    PayoutBlinded,
    PayoutNotTaproot,
    PayoutInvalidKey,
    Taproot(TaprootBuilderError),
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SameAsset => write!(f, "asset_a and asset_b must differ"),
            Self::PriceOutOfRange => {
                write!(
                    f,
                    "price_a and price_b must be non-zero and below 2^{MAX_PRICE_BITS}"
                )
            }
            Self::MinAmountOutOfRange => write!(
                f,
                "min_amount_a and min_amount_b must be non-zero and below 2^{MAX_AMOUNT_BITS}"
            ),
            Self::PayoutBlinded => write!(f, "payout address must be unblinded"),
            Self::PayoutNotTaproot => write!(f, "payout address must be taproot"),
            Self::PayoutInvalidKey => write!(f, "payout address carries an invalid x-only key"),
            Self::Taproot(e) => write!(f, "taproot tree: {e}"),
        }
    }
}

impl std::error::Error for ContractError {}

impl From<TaprootBuilderError> for ContractError {
    fn from(e: TaprootBuilderError) -> Self {
        Self::Taproot(e)
    }
}

/// A validated order contract.
#[derive(Debug, Clone)]
pub struct Contract {
    asset_a: AssetId,
    asset_b: AssetId,
    price_a: u64,
    price_b: u64,
    min_amount_a: u64,
    min_amount_b: u64,
    /// Taproot output key of the payout address.
    payout_key: XOnlyPublicKey,
    service_pk: XOnlyPublicKey,
    user_pk: XOnlyPublicKey,
}

impl Contract {
    pub fn new(params: ContractParams) -> Result<Self, ContractError> {
        if params.asset_a == params.asset_b {
            return Err(ContractError::SameAsset);
        }
        if !fits(params.price_a, MAX_PRICE_BITS) || !fits(params.price_b, MAX_PRICE_BITS) {
            return Err(ContractError::PriceOutOfRange);
        }
        if !fits(params.min_amount_a, MAX_AMOUNT_BITS)
            || !fits(params.min_amount_b, MAX_AMOUNT_BITS)
        {
            return Err(ContractError::MinAmountOutOfRange);
        }
        let payout_key = payout_output_key(&params.payout)?;

        Ok(Self {
            asset_a: params.asset_a,
            asset_b: params.asset_b,
            price_a: params.price_a,
            price_b: params.price_b,
            min_amount_a: params.min_amount_a,
            min_amount_b: params.min_amount_b,
            payout_key,
            service_pk: params.service_pk,
            user_pk: params.user_pk,
        })
    }

    pub fn asset_a(&self) -> AssetId {
        self.asset_a
    }

    pub fn asset_b(&self) -> AssetId {
        self.asset_b
    }

    pub fn price_a(&self) -> u64 {
        self.price_a
    }

    pub fn price_b(&self) -> u64 {
        self.price_b
    }

    pub fn min_amount_a(&self) -> u64 {
        self.min_amount_a
    }

    pub fn min_amount_b(&self) -> u64 {
        self.min_amount_b
    }

    pub fn payout_key(&self) -> XOnlyPublicKey {
        self.payout_key
    }

    pub fn service_pk(&self) -> XOnlyPublicKey {
        self.service_pk
    }

    pub fn user_pk(&self) -> XOnlyPublicKey {
        self.user_pk
    }

    /// Leaf A. Witness: `<k> <service_sig>`.
    pub fn complete_fill_script(&self) -> Script {
        let b = self.payout_checks(Builder::new());
        // 2. output k value is explicit            # amount_b
        let b = verify_explicit(b.push_opcode(OP_INSPECTOUTPUTVALUE));
        // 5. amount_b >= min_amount_b
        let b = verify_ge(b.push_opcode(OP_DUP), self.min_amount_b);
        // 6. amount_a * price_a <= amount_b * price_b
        let b = verify_mul(b, self.price_b); // rhs
        let b = verify_explicit(
            b.push_opcode(OP_PUSHCURRENTINPUTINDEX)
                .push_opcode(OP_INSPECTINPUTVALUE),
        ); // rhs amount_a
        let b = verify_mul(b, self.price_a); // rhs lhs
        b.push_opcode(OP_GREATERTHANOREQUAL64).into_script()
    }

    /// Leaf B. Witness: `<k> <service_sig>`.
    pub fn partial_fill_script(&self) -> Script {
        let b = self.payout_checks(Builder::new());
        // 2. output k value is explicit            # k amount_b
        let b = verify_explicit(b.push_opcode(OP_DUP).push_opcode(OP_INSPECTOUTPUTVALUE));
        // 5. amount_b >= min_amount_b
        let b = verify_ge(b.push_opcode(OP_DUP), self.min_amount_b);
        // right-hand side of the price check       # k rhs
        let b = verify_mul(b, self.price_b);
        // # rhs k+1
        let b = b.push_opcode(OP_SWAP).push_opcode(OP_1ADD);
        // 6-7. output k+1 asset is explicit and equals asset_a
        let b = verify_explicit(b.push_opcode(OP_DUP).push_opcode(OP_INSPECTOUTPUTASSET))
            .push_slice(self.asset_a.as_byte_array())
            .push_opcode(OP_EQUALVERIFY);
        // 8. output k+1 scriptPubKey equals the current input's scriptPubKey
        let b = verify_taproot_version(
            b.push_opcode(OP_DUP)
                .push_opcode(OP_INSPECTOUTPUTSCRIPTPUBKEY),
        );
        let b = verify_taproot_version(
            b.push_opcode(OP_PUSHCURRENTINPUTINDEX)
                .push_opcode(OP_INSPECTINPUTSCRIPTPUBKEY),
        );
        let b = b.push_opcode(OP_EQUALVERIFY); // rhs k+1
        // 6. output k+1 value is explicit          # rhs change
        let b = verify_explicit(b.push_opcode(OP_INSPECTOUTPUTVALUE));
        // 9. change >= min_amount_a
        let b = verify_ge(b.push_opcode(OP_DUP), self.min_amount_a);
        // filled = amount_a - change               # rhs filled
        let b = verify_explicit(
            b.push_opcode(OP_PUSHCURRENTINPUTINDEX)
                .push_opcode(OP_INSPECTINPUTVALUE),
        );
        let b = b
            .push_opcode(OP_SWAP)
            .push_opcode(OP_SUB64)
            .push_opcode(OP_VERIFY);
        // 10. filled >= min_amount_a
        let b = verify_ge(b.push_opcode(OP_DUP), self.min_amount_a);
        // 11. filled * price_a <= amount_b * price_b
        let b = verify_mul(b, self.price_a); // rhs lhs
        b.push_opcode(OP_GREATERTHANOREQUAL64).into_script()
    }

    /// Unblinded taproot address of the order for the given network.
    pub fn address(&self, params: &'static AddressParams) -> Address {
        let info = self.spend_info();
        Address::p2tr_tweaked(info.output_key(), None, params)
    }

    /// scriptPubKey of the order output.
    pub fn script_pubkey(&self) -> Script {
        Script::new_v1_p2tr_tweaked(self.spend_info().output_key())
    }

    fn spend_info(&self) -> TaprootSpendInfo {
        let secp = Secp256k1::verification_only();
        TaprootBuilder::new()
            .add_leaf(1, self.complete_fill_script())
            .and_then(|t| t.add_leaf(1, self.partial_fill_script()))
            .and_then(|t| t.finalize(&secp, self.user_pk))
            .expect("two leaves at depth 1 always form a complete tree")
    }

    /// Steps 1-4 shared by both leaves: service signature, then output `k`
    /// asset and scriptPubKey. Leaves `k` on the stack.
    fn payout_checks(&self, b: Builder) -> Builder {
        // 1. service signature
        let b = b
            .push_slice(&self.service_pk.serialize())
            .push_opcode(OP_CHECKSIGVERIFY);
        // 2-3. output k asset is explicit and equals asset_b
        let b = verify_explicit(b.push_opcode(OP_DUP).push_opcode(OP_INSPECTOUTPUTASSET))
            .push_slice(self.asset_b.as_byte_array())
            .push_opcode(OP_EQUALVERIFY);
        // 4. output k scriptPubKey equals payout_spk
        verify_taproot_version(
            b.push_opcode(OP_DUP)
                .push_opcode(OP_INSPECTOUTPUTSCRIPTPUBKEY),
        )
        .push_slice(&self.payout_key.serialize())
        .push_opcode(OP_EQUALVERIFY)
    }
}

/// Leaf version used by both scripts.
pub fn leaf_version() -> LeafVersion {
    LeafVersion::default()
}

fn fits(v: u64, bits: u32) -> bool {
    v > 0 && v < (1u64 << bits)
}

fn payout_output_key(addr: &Address) -> Result<XOnlyPublicKey, ContractError> {
    if addr.blinding_pubkey.is_some() {
        return Err(ContractError::PayoutBlinded);
    }
    match &addr.payload {
        Payload::WitnessProgram { version, program }
            if version.to_u8() == 1 && program.len() == 32 =>
        {
            XOnlyPublicKey::from_slice(program).map_err(|_| ContractError::PayoutInvalidKey)
        }
        _ => Err(ContractError::PayoutNotTaproot),
    }
}

/// Consume the introspection prefix byte and require it to be explicit.
fn verify_explicit(b: Builder) -> Builder {
    b.push_opcode(OP_PUSHNUM_1).push_opcode(OP_EQUALVERIFY)
}

/// Consume the segwit version pushed by `OP_INSPECT*SCRIPTPUBKEY` and require taproot.
fn verify_taproot_version(b: Builder) -> Builder {
    b.push_opcode(OP_PUSHNUM_1).push_opcode(OP_EQUALVERIFY)
}

/// `top >= v`, consuming the top item.
fn verify_ge(b: Builder, v: u64) -> Builder {
    push_le64(b, v)
        .push_opcode(OP_GREATERTHANOREQUAL64)
        .push_opcode(OP_VERIFY)
}

/// `top * v`, aborting on overflow.
fn verify_mul(b: Builder, v: u64) -> Builder {
    push_le64(b, v).push_opcode(OP_MUL64).push_opcode(OP_VERIFY)
}

fn push_le64(b: Builder, v: u64) -> Builder {
    b.push_slice(&(v as i64).to_le_bytes())
}
