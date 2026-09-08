//! Order contract: the taproot output that holds a limit order.
//!
//! Key path: user's refund key.
//! Leaf A: complete fill. Leaf B: partial fill.
//! See `docs/general.md` and `docs/script.md`.

use std::fmt;

use elements::address::Payload;
use elements::opcodes::all::*;
use elements::schnorr::TweakedPublicKey;
use elements::script::Builder;
use elements::secp256k1_zkp::{PublicKey, Secp256k1, XOnlyPublicKey};
use elements::taproot::{LeafVersion, TaprootBuilder, TaprootBuilderError};
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
    /// Unblinded taproot address that receives `asset_b`. The script compares
    /// the payout output's witness program against this address's 32-byte
    /// taproot output key.
    pub payout: Address,
    /// Service key that must sign every fill.
    pub service_pk: PublicKey,
    /// User key for the refund key path.
    pub user_pk: PublicKey,
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

/// A validated order contract with its taproot tree already built.
#[derive(Debug, Clone)]
pub struct Contract {
    params: ContractParams,
    /// 32-byte taproot output key of the payout address.
    payout_program: [u8; 32],
    /// Taproot output key of the order itself.
    output_key: TweakedPublicKey,
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
        let payout_program = payout_program(&params.payout)?;

        let secp = Secp256k1::verification_only();
        let output_key = TaprootBuilder::new()
            .add_leaf(1, complete_fill_script(&params, &payout_program))?
            .add_leaf(1, partial_fill_script(&params, &payout_program))?
            .finalize(&secp, XOnlyPublicKey::from(params.user_pk))?
            .output_key();

        Ok(Self {
            params,
            payout_program,
            output_key,
        })
    }

    pub fn params(&self) -> &ContractParams {
        &self.params
    }

    /// Leaf A. Witness: `<k> <service_sig>`.
    pub fn complete_fill_script(&self) -> Script {
        complete_fill_script(&self.params, &self.payout_program)
    }

    /// Leaf B. Witness: `<k> <service_sig>`.
    pub fn partial_fill_script(&self) -> Script {
        partial_fill_script(&self.params, &self.payout_program)
    }

    /// Unblinded taproot address of the order for the given network.
    pub fn address(&self, params: &'static AddressParams) -> Address {
        Address::p2tr_tweaked(self.output_key, None, params)
    }

    /// scriptPubKey of the order output.
    pub fn script_pubkey(&self) -> Script {
        Script::new_v1_p2tr_tweaked(self.output_key)
    }
}

/// Leaf version used by both scripts.
pub fn leaf_version() -> LeafVersion {
    LeafVersion::default()
}

fn complete_fill_script(p: &ContractParams, payout_program: &[u8; 32]) -> Script {
    // 1. service signature                     # k
    let b = Builder::new()
        .push_slice(&XOnlyPublicKey::from(p.service_pk).serialize())
        .push_opcode(OP_CHECKSIGVERIFY);
    // 2-3. output k asset is explicit and equals asset_b
    let b = verify_explicit(b.push_opcode(OP_DUP).push_opcode(OP_INSPECTOUTPUTASSET))
        .push_slice(p.asset_b.as_byte_array())
        .push_opcode(OP_EQUALVERIFY);
    // 4. output k scriptPubKey equals payout_spk
    let b = verify_taproot_version(
        b.push_opcode(OP_DUP)
            .push_opcode(OP_INSPECTOUTPUTSCRIPTPUBKEY),
    )
    .push_slice(payout_program)
    .push_opcode(OP_EQUALVERIFY);
    // 2. output k value is explicit            # amount_b
    let b = verify_explicit(b.push_opcode(OP_INSPECTOUTPUTVALUE));
    // 5. amount_b >= min_amount_b
    let b = verify_ge(b.push_opcode(OP_DUP), p.min_amount_b);
    // 6. amount_a * price_a <= amount_b * price_b
    let b = verify_mul(b, p.price_b); // rhs
    let b = verify_explicit(
        b.push_opcode(OP_PUSHCURRENTINPUTINDEX)
            .push_opcode(OP_INSPECTINPUTVALUE),
    ); // rhs amount_a
    let b = verify_mul(b, p.price_a); // rhs lhs
    b.push_opcode(OP_GREATERTHANOREQUAL64).into_script()
}

fn partial_fill_script(p: &ContractParams, payout_program: &[u8; 32]) -> Script {
    // 1. service signature                     # k
    let b = Builder::new()
        .push_slice(&XOnlyPublicKey::from(p.service_pk).serialize())
        .push_opcode(OP_CHECKSIGVERIFY);
    // 2-3. output k asset is explicit and equals asset_b
    let b = verify_explicit(b.push_opcode(OP_DUP).push_opcode(OP_INSPECTOUTPUTASSET))
        .push_slice(p.asset_b.as_byte_array())
        .push_opcode(OP_EQUALVERIFY);
    // 4. output k scriptPubKey equals payout_spk
    let b = verify_taproot_version(
        b.push_opcode(OP_DUP)
            .push_opcode(OP_INSPECTOUTPUTSCRIPTPUBKEY),
    )
    .push_slice(payout_program)
    .push_opcode(OP_EQUALVERIFY);
    // 2. output k value is explicit            # k amount_b
    let b = verify_explicit(b.push_opcode(OP_DUP).push_opcode(OP_INSPECTOUTPUTVALUE));
    // 5. amount_b >= min_amount_b
    let b = verify_ge(b.push_opcode(OP_DUP), p.min_amount_b);
    // right-hand side of the price check       # k rhs
    let b = verify_mul(b, p.price_b);
    // # rhs k+1
    let b = b.push_opcode(OP_SWAP).push_opcode(OP_1ADD);
    // 6-7. output k+1 asset is explicit and equals asset_a
    let b = verify_explicit(b.push_opcode(OP_DUP).push_opcode(OP_INSPECTOUTPUTASSET))
        .push_slice(p.asset_a.as_byte_array())
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
    let b = verify_ge(b.push_opcode(OP_DUP), p.min_amount_a);
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
    let b = verify_ge(b.push_opcode(OP_DUP), p.min_amount_a);
    // 11. filled * price_a <= amount_b * price_b
    let b = verify_mul(b, p.price_a); // rhs lhs
    b.push_opcode(OP_GREATERTHANOREQUAL64).into_script()
}

fn fits(v: u64, bits: u32) -> bool {
    v > 0 && v < (1u64 << bits)
}

/// Check the payout address is an unblinded taproot address and return its
/// 32-byte output key.
fn payout_program(addr: &Address) -> Result<[u8; 32], ContractError> {
    if addr.blinding_pubkey.is_some() {
        return Err(ContractError::PayoutBlinded);
    }
    let program = match &addr.payload {
        Payload::WitnessProgram { version, program } if version.to_u8() == 1 => program,
        _ => return Err(ContractError::PayoutNotTaproot),
    };
    let program: [u8; 32] = program
        .as_slice()
        .try_into()
        .map_err(|_| ContractError::PayoutNotTaproot)?;
    XOnlyPublicKey::from_slice(&program).map_err(|_| ContractError::PayoutInvalidKey)?;
    Ok(program)
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
