use circuit::boolean::{
    AllocatedBit,
    Boolean
};

use pairing::{
    Engine,
};

use bellman::{
    SynthesisError,
    ConstraintSystem,
    Circuit
};

use jubjub::{
    JubjubEngine,
};

use super::blake2s;
use super::multipack;

/// This is an instance of the `PreImage` circuit.
pub struct PreImage<'a, E: JubjubEngine> {
    pub params: &'a E::Params,
    pub team_preimg: Option<[u8; 16]>,
    pub chal_preimg: Option<[u8; 16]>,
}

impl<'a, E: JubjubEngine> Circuit<E> for PreImage<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError>
    {
        let team_preimg = witness_u128(
            cs.namespace(|| "team preimage"),
            self.team_preimg.as_ref().map(|v| &v[..])
        )?;

        let chal_preimg = witness_u128(
            cs.namespace(|| "chal preimage"),
            self.chal_preimg.as_ref().map(|v| &v[..])
        )?;

        let team_hash = blake2s::blake2s(
            cs.namespace(|| "team hash computation"),
            &team_preimg,
            b"teamkey_"
        )?;

        let chal_hash = blake2s::blake2s(
            cs.namespace(|| "chal hash computation"),
            &chal_preimg,
            b"chalkey_"
        )?;

        multipack::pack_into_inputs(cs.namespace(|| "team hash"), &team_hash)?;
        multipack::pack_into_inputs(cs.namespace(|| "chal hash"), &chal_hash)
    }
}

/// Witnesses some bytes in the constraint system,
/// skipping the first `skip_bits`.
fn witness_bits<E, CS>(
    mut cs: CS,
    value: Option<&[u8]>,
    num_bits: usize,
    skip_bits: usize
) -> Result<Vec<Boolean>, SynthesisError>
    where E: Engine, CS: ConstraintSystem<E>,
{
    let bit_values = if let Some(value) = value {
        let mut tmp = vec![];
        for b in value.iter()
                      .flat_map(|&m| (0..8).rev().map(move |i| m >> i & 1 == 1))
                      .skip(skip_bits)
        {
            tmp.push(Some(b));
        }
        tmp
    } else {
        vec![None; num_bits]
    };
    assert_eq!(bit_values.len(), num_bits);

    let mut bits = vec![];

    for (i, value) in bit_values.into_iter().enumerate() {
        bits.push(Boolean::from(AllocatedBit::alloc(
            cs.namespace(|| format!("bit {}", i)),
            value
        )?));
    }

    Ok(bits)
}

fn witness_u128<E, CS>(
    cs: CS,
    value: Option<&[u8]>,
) -> Result<Vec<Boolean>, SynthesisError>
    where E: Engine, CS: ConstraintSystem<E>,
{
    witness_bits(cs, value, 128, 0)
}

