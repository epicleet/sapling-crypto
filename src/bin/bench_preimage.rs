extern crate sapling_crypto;
extern crate bellman;
extern crate rand;
extern crate pairing;

use std::time::{Duration, Instant};
use sapling_crypto::jubjub::{
    JubjubBls12,
};
use sapling_crypto::circuit::preimage::PreImage;
use bellman::groth16::*;
use rand::{XorShiftRng, SeedableRng, Rng};
use pairing::bls12_381::{Bls12, };

fn main() {
    let jubjub_params = &JubjubBls12::new();
    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    println!("Creating sample parameters...");
    let groth_params = generate_random_parameters::<Bls12, _, _>(
        PreImage {
            params: jubjub_params,
            team_preimg: None,
            chal_preimg: None,
        },
        rng
    ).unwrap();
    groth_params.write(std::fs::File::create("groth.params").unwrap()).unwrap();

    const SAMPLES: u32 = 50;

    let mut total_time = Duration::new(0, 0);
    for _ in 0..SAMPLES {
        let start = Instant::now();
        let _ = create_random_proof(PreImage {
            params: jubjub_params,
            team_preimg: Some(rng.gen()),
            chal_preimg: Some(rng.gen()),
        }, &groth_params, rng).unwrap();
        total_time += start.elapsed();
    }
    let avg = total_time / SAMPLES;
    let avg = avg.subsec_nanos() as f64 / 1_000_000_000f64
              + (avg.as_secs() as f64);

    println!("Average proving time (in seconds): {}", avg);
}
