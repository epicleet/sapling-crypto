# Preimage experiment

We have implemented a simple [preimage circuit](src/circuit/preimage/mod.rs) which checks whether two distinct 128-bit witnesses are the preimage of two different Blake2b public hash values.

## Running the experiment

```
cargo build --release
./target/release/bench_preimage
```

## Results

 * Size of the public parameters file (`groth.params`): 23041944 bytes
 * Mean running time (Intel Core i7-5500U CPU): 1.4 seconds
