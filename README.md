# Threshold Decryption
## Setup
Install the latest version of Rust nightly from: [https://rustup.rs/](https://rustup.rs/)

**IMPORTANT:** It will *NOT* work with Rust stable, as we are using unstable features in this project

## Executing the code
To execute the code, you must have your current working directory be the root of this GitHub repo.

After this (assuming that Rust is installed), you must run the following command:

```
cargo run --release
```

It is important to run with the `--release` flag, as otherwise, the code will be unoptimized. Optimizations for this project are VERY important, as the algorithm is very inefficient and takes *MUCH* longer without optimizations.
For this reason, it is also recommended that the code is run on a powerful modern computer with good single-threaded performance (multiple cores will not improve the performance, as the code is single-threaded).

## Output
The following is an example output for a given round:

```
---Starting round---
n: 25
m: 1
Standard LWE: 1
Party 1: 1
Party 2: 1
Party 3: 1
Party 4: 1
Party 5: 1
Party 6: 1
Party 7: 1
Party 8: 1
Party 9: 1
Party 10: 1
---Ending round---
```

- n: The choice of n.
- m: The bit to be encrypted/decrypted.
- Standard LWE: The output of dec(enc(m)) for the LWE crypto system (non-distributed).
- Party 1-10: The output of dec(enc(m)) for each party in the threshold decryption setting.

Lastly, after the final step, it will output the result of the benchmarks in `csv` format.


## Reviewing the code
The code is located entirely the the `src` directory. The code is split into modules, and the benchmarking code can be found in `main.rs`. Here the choice of `INIT_N` and `STEPS` can be set. To change the number of parties in the distributed setting, the variable `NUMBER_OF_PARTIES` in `threshold.rs` can be set.