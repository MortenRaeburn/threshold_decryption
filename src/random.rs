use num::{bigint::RandBigInt, BigInt};

pub fn rand_value(n: usize) -> BigInt {
    let mut rng = rand::thread_rng();
    rng.gen_bigint(n as u64)
}
