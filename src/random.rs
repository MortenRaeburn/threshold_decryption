use num::{bigint::RandBigInt, BigUint};

pub fn rand_value(n: usize) -> BigUint {
    let mut rng = rand::thread_rng();
    rng.gen_biguint(n as u64)
}
