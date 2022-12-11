#![feature(iter_intersperse)]

use std::{time::Instant, vec};

use rand::Rng;
use threshold::Dealer;

use crate::pke::Pke;

mod lagrange;
mod lwe;
mod pke;
mod random;
mod threshold;

fn main() {
    let mut rng = rand::thread_rng();
    const INIT_N: usize = 25;
    const STEPS: usize = 10;

    let params = vec![
        "n",
        "keygen",
        "encrypt",
        "decrypt",
        "dealer",
        "dealer_encrypt",
        "dealer_decrypt",
    ];
    let mut benchmarks = Vec::with_capacity(STEPS);

    for n in INIT_N..INIT_N + STEPS {
        println!("---Starting round---");
        let mut benchmark = Vec::with_capacity(7);
        benchmark.push(n as u128);

        println!("n: {n}");

        let crypto = lwe::Lwe::new(n);
        let m = rng.gen_range(0..=1);
        println!("m: {m}");

        let now = Instant::now();
        let (pk, sk) = crypto.keygen();
        let keygen_time = now.elapsed();

        benchmark.push(keygen_time.as_micros());

        let now = Instant::now();
        let c = crypto.encrypt(&pk, &m);
        let encrypt_time = now.elapsed();

        benchmark.push(encrypt_time.as_micros());

        let now = Instant::now();
        let d = crypto.decrypt(&sk, &c);
        let decrypt_time = now.elapsed();

        benchmark.push(decrypt_time.as_micros());

        println!("Standard LWE: {d}");

        let now = Instant::now();
        let dealer = Dealer::new(n);
        let dealer_time = now.elapsed();

        benchmark.push(dealer_time.as_micros());

        let now = Instant::now();
        let c = dealer.encrypt(&m);
        let dealer_encrypt_time = now.elapsed();

        benchmark.push(dealer_encrypt_time.as_micros());

        let now = Instant::now();
        let res = dealer.decrypt(&c);
        let dealer_decrypt = now.elapsed();

        benchmark.push(dealer_decrypt.as_micros());

        for (p, r) in res {
            println!("Party {p}: {r}")
        }

        benchmarks.push(benchmark);
        println!("---Ending round---")
    }

    params
        .iter()
        .intersperse(&",")
        .for_each(|param| print!("{param}"));

    println!();

    for benchmark in benchmarks {
        benchmark
            .iter()
            .map(|v| v.to_string())
            .intersperse(",".to_string())
            .for_each(|s| print!("{s}"));

        println!()
    }
}
