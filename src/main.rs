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
    let n = 25;
    let crypto = lwe::Lwe::new(n);

    loop {
        println!("---Starting round---");
        // let m = rng.gen_range(0..=1);
        let m = 1;
        println!("m: {m}");

        // let (pk, sk) = crypto.keygen();
        // let c = crypto.encrypt(&pk, &m);
        // let d = crypto.decrypt(&sk, &c);

        // println!("{d}");

        let dealer = Dealer::new(n);
        let c = dealer.encrypt(&m);
        dealer.decrypt(&c);
        println!("---Ending round---")
    }
}
