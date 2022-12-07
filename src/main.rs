use pke::Pke;
use threshold::Dealer;

mod lwe;
mod pke;
mod random;
mod shamir;
mod threshold;

fn main() {
    let m = 1;
    let n = 10;
    let crypto = lwe::Lwe::new(n);

    loop {
        // let (pk, sk) = crypto.keygen();
        // let c = crypto.encrypt(&pk, &m);
        // let d = crypto.decrypt(&sk, &c);

        // println!("{d}");

        let dealer = Dealer::new(n);
        let c = dealer.encrypt(&m);
        dealer.decrypt(&c);
    }
}
