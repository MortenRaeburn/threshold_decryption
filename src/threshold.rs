use num::{
    bigint::{RandBigInt, RandomBits},
    BigUint, Zero,
};
use rand::{rngs::SmallRng, Rng, SeedableRng};

const NUMBER_OF_PARTIES: usize = 6;

use crate::{
    lwe::{self, Ciphertext},
    pke::Pke,
    shamir::{interpolate, Share},
};

struct Party {
    number: usize,
    sk: Option<lwe::SecretKey>,
    pk: Option<lwe::PublicKey>,
    crypto: lwe::Lwe,
    keys: Vec<BigUint>,
}

impl Party {
    fn new(number: usize, crypto: lwe::Lwe) -> Self {
        let keys = Vec::new();

        Self {
            number,
            sk: None,
            pk: None,
            keys,
            crypto,
        }
    }

    pub fn rand_value(&self, n: usize) -> BigUint {
        let mut rng = rand::thread_rng();
        rng.gen_biguint(n as u64)
    }

    fn set_sk(&mut self, sk: &lwe::SecretKey) {
        self.sk = Some(sk.clone());
    }

    fn decrypt1(&self, c: &lwe::Ciphertext) -> Share {
        let sk = self.sk.clone().unwrap(); //At this point, we know that sk should be Some - which is after keygen

        let a = &c.0;
        let b = &c.1;

        let e = b - a
            .iter()
            .zip(sk)
            .fold(BigUint::zero(), |acc, (a, sk)| acc + a * sk);

        let x = self.gen_x(&self.keys, c);

        Share(self.number, x + e)
    }

    fn gen_x(&self, keys: &Vec<BigUint>, c: &lwe::Ciphertext) -> BigUint {
        keys.iter().fold(BigUint::zero(), |acc, key| {
            acc + rand_from_cipher_and_key(c, key)
        })
    }

    fn decrypt2(&self, shares: &[Share]) -> lwe::Plaintext {
        let m = interpolate(shares)(0);
        let q = &self.crypto.q;

        let lower = q / 4u32;
        let upper = q + &lower;

        if m < lower && upper < m {
            return 1;
        }

        0
    }
}

fn rand_from_cipher_and_key(c: &Ciphertext, key: &BigUint) -> BigUint {
    let mut rng = SmallRng::seed_from_u64(0);

    todo!()
}

pub struct Dealer {
    parties: Vec<Party>,
    pk: lwe::PublicKey,
    crypto: lwe::Lwe,
}

impl Dealer {
    pub fn new(n: usize) -> Self {
        let crypto = lwe::Lwe::new(n);
        let parties = (0..NUMBER_OF_PARTIES)
            .map(|number| Party::new(number, crypto.clone()))
            .collect::<Vec<_>>();
        let pk = todo!();

        Self {
            parties,
            crypto,
            pk,
        }
    }

    pub fn keygen(&self) {
        let mut shares = Vec::new();

        for party in &self.parties {
            let r_val = party.rand_value(self.crypto.n);
            let share = Share(party.number, r_val);
            shares.push(share);

            todo!()
        }

        todo!()
    }

    pub fn encrypt(&self, m: &lwe::Plaintext) -> lwe::Ciphertext {
        self.crypto.encrypt(&self.pk, m)
    }

    pub fn decrypt(&self, c: &lwe::Ciphertext) {
        let mut shares = Vec::new();
        let mut res = Vec::new();

        for party in &self.parties {
            shares.push(party.decrypt1(c))
        }

        for party in &self.parties {
            res.push(party.decrypt2(&shares));
        }

        for res in res {
            println!("{res}");
        }
    }
}
