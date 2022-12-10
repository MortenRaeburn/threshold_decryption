use core::panic;

use num::{bigint::RandBigInt, BigInt, Zero, Integer};
use rand::{rngs::SmallRng, SeedableRng};
use sha256::digest;

const NUMBER_OF_PARTIES: usize = 6;

use crate::{
    lwe::{self, Ciphertext, Lwe},
    pke::Pke,
    lagrange::{interpolate, Share},
};

pub struct Party {
    number: usize,
    sk: Option<lwe::SecretKey>,
    pk: Option<lwe::PublicKey>,
    crypto: lwe::Lwe,
    keys: Vec<BigInt>,
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

    pub fn rand_value(&self, n: usize) -> BigInt {
        crate::random::rand_value(n)
    }

    fn set_sk(&mut self, sk: &lwe::SecretKey) {
        self.sk = Some(sk.clone());
    }

    pub fn set_pk_from_a(&mut self, a: Vec<Vec<BigInt>>) {
        let q = &self.crypto.q;
        let s = self.sk.clone().unwrap();

        let b = Lwe::gen_b(&a, &s, q);

        let pk = (a, b);
        self.pk = Some(pk);
    }

    fn decrypt1(&self, c: &lwe::Ciphertext) -> Share {
        let sk = self.sk.clone().unwrap(); //At this point, we know that sk should be Some - which is after keygen

        let (a, b) = c;

        let e = b - a
            .iter()
            .zip(sk)
            .fold(BigInt::zero(), |acc, (a, sk)| acc + a * sk);

        let x = self.gen_x(&self.keys, c);

        Share(self.number, x + e)
    }

    fn gen_x(&self, keys: &Vec<BigInt>, c: &lwe::Ciphertext) -> BigInt {
        let n = self.crypto.n;

        if keys.len() != 1 {
            panic!(
                "Expecting case u-t = 1, but keys length was: {}",
                keys.len()
            );
        }

        rand_from_cipher_and_key(c, &keys[0], n)
    }

    fn decrypt2(&self, shares: &[Share]) -> lwe::Plaintext {
        let q = &self.crypto.q;
        let m = interpolate(shares)(0).mod_floor(q);

        let lower = q / 4u32;
        let upper = q - &lower;

        if lower < m && m < upper {
            return 1;
        }

        0
    }
}

fn rand_from_cipher_and_key(c: &Ciphertext, key: &BigInt, n: usize) -> BigInt {
    let (a, b) = c;

    let mut input = Vec::new();

    for ai in a {
        input.extend(ai.to_bytes_be().1);
    }

    input.extend(b.to_bytes_be().1);
    input.extend(key.to_bytes_be().1);

    let hash = digest(input.as_slice());
    let hash = hash.as_bytes();

    let mut seed = [0u8; 32];
    seed.iter_mut().zip(hash).for_each(|(s, h)| *s = *h);

    let mut rng = SmallRng::from_seed(seed);
    rng.gen_bigint(n as u64)
}

pub struct Dealer {
    parties: Vec<Party>,
    pk: lwe::PublicKey,
    crypto: lwe::Lwe,
}

impl Dealer {
    pub fn new(n: usize) -> Self {
        let crypto = lwe::Lwe::new(n);
        let m = crypto.m;
        let q = &crypto.q;

        let mut parties = (1..=NUMBER_OF_PARTIES)
            .map(|number| Party::new(number, crypto.clone()))
            .collect::<Vec<_>>();
        let pk = Self::keygen(n, m, q, &mut parties);

        Self {
            parties,
            crypto,
            pk,
        }
    }

    pub fn keygen(
        n: usize,
        m: usize,
        q: &BigInt,
        parties: &mut Vec<Party>,
    ) -> (Vec<Vec<BigInt>>, Vec<BigInt>) {
        let u = parties.len();

        let mut s = Vec::with_capacity(n);
        let mut sks = vec![Vec::with_capacity(n); u];
        let mut keys = vec![Vec::with_capacity(1); u];

        // Generate secret key
        for _ in 0..n {
            let mut shares = Vec::new();

            for (i, party) in parties.iter().enumerate() {
                let r_val = party.rand_value(n);
                sks[i].push(r_val.clone());
                let share = Share(party.number, r_val);
                shares.push(share);
            }

            let l = interpolate(&shares);
            let si = l(0);

            s.push(si);
        }

        // Generate keys
        for i in 0..u {
            let r_val = parties[i].rand_value(n);
            keys[i].push(r_val.clone());
        }

        let (a, b) = Lwe::gen_pk(&s, m, n, q);

        // Set all keys
        for (i, party) in parties.iter_mut().enumerate() {
            let sk = sks[i].clone();
            party.set_sk(&sk);
            party.set_pk_from_a(a.clone());
            party.keys.extend(keys[i].clone());
        }

        (a, b)
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
