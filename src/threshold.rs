use core::panic;

use num::{bigint::RandBigInt, BigInt, FromPrimitive, Integer, ToPrimitive, Zero};
use rand::{rngs::SmallRng, Rng, SeedableRng};
use sha256::digest;

const NUMBER_OF_PARTIES: usize = 10;

use crate::{
    lagrange::{interpolate, Share},
    lwe::{self, Ciphertext, Lwe},
    pke::Pke,
};

pub struct Party {
    number: usize,
    sk: Option<lwe::SecretKey>,
    crypto: lwe::Lwe,
    keys: Vec<BigInt>,
}

impl Party {
    fn new(number: usize, crypto: lwe::Lwe) -> Self {
        let keys = Vec::new();

        Self {
            number,
            sk: None,
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

    pub fn gen_b(&self, a: Vec<Vec<BigInt>>, e: &Vec<Vec<BigInt>>) -> Vec<BigInt> {
        let q = &self.crypto.q;
        let s = self.sk.clone().unwrap();

        let e = e
            .iter()
            .map(|ei| {
                let u = ei.len();

                (ei.iter().sum::<BigInt>() / u).mod_floor(q)
            })
            .collect::<Vec<_>>();

        Lwe::gen_b(&a, &s, q, &e)
    }

    fn gen_e(&self) -> Vec<BigInt> {
        let m = self.crypto.m;
        let q = &self.crypto.q;

        Lwe::gen_e(m, q)
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
        let q = &self.crypto.q;

        if keys.len() != 1 {
            panic!(
                "Expecting case u-t = 1, but keys length was: {}",
                keys.len()
            );
        }

        rand_from_cipher_and_key(c, &keys[0], n, q)
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

fn rand_from_cipher_and_key(c: &Ciphertext, key: &BigInt, n: usize, q: &BigInt) -> BigInt {
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
    rng.gen_bigint(n as u64).mod_floor(q).sqrt()
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

        // Set all keys
        for (i, party) in parties.iter_mut().enumerate() {
            let sk = sks[i].clone();
            party.set_sk(&sk);
            party.keys.extend(keys[i].clone());
        }

        // Generate public key
        let mut es = vec![vec![vec![BigInt::zero(); u]; m]; u];
        for (j, party) in parties.iter().enumerate() {
            let e = party.gen_e();
            for (i, ei) in e.iter().enumerate() {
                let mut shares = Vec::with_capacity(u / 4 + 1);
                shares.push(Share(0, ei.clone()));

                for party in parties.iter().take(u / 4) {
                    let r_val = party.rand_value(n);
                    let share = Share(party.number, r_val);
                    shares.push(share);
                }
                let l = interpolate(&shares);

                for party in parties.iter() {
                    let p = party.number - 1;
                    es[p][i][j] = l(party.number);
                }
            }
        }

        let (a, _) = Lwe::gen_pk(&s, m, n, q);
        let mut bss = vec![Vec::with_capacity(u); m];
        for party in parties.iter() {
            let p = party.number - 1;
            let b = party.gen_b(a.clone(), &es[p]);
            for (i, bi) in b.iter().enumerate() {
                let share = Share(party.number, bi.clone());

                bss[i].push(share);
            }
        }

        let mut b = Vec::with_capacity(m);

        for bs in bss {
            let l = interpolate(&bs);
            b.push(l(0));
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
