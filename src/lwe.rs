use crate::pke::Pke;
use num::{bigint::RandomBits, traits::Pow, BigInt, BigUint, Zero};
use rand::prelude::*;

pub type PublicKey = (Vec<Vec<BigUint>>, Vec<BigUint>);
pub type SecretKey = Vec<BigUint>;
pub type Ciphertext = (Vec<BigUint>, BigUint);
pub type Plaintext = usize;

#[derive(Clone)]
#[non_exhaustive]
pub struct Lwe {
    pub n: usize,
    pub m: usize,
    pub q: BigUint,
}

impl Lwe {
    pub fn new(n: usize) -> Self {
        let m = n.pow(3);
        let q = BigUint::from(2u32);
        let q = q.pow(n as u32);

        Self { n, m, q }
    }
}

impl Pke for Lwe {
    type Ciphertext = Ciphertext;
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;
    type Plaintext = Plaintext;

    fn keygen(&self) -> (Self::PublicKey, Self::SecretKey) {
        let sk = new_rand_biguint_vec(self.n);
        let pk = Lwe::gen_pk(self, &sk);

        (pk, sk)
    }

    fn encrypt(&self, pk: &Self::PublicKey, m: &Self::Plaintext) -> Self::Ciphertext {
        if !(0..=1).contains(m) {
            unimplemented!();
        }
        let mut rng = rand::thread_rng();

        let mut subs_i = (0..self.m).collect::<Vec<_>>();
        subs_i.shuffle(&mut rng);
        let subs_i = subs_i.get(0..self.m / 2).unwrap();

        let mut a = vec![BigUint::zero(); self.m];
        let mut b = BigUint::from(*m) * &self.q / 2u32;

        for i in subs_i {
            let ai = pk.0.get(*i).unwrap();

            let bi = pk.1.get(*i).unwrap();

            a.iter_mut()
                .zip(ai)
                .for_each(|(a_elem, ai_elem)| *a_elem = (a_elem.clone() + ai_elem) % &self.q);

            b = (b + bi) % &self.q;
        }

        (a, b)
    }

    fn decrypt(&self, sk: &Self::SecretKey, c: &Self::Ciphertext) -> Self::Plaintext {
        let q = BigInt::from(self.q.clone());
        let b = BigInt::from(c.1.clone());

        let a: BigInt =
            c.0.iter()
                .zip(sk)
                .fold(BigUint::zero(), |acc, (ai, si)| (acc + ai * si) % &self.q)
                .into();

        let m = (b - a) % &q;

        let lower = &q / 4u32;
        let upper = &q + &lower;

        if m < lower && upper < m {
            return 1;
        }

        0
    }
}

fn new_rand_biguint_vec(n: usize) -> Vec<BigUint> {
    let mut rng = rand::thread_rng();

    (0..n)
        .map(|_| rng.sample::<BigUint, _>(RandomBits::new(n as u64)))
        .collect::<Vec<_>>()
}

impl Lwe {
    fn gen_e(n: usize, q: &BigUint) -> Vec<BigUint> {
        eprintln!("WARNING: Randomness not implemented. All values of e are 0");

        // let mut rng = rand::thread_rng();

        // let sigma = q.sqrt().sqrt().to_f64().unwrap();

        // Standard

        // rng.sample_iter(dist);

        (0..n).map(|_| BigUint::zero()).collect::<Vec<_>>()
    }

    fn gen_pk(&self, s: &[BigUint]) -> (Vec<Vec<BigUint>>, Vec<BigUint>) {
        let a = (0..self.m)
            .map(|_| new_rand_biguint_vec(self.n))
            .collect::<Vec<_>>();

        let _e = Lwe::gen_e(self.m, &self.q);

        let b = a
            .iter()
            .map(|ai| {
                ai.iter()
                    .zip(s)
                    .fold(BigUint::zero(), |acc, (ai_elem, si)| {
                        (acc + ai_elem * si) % &self.q
                    })
            })
            .collect::<Vec<_>>();

        (a, b)
    }
}
