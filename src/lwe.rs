use crate::pke::Pke;
use num::{bigint::RandomBits, traits::Pow, BigInt, FromPrimitive, Integer, ToPrimitive, Zero};
use probability::prelude::*;
use rand::prelude::*;

pub type PublicKey = (Vec<Vec<BigInt>>, Vec<BigInt>);
pub type SecretKey = Vec<BigInt>;
pub type Ciphertext = (Vec<BigInt>, BigInt);
pub type Plaintext = usize;

#[derive(Clone)]
#[non_exhaustive]
pub struct Lwe {
    pub n: usize,
    pub m: usize,
    pub q: BigInt,
}

impl Lwe {
    pub fn new(n: usize) -> Self {
        let m = n.pow(3);
        let q = BigInt::from(2u32);
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
        let sk = new_rand_big_int_vec(self.n);
        let pk = Self::gen_pk(&sk, self.m, self.n, &self.q);

        (pk, sk)
    }

    fn encrypt(&self, pk: &Self::PublicKey, m: &Self::Plaintext) -> Self::Ciphertext {
        if !(0..=1).contains(m) {
            unimplemented!();
        }
        let mut rng = rand::thread_rng();

        let mut subs_i = (0..self.m).collect::<Vec<_>>();
        subs_i.shuffle(&mut rng);
        let subs_i = &subs_i[0..self.m / 2];

        let mut a = vec![BigInt::zero(); self.m];
        let mut b = BigInt::from(*m) * &self.q / 2u32;

        for i in subs_i {
            let ai = &pk.0[*i];
            let bi = &pk.1[*i];

            a.iter_mut().zip(ai).for_each(|(a_elem, ai_elem)| {
                *a_elem = (a_elem.clone() + ai_elem).mod_floor(&self.q)
            });

            b = (b + bi).mod_floor(&self.q);
        }

        (a, b)
    }

    fn decrypt(&self, sk: &Self::SecretKey, c: &Self::Ciphertext) -> Self::Plaintext {
        let q = &self.q;
        let b = &c.1;

        let a: BigInt =
            c.0.iter()
                .zip(sk)
                .fold(BigInt::zero(), |acc, (ai, si)| (acc + ai * si).mod_floor(q));

        let m = (b - a).mod_floor(q);
        dbg!(&m);

        let lower = q / 4u32;
        let upper = q - &lower;

        if lower < m && m < upper {
            return 1;
        }

        0
    }
}

fn new_rand_big_int_vec(n: usize) -> Vec<BigInt> {
    let mut rng = rand::thread_rng();

    (0..n)
        .map(|_| rng.sample::<BigInt, _>(RandomBits::new(n as u64)))
        .collect::<Vec<_>>()
}

impl Lwe {
    pub fn gen_e(m: usize, q: &BigInt) -> Vec<BigInt> {
        let mut rng = rand::thread_rng();
        let mut source = source::default(rng.gen());

        let sigma = q.to_f64().unwrap().sqrt().sqrt();
        let mu = 0.;

        let dist = Gaussian::new(mu, sigma);

        (0..m)
            .map(|_| {
                let mut sample = dist.sample(&mut source);
                sample = sample.round();
                BigInt::from_f64(sample).unwrap().mod_floor(q)
            })
            .collect()
    }

    pub fn gen_pk(s: &[BigInt], m: usize, n: usize, q: &BigInt) -> (Vec<Vec<BigInt>>, Vec<BigInt>) {
        let a = (0..m).map(|_| new_rand_big_int_vec(n)).collect::<Vec<_>>();

        let e = Self::gen_e(m, q);

        let b = Self::gen_b(&a, s, q, &e);

        (a, b)
    }

    pub fn gen_b(a: &[Vec<BigInt>], s: &[BigInt], q: &BigInt, e: &[BigInt]) -> Vec<BigInt> {
        let b = a
            .iter()
            .map(|ai| {
                ai.iter()
                    .zip(s)
                    .zip(e)
                    .fold(BigInt::zero(), |acc, ((ai_elem, si), ei)| {
                        (acc + (ai_elem * si + ei)).mod_floor(q)
                    })
            })
            .collect::<Vec<_>>();
        b
    }
}
