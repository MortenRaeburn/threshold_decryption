use num::{BigInt, One, Zero, BigRational};

#[derive(Clone)]
pub struct Share(pub usize, pub BigInt);

fn lagrange(shares: &[Share], j: usize, x: usize) -> BigRational {
    let mut res = BigRational::one();
    let xj = shares[j].0;

    for share in shares.iter() {
        let xm = share.0;
        
        if xm == xj {
            continue;
        }

        res *= BigInt::from(x as isize - xm as isize);
        res /= BigInt::from(xj as isize - xm as isize);
    }

    res
}

pub fn interpolate(shares: &[Share]) -> impl Fn(usize) -> BigInt {
    let shares = shares.to_vec();

    move |x: usize| {
        let mut res = BigRational::zero();

        for (j, share) in shares.iter().enumerate() {
            let yj = &share.1;

            res += lagrange(&shares, j, x) * yj;
        }

        res.to_integer()
    }
}
