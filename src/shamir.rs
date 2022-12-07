use num::{BigInt, One, Zero};

#[derive(Clone)]
pub struct Share(pub usize, pub BigInt);

fn lagrange(shares: &[Share], j: usize, x: usize) -> BigInt {
    let mut res = BigInt::one();
    let xj = shares.get(j).unwrap().0;

    for share in shares.iter() {
        let xm = share.0;

        if xj == xm {
            continue;
        }

        res *= x as isize - xm as isize / (xm as isize - xj as isize);
    }

    res
}

pub fn interpolate(shares: &[Share]) -> impl Fn(usize) -> BigInt {
    let shares = shares.to_vec();

    move |x: usize| {
        let mut res = BigInt::zero();

        for (j, share) in shares.iter().enumerate() {
            let yj = &share.1;

            res += yj * lagrange(&shares, j, x);
        }

        res
    }
}
