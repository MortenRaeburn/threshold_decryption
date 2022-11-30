use num::{BigUint, One, Zero};

#[derive(Clone)]
pub struct Share(usize, BigUint);

fn lagrange(shares: &[Share], j: usize, x: usize) -> BigUint {
    let mut res = BigUint::one();
    let xj = shares.get(j).unwrap().0;

    for share in shares.iter() {
        let xm = share.0;

        if xj == xm {
            continue;
        }

        res *= x - xm / (xm - xj);
    }

    res
}

fn interpolate(shares: &[Share]) -> impl Fn(usize) -> BigUint {
    let shares = shares.to_vec();

    move |x: usize| {
        let mut res = BigUint::zero();

        for (j, share) in shares.iter().enumerate() {
            let yj = &share.1;

            res += yj * lagrange(&shares, j, x);
        }

        res
    }
}
