use rand_core::RngCore;

use crate::error::{ArcError, Result};
use crate::group::{Element, Scalar, generator_g, generator_h, random_scalar, scalar_inverse};
use crate::proof::LinearRelation;

pub(crate) fn compute_bases(presentation_limit: u64) -> Result<Vec<u64>> {
    if presentation_limit < 2 {
        return Err(ArcError::InvalidPresentationLimit);
    }

    let num_bits = u64::BITS - (presentation_limit - 1).leading_zeros();
    let mut remainder = presentation_limit;
    let mut bases = Vec::with_capacity(num_bits as usize);

    for i in 0..(num_bits - 1) {
        let base = 1u64
            .checked_shl(i)
            .ok_or(ArcError::InvalidPresentationLimit)?;
        remainder = remainder
            .checked_sub(base)
            .ok_or(ArcError::InvalidPresentationLimit)?;
        bases.push(base);
    }

    bases.push(
        remainder
            .checked_sub(1)
            .ok_or(ArcError::InvalidPresentationLimit)?,
    );
    if bases.iter().any(|base| *base == 0) {
        return Err(ArcError::InvalidPresentationLimit);
    }

    bases.sort_unstable_by(|a, b| b.cmp(a));
    Ok(bases)
}

pub(crate) fn make_range_proof_helper<R: RngCore + ?Sized>(
    statement: &mut LinearRelation,
    nonce: u64,
    nonce_blinding: Scalar,
    presentation_limit: u64,
    gen_g_var: usize,
    gen_h_var: usize,
    nonce_commit_var: usize,
    nonce_commit: Element,
    rng: &mut R,
) -> Result<(Vec<Element>, Vec<Scalar>)> {
    let bases = compute_bases(presentation_limit)?;
    let mut bits = Vec::with_capacity(bases.len());
    let mut remainder = nonce;
    for base in &bases {
        let bit = u64::from(remainder >= *base);
        remainder = remainder.saturating_sub(bit * *base);
        bits.push(bit);
    }

    let mut d = Vec::with_capacity(bases.len());
    let mut blindings = Vec::with_capacity(bases.len());
    let mut s2 = Vec::with_capacity(bases.len());
    let mut partial_sum = Scalar::ZERO;

    for (i, bit) in bits.iter().enumerate().take(bases.len() - 1) {
        let blinding = random_scalar(rng);
        blindings.push(blinding);
        partial_sum += Scalar::from(bases[i]) * blinding;

        let bit_scalar = Scalar::from(*bit);
        s2.push((Scalar::ONE - bit_scalar) * blinding);
        d.push(generator_g().mul(bit_scalar) + generator_h().mul(blinding));
    }

    let last = bases.len() - 1;
    let last_base_inverse = scalar_inverse(Scalar::from(bases[last]))?;
    let last_blinding = (nonce_blinding - partial_sum) * last_base_inverse;
    blindings.push(last_blinding);

    let last_bit_scalar = Scalar::from(bits[last]);
    s2.push((Scalar::ONE - last_bit_scalar) * last_blinding);
    d.push(generator_g().mul(last_bit_scalar) + generator_h().mul(last_blinding));

    append_range_constraints(
        statement,
        &d,
        gen_g_var,
        gen_h_var,
        nonce_commit_var,
        nonce_commit,
    )?;

    let mut witness = Vec::with_capacity(bits.len() * 3);
    witness.extend(bits.iter().map(|bit| Scalar::from(*bit)));
    witness.extend(blindings);
    witness.extend(s2);
    Ok((d, witness))
}

pub(crate) fn verify_range_proof_helper(
    statement: &mut LinearRelation,
    d: &[Element],
    nonce_commit: Element,
    presentation_limit: u64,
    gen_g_var: usize,
    gen_h_var: usize,
    nonce_commit_var: usize,
) -> Result<bool> {
    let bases = compute_bases(presentation_limit)?;
    if d.len() != bases.len() {
        return Err(ArcError::InvalidRangeProof);
    }

    append_range_constraints(
        statement,
        d,
        gen_g_var,
        gen_h_var,
        nonce_commit_var,
        nonce_commit,
    )?;

    let mut sum = Element::identity();
    for (base, commitment) in bases.iter().zip(d.iter()) {
        sum = sum + commitment.mul(Scalar::from(*base));
    }
    Ok(sum == nonce_commit)
}

fn append_range_constraints(
    statement: &mut LinearRelation,
    d: &[Element],
    gen_g_var: usize,
    gen_h_var: usize,
    nonce_commit_var: usize,
    nonce_commit: Element,
) -> Result<()> {
    let num_bits = d.len();
    let vars_b = statement.allocate_scalars_dyn(num_bits);
    let vars_s = statement.allocate_scalars_dyn(num_bits);
    let vars_s2 = statement.allocate_scalars_dyn(num_bits);

    let vars_d = if num_bits == 1 && d[0] == nonce_commit {
        vec![nonce_commit_var]
    } else {
        let vars_d = statement.allocate_elements_dyn(num_bits);
        let assignments: Vec<_> = vars_d.iter().copied().zip(d.iter().copied()).collect();
        statement.set_elements(&assignments)?;
        vars_d
    };

    for i in 0..num_bits {
        statement.append_equation(vars_d[i], &[(vars_b[i], gen_g_var), (vars_s[i], gen_h_var)]);
        statement.append_equation(
            vars_d[i],
            &[(vars_b[i], vars_d[i]), (vars_s2[i], gen_h_var)],
        );
    }

    Ok(())
}

trait DynamicAllocation {
    fn allocate_scalars_dyn(&mut self, n: usize) -> Vec<usize>;
    fn allocate_elements_dyn(&mut self, n: usize) -> Vec<usize>;
}

impl DynamicAllocation for LinearRelation {
    fn allocate_scalars_dyn(&mut self, n: usize) -> Vec<usize> {
        (0..n)
            .map(|_| {
                let [index] = self.allocate_scalars::<1>();
                index
            })
            .collect()
    }

    fn allocate_elements_dyn(&mut self, n: usize) -> Vec<usize> {
        (0..n)
            .map(|_| {
                let [index] = self.allocate_elements::<1>();
                index
            })
            .collect()
    }
}
