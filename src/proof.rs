use sha3::Shake128;
use sha3::digest::{ExtendableOutput, Update, XofReader};

use crate::error::{ArcError, Result};
use crate::group::{
    Element, NS, Scalar, random_proof_scalar, scalar_from_bytes, scalar_to_bytes,
    serialize_elements,
};
use rand_core::RngCore;

const WORD_SIZE: usize = 4;
const PROTOCOL_ID_LABEL: &[u8] = b"sigma-proofs_Shake128_P256";
const SESSION_ID_LABEL: &[u8] = b"fiat-shamir/session-id";
const SHAKE128_RATE: usize = 168;
const SESSION_HASH_BYTES: usize = 32;
const IV_BYTES: usize = 64;
const CHALLENGE_BYTES: usize = 64;

#[derive(Clone, Debug)]
struct LinearCombination {
    scalar_indices: Vec<usize>,
    element_indices: Vec<usize>,
}

#[derive(Clone, Debug)]
pub(crate) struct LinearRelation {
    combinations: Vec<LinearCombination>,
    group_elements: Vec<Option<Element>>,
    image: Vec<usize>,
    num_scalars: usize,
}

impl LinearRelation {
    pub(crate) fn new() -> Self {
        Self {
            combinations: Vec::new(),
            group_elements: Vec::new(),
            image: Vec::new(),
            num_scalars: 0,
        }
    }

    pub(crate) fn allocate_scalars<const N: usize>(&mut self) -> [usize; N] {
        let start = self.num_scalars;
        self.num_scalars += N;
        std::array::from_fn(|i| start + i)
    }

    pub(crate) fn allocate_elements<const N: usize>(&mut self) -> [usize; N] {
        let start = self.group_elements.len();
        self.group_elements.extend((0..N).map(|_| None));
        std::array::from_fn(|i| start + i)
    }

    pub(crate) fn set_elements(&mut self, elements: &[(usize, Element)]) -> Result<()> {
        for (index, element) in elements {
            let slot = self
                .group_elements
                .get_mut(*index)
                .ok_or(ArcError::MalformedStatement)?;
            *slot = Some(*element);
        }
        Ok(())
    }

    pub(crate) fn append_equation(&mut self, lhs: usize, rhs: &[(usize, usize)]) {
        self.combinations.push(LinearCombination {
            scalar_indices: rhs.iter().map(|(scalar, _)| *scalar).collect(),
            element_indices: rhs.iter().map(|(_, element)| *element).collect(),
        });
        self.image.push(lhs);
    }

    pub(crate) fn num_scalars(&self) -> usize {
        self.num_scalars
    }

    pub(crate) fn map(&self, scalars: &[Scalar]) -> Result<Vec<Element>> {
        if scalars.len() != self.num_scalars {
            return Err(ArcError::MalformedStatement);
        }

        self.combinations
            .iter()
            .map(|combination| {
                if combination.scalar_indices.len() != combination.element_indices.len() {
                    return Err(ArcError::MalformedStatement);
                }

                let mut acc = Element::identity();
                for (scalar_index, element_index) in combination
                    .scalar_indices
                    .iter()
                    .zip(combination.element_indices.iter())
                {
                    let scalar = *scalars
                        .get(*scalar_index)
                        .ok_or(ArcError::MalformedStatement)?;
                    let element = self.element(*element_index)?;
                    acc = acc + element.mul(scalar);
                }
                Ok(acc)
            })
            .collect()
    }

    pub(crate) fn image(&self) -> Result<Vec<Element>> {
        self.image
            .iter()
            .map(|index| self.element(*index))
            .collect()
    }

    fn element(&self, index: usize) -> Result<Element> {
        self.group_elements
            .get(index)
            .ok_or(ArcError::MalformedStatement)?
            .ok_or(ArcError::MalformedStatement)
    }

    fn instance_label(&self) -> Result<Vec<u8>> {
        if self.group_elements.iter().any(Option::is_none) {
            return Err(ArcError::MalformedStatement);
        }

        let mut out = Vec::new();
        append_u32_le(&mut out, self.combinations.len())?;

        for (i, combination) in self.combinations.iter().enumerate() {
            append_u32_le(&mut out, self.image[i])?;
            append_u32_le(&mut out, combination.scalar_indices.len())?;
            for (scalar_index, element_index) in combination
                .scalar_indices
                .iter()
                .zip(combination.element_indices.iter())
            {
                append_u32_le(&mut out, *scalar_index)?;
                append_u32_le(&mut out, *element_index)?;
            }
        }

        for element in &self.group_elements {
            out.extend_from_slice(
                &element
                    .ok_or(ArcError::MalformedStatement)?
                    .try_to_bytes()?,
            );
        }

        Ok(out)
    }
}

pub(crate) fn prove<R: RngCore + ?Sized>(
    session: &[u8],
    statement: &LinearRelation,
    witness: &[Scalar],
    rng: &mut R,
) -> Result<Vec<u8>> {
    if witness.len() != statement.num_scalars() {
        return Err(ArcError::MalformedStatement);
    }

    let nonces: Vec<_> = (0..statement.num_scalars())
        .map(|_| random_proof_scalar(rng))
        .collect();
    let commitment = statement.map(&nonces)?;
    let mut sponge = proof_sponge(session, statement)?;
    sponge.update(&serialize_elements(&commitment)?);
    let challenge = challenge_scalar(&sponge);

    let responses: Vec<_> = nonces
        .iter()
        .zip(witness.iter())
        .map(|(nonce, witness)| *nonce + (*witness * challenge))
        .collect();

    if !verify_transcript(statement, &commitment, challenge, &responses)? {
        return Err(ArcError::ProofVerificationFailed);
    }

    let mut proof = Vec::with_capacity((1 + responses.len()) * NS);
    proof.extend_from_slice(&scalar_to_bytes(challenge));
    for response in responses {
        proof.extend_from_slice(&scalar_to_bytes(response));
    }
    Ok(proof)
}

pub(crate) fn verify(session: &[u8], statement: &LinearRelation, proof: &[u8]) -> Result<bool> {
    let expected = (1 + statement.num_scalars()) * NS;
    if proof.len() != expected {
        return Err(ArcError::InvalidProofLength {
            expected,
            actual: proof.len(),
        });
    }

    let challenge = scalar_from_bytes(&proof[..NS])?;
    let responses: Vec<_> = proof[NS..]
        .chunks_exact(NS)
        .map(scalar_from_bytes)
        .collect::<Result<_>>()?;

    let commitment = simulate_commitment(statement, &responses, challenge)?;
    let mut sponge = proof_sponge(session, statement)?;
    let Ok(commitment_bytes) = serialize_elements(&commitment) else {
        return Ok(false);
    };
    sponge.update(&commitment_bytes);
    let expected_challenge = challenge_scalar(&sponge);
    if challenge != expected_challenge {
        return Ok(false);
    }

    verify_transcript(statement, &commitment, challenge, &responses)
}

fn simulate_commitment(
    statement: &LinearRelation,
    responses: &[Scalar],
    challenge: Scalar,
) -> Result<Vec<Element>> {
    let mapped = statement.map(responses)?;
    let image = statement.image()?;
    Ok(mapped
        .into_iter()
        .zip(image)
        .map(|(mapped, image)| mapped - image.mul(challenge))
        .collect())
}

fn verify_transcript(
    statement: &LinearRelation,
    commitment: &[Element],
    challenge: Scalar,
    response: &[Scalar],
) -> Result<bool> {
    let expected = statement.map(response)?;
    let image = statement.image()?;
    if commitment.len() != expected.len() || image.len() != expected.len() {
        return Err(ArcError::MalformedStatement);
    }

    let got: Vec<_> = commitment
        .iter()
        .zip(image)
        .map(|(commitment, image)| *commitment + image.mul(challenge))
        .collect();

    Ok(got == expected)
}

fn proof_sponge(session: &[u8], statement: &LinearRelation) -> Result<Shake128> {
    let protocol_id = padded_iv(PROTOCOL_ID_LABEL);

    let session_iv = padded_iv(SESSION_ID_LABEL);
    let mut session_hash = shake128_with_iv(&session_iv);
    session_hash.update(session);
    let session_digest = squeeze(&session_hash, SESSION_HASH_BYTES);
    let mut session_id = [0u8; IV_BYTES];
    session_id[SESSION_HASH_BYTES..].copy_from_slice(&session_digest);

    let mut sponge = shake128_with_iv(&protocol_id);
    sponge.update(&session_id);
    sponge.update(&statement.instance_label()?);
    Ok(sponge)
}

fn challenge_scalar(sponge: &Shake128) -> Scalar {
    let bytes = squeeze(sponge, CHALLENGE_BYTES);
    scalar_from_wide_mod_order(&bytes)
}

fn scalar_from_wide_mod_order(bytes: &[u8]) -> Scalar {
    let mut scalar = Scalar::ZERO;
    let radix = Scalar::from(256u64);
    for byte in bytes {
        scalar = scalar * radix + Scalar::from(*byte as u64);
    }
    scalar
}

fn shake128_with_iv(iv: &[u8; IV_BYTES]) -> Shake128 {
    let mut initial_block = [0u8; SHAKE128_RATE];
    initial_block[..IV_BYTES].copy_from_slice(iv);
    let mut state = Shake128::default();
    state.update(&initial_block);
    state
}

fn squeeze(state: &Shake128, length: usize) -> Vec<u8> {
    let mut reader = state.clone().finalize_xof();
    let mut out = vec![0u8; length];
    reader.read(&mut out);
    out
}

fn padded_iv(label: &[u8]) -> [u8; IV_BYTES] {
    let mut out = [0u8; IV_BYTES];
    out[..label.len()].copy_from_slice(label);
    out
}

fn append_u32_le(out: &mut Vec<u8>, value: usize) -> Result<()> {
    let value = u32::try_from(value).map_err(|_| ArcError::MalformedStatement)?;
    out.extend_from_slice(&value.to_le_bytes()[..WORD_SIZE]);
    Ok(())
}
