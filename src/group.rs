use std::ops::{Add, Neg, Sub};
use std::sync::OnceLock;

use num_bigint::BigUint;
use p256::elliptic_curve::ff::{Field, PrimeField};
use p256::elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{AffinePoint, EncodedPoint, FieldBytes, NistP256, ProjectivePoint};
use rand_core::RngCore;
use sha2::Sha256;
use subtle::CtOption;

use crate::error::{ArcError, Result};

pub const CONTEXT_STRING: &[u8] = b"ARCV1-P256";
pub const NE: usize = 33;
pub const NS: usize = 32;
const WIDE_SCALAR_BYTES: usize = 48;

pub type Scalar = p256::Scalar;

#[derive(Clone, Copy, Debug)]
pub struct Element(pub(crate) ProjectivePoint);

impl Element {
    pub(crate) fn identity() -> Self {
        Self(ProjectivePoint::IDENTITY)
    }

    pub(crate) fn mul(self, scalar: Scalar) -> Self {
        Self(self.0 * scalar)
    }

    pub(crate) fn try_to_bytes(self) -> Result<[u8; NE]> {
        let encoded = AffinePoint::from(self.0).to_encoded_point(true);
        let bytes = encoded.as_bytes();
        if bytes.len() != NE {
            return Err(ArcError::InvalidElement);
        }

        let mut out = [0u8; NE];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    pub fn to_bytes(self) -> Result<[u8; NE]> {
        self.try_to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != NE {
            return Err(ArcError::InvalidLength {
                expected: NE,
                actual: bytes.len(),
            });
        }

        if bytes[0] != 0x02 && bytes[0] != 0x03 {
            return Err(ArcError::InvalidElement);
        }

        let encoded = EncodedPoint::from_bytes(bytes).map_err(|_| ArcError::InvalidElement)?;
        let affine = ct_option_to_result(
            AffinePoint::from_encoded_point(&encoded),
            ArcError::InvalidElement,
        )?;
        if bool::from(affine.is_identity()) {
            return Err(ArcError::InvalidElement);
        }

        Ok(Self(ProjectivePoint::from(affine)))
    }
}

impl PartialEq for Element {
    fn eq(&self, other: &Self) -> bool {
        AffinePoint::from(self.0) == AffinePoint::from(other.0)
    }
}

impl Eq for Element {}

impl Add for Element {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Sub for Element {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl Neg for Element {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(-self.0)
    }
}

pub fn generator_g() -> Element {
    Element(ProjectivePoint::GENERATOR)
}

pub fn generator_h() -> Element {
    static GENERATOR_H: OnceLock<Element> = OnceLock::new();
    *GENERATOR_H.get_or_init(|| {
        let gen_g = generator_g()
            .try_to_bytes()
            .expect("P-256 generator is serializable");
        hash_to_group(&gen_g, b"generatorH").expect("generatorH hash-to-group succeeds")
    })
}

pub fn random_scalar<R: RngCore + ?Sized>(rng: &mut R) -> Scalar {
    loop {
        let mut bytes = [0u8; WIDE_SCALAR_BYTES];
        rng.fill_bytes(&mut bytes);
        let scalar = scalar_from_random_bytes(&bytes);
        if !bool::from(scalar.is_zero()) {
            return scalar;
        }
    }
}

pub(crate) fn random_proof_scalar<R: RngCore + ?Sized>(rng: &mut R) -> Scalar {
    let mut bytes = [0u8; WIDE_SCALAR_BYTES];
    rng.fill_bytes(&mut bytes);
    scalar_from_wide_bytes(&bytes)
}

pub fn scalar_to_bytes(scalar: Scalar) -> [u8; NS] {
    scalar.to_bytes().into()
}

pub fn scalar_from_bytes(bytes: &[u8]) -> Result<Scalar> {
    if bytes.len() != NS {
        return Err(ArcError::InvalidLength {
            expected: NS,
            actual: bytes.len(),
        });
    }

    let mut repr = FieldBytes::default();
    repr.copy_from_slice(bytes);
    ct_option_to_result(Scalar::from_repr(repr), ArcError::InvalidScalar)
}

pub(crate) fn scalar_from_wide_bytes(bytes: &[u8; WIDE_SCALAR_BYTES]) -> Scalar {
    let mut scalar = Scalar::ZERO;
    let radix = Scalar::from(256u64);
    for byte in bytes {
        scalar = scalar * radix + Scalar::from(*byte as u64);
    }
    scalar
}

fn scalar_from_random_bytes(bytes: &[u8; WIDE_SCALAR_BYTES]) -> Scalar {
    static ORDER_MINUS_ONE: OnceLock<BigUint> = OnceLock::new();
    let modulus = ORDER_MINUS_ONE.get_or_init(|| {
        BigUint::parse_bytes(
            b"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
            16,
        )
        .expect("valid P-256 order minus one")
    });

    let value = BigUint::from_bytes_be(bytes) % modulus;
    let reduced = value.to_bytes_be();
    let mut scalar_bytes = [0u8; NS];
    let start = NS - reduced.len();
    scalar_bytes[start..].copy_from_slice(&reduced);
    scalar_from_bytes(&scalar_bytes).expect("reduction modulo order - 1 yields a scalar")
}

pub(crate) fn scalar_inverse(scalar: Scalar) -> Result<Scalar> {
    ct_option_to_result(scalar.invert(), ArcError::InvalidScalar)
}

pub fn hash_to_group(input: &[u8], info: &[u8]) -> Result<Element> {
    let dst = dst(b"HashToGroup-", info);
    let point = <NistP256 as GroupDigest>::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
        &[input],
        &[dst.as_slice()],
    )
    .map_err(|_| ArcError::InvalidElement)?;

    let element = Element(point);
    if element.try_to_bytes().is_err() {
        return Err(ArcError::InvalidElement);
    }
    Ok(element)
}

pub fn hash_to_scalar(input: &[u8], info: &[u8]) -> Result<Scalar> {
    let dst = dst(b"HashToScalar-", info);
    <NistP256 as GroupDigest>::hash_to_scalar::<ExpandMsgXmd<Sha256>>(&[input], &[dst.as_slice()])
        .map_err(|_| ArcError::InvalidScalar)
}

pub(crate) fn serialize_elements(elements: &[Element]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(elements.len() * NE);
    for element in elements {
        out.extend_from_slice(&element.try_to_bytes()?);
    }
    Ok(out)
}

pub(crate) fn deserialize_elements(bytes: &[u8], count: usize) -> Result<Vec<Element>> {
    let expected = count * NE;
    if bytes.len() != expected {
        return Err(ArcError::InvalidLength {
            expected,
            actual: bytes.len(),
        });
    }

    bytes.chunks_exact(NE).map(Element::from_bytes).collect()
}

pub(crate) fn deserialize_scalars(bytes: &[u8], count: usize) -> Result<Vec<Scalar>> {
    let expected = count * NS;
    if bytes.len() != expected {
        return Err(ArcError::InvalidLength {
            expected,
            actual: bytes.len(),
        });
    }

    bytes.chunks_exact(NS).map(scalar_from_bytes).collect()
}

fn dst(prefix: &[u8], info: &[u8]) -> Vec<u8> {
    let mut dst = Vec::with_capacity(prefix.len() + CONTEXT_STRING.len() + info.len());
    dst.extend_from_slice(prefix);
    dst.extend_from_slice(CONTEXT_STRING);
    dst.extend_from_slice(info);
    dst
}

fn ct_option_to_result<T>(value: CtOption<T>, error: ArcError) -> Result<T> {
    Option::<T>::from(value).ok_or(error)
}
