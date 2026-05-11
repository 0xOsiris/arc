use rand_core::RngCore;
use zeroize::Zeroize;

use crate::error::{ArcError, Result};
use crate::group::{
    Element, NE, NS, Scalar, deserialize_elements, deserialize_scalars, generator_g, generator_h,
    hash_to_group, hash_to_scalar, random_scalar, scalar_inverse, scalar_to_bytes,
    serialize_elements,
};
use crate::proof::{LinearRelation, prove, verify};
use crate::range::{compute_bases, make_range_proof_helper, verify_range_proof_helper};

const REQUEST_PROOF_SCALARS: usize = 5;
const RESPONSE_PROOF_SCALARS: usize = 8;

#[derive(Clone, Debug, Zeroize)]
pub struct ServerPrivateKey {
    pub x0: Scalar,
    pub x1: Scalar,
    pub x2: Scalar,
    pub x0_blinding: Scalar,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerPublicKey {
    pub x0: Element,
    pub x1: Element,
    pub x2: Element,
}

#[derive(Clone, Debug, Zeroize)]
pub struct ClientSecrets {
    pub m1: Scalar,
    pub m2: Scalar,
    pub r1: Scalar,
    pub r2: Scalar,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialRequest {
    pub m1_enc: Element,
    pub m2_enc: Element,
    pub request_proof: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialResponse {
    pub u: Element,
    pub enc_u_prime: Element,
    pub x0_aux: Element,
    pub x1_aux: Element,
    pub x2_aux: Element,
    pub h_aux: Element,
    pub response_proof: Vec<u8>,
}

#[derive(Clone, Debug, Zeroize)]
pub struct Credential {
    pub m1: Scalar,
    #[zeroize(skip)]
    pub u: Element,
    #[zeroize(skip)]
    pub u_prime: Element,
    #[zeroize(skip)]
    pub x1: Element,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresentationProof {
    pub d: Vec<Element>,
    pub challenge: Scalar,
    pub responses: Vec<Scalar>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Presentation {
    pub u: Element,
    pub u_prime_commit: Element,
    pub m1_commit: Element,
    pub tag: Element,
    pub nonce_commit: Element,
    pub proof: PresentationProof,
}

#[derive(Clone, Debug)]
pub struct PresentationState {
    credential: Credential,
    presentation_context: Vec<u8>,
    presentation_limit: u64,
    next_nonce: u64,
}

impl ServerPublicKey {
    pub const BYTE_LEN: usize = 3 * NE;

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serialize_elements(&[self.x0, self.x1, self.x2])
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let elements = deserialize_elements(bytes, 3)?;
        Ok(Self {
            x0: elements[0],
            x1: elements[1],
            x2: elements[2],
        })
    }
}

impl CredentialRequest {
    pub const BYTE_LEN: usize = 2 * NE + REQUEST_PROOF_SCALARS * NS;

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = serialize_elements(&[self.m1_enc, self.m2_enc])?;
        if self.request_proof.len() != REQUEST_PROOF_SCALARS * NS {
            return Err(ArcError::InvalidProofLength {
                expected: REQUEST_PROOF_SCALARS * NS,
                actual: self.request_proof.len(),
            });
        }
        out.extend_from_slice(&self.request_proof);
        Ok(out)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::BYTE_LEN {
            return Err(ArcError::InvalidLength {
                expected: Self::BYTE_LEN,
                actual: bytes.len(),
            });
        }

        let elements = deserialize_elements(&bytes[..2 * NE], 2)?;
        Ok(Self {
            m1_enc: elements[0],
            m2_enc: elements[1],
            request_proof: bytes[2 * NE..].to_vec(),
        })
    }
}

impl CredentialResponse {
    pub const BYTE_LEN: usize = 6 * NE + RESPONSE_PROOF_SCALARS * NS;

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = serialize_elements(&[
            self.u,
            self.enc_u_prime,
            self.x0_aux,
            self.x1_aux,
            self.x2_aux,
            self.h_aux,
        ])?;
        if self.response_proof.len() != RESPONSE_PROOF_SCALARS * NS {
            return Err(ArcError::InvalidProofLength {
                expected: RESPONSE_PROOF_SCALARS * NS,
                actual: self.response_proof.len(),
            });
        }
        out.extend_from_slice(&self.response_proof);
        Ok(out)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::BYTE_LEN {
            return Err(ArcError::InvalidLength {
                expected: Self::BYTE_LEN,
                actual: bytes.len(),
            });
        }

        let elements = deserialize_elements(&bytes[..6 * NE], 6)?;
        Ok(Self {
            u: elements[0],
            enc_u_prime: elements[1],
            x0_aux: elements[2],
            x1_aux: elements[3],
            x2_aux: elements[4],
            h_aux: elements[5],
            response_proof: bytes[6 * NE..].to_vec(),
        })
    }
}

impl PresentationProof {
    pub fn byte_len(presentation_limit: u64) -> Result<usize> {
        let k = compute_bases(presentation_limit)?.len();
        Ok(k * NE + (6 + 3 * k) * NS)
    }

    pub fn to_bytes(&self, presentation_limit: u64) -> Result<Vec<u8>> {
        let k = compute_bases(presentation_limit)?.len();
        let expected_responses = 5 + 3 * k;
        if self.d.len() != k {
            return Err(ArcError::InvalidRangeProof);
        }
        if self.responses.len() != expected_responses {
            return Err(ArcError::InvalidProofLength {
                expected: expected_responses * NS,
                actual: self.responses.len() * NS,
            });
        }

        let mut out = serialize_elements(&self.d)?;
        out.extend_from_slice(&scalar_to_bytes(self.challenge));
        for response in &self.responses {
            out.extend_from_slice(&scalar_to_bytes(*response));
        }
        Ok(out)
    }

    pub fn from_bytes(presentation_limit: u64, bytes: &[u8]) -> Result<Self> {
        let k = compute_bases(presentation_limit)?.len();
        let expected = Self::byte_len(presentation_limit)?;
        if bytes.len() != expected {
            return Err(ArcError::InvalidProofLength {
                expected,
                actual: bytes.len(),
            });
        }

        let d_len = k * NE;
        let d = deserialize_elements(&bytes[..d_len], k)?;
        let scalars = deserialize_scalars(&bytes[d_len..], 1 + 5 + 3 * k)?;
        Ok(Self {
            d,
            challenge: scalars[0],
            responses: scalars[1..].to_vec(),
        })
    }

    fn schnorr_bytes(&self, presentation_limit: u64) -> Result<Vec<u8>> {
        let k = compute_bases(presentation_limit)?.len();
        let expected_responses = 5 + 3 * k;
        if self.responses.len() != expected_responses {
            return Err(ArcError::InvalidProofLength {
                expected: (1 + expected_responses) * NS,
                actual: (1 + self.responses.len()) * NS,
            });
        }

        let mut out = Vec::with_capacity((1 + self.responses.len()) * NS);
        out.extend_from_slice(&scalar_to_bytes(self.challenge));
        for response in &self.responses {
            out.extend_from_slice(&scalar_to_bytes(*response));
        }
        Ok(out)
    }
}

impl Presentation {
    pub fn byte_len(presentation_limit: u64) -> Result<usize> {
        Ok(5 * NE + PresentationProof::byte_len(presentation_limit)?)
    }

    pub fn to_bytes(&self, presentation_limit: u64) -> Result<Vec<u8>> {
        let mut out = serialize_elements(&[
            self.u,
            self.u_prime_commit,
            self.m1_commit,
            self.tag,
            self.nonce_commit,
        ])?;
        out.extend_from_slice(&self.proof.to_bytes(presentation_limit)?);
        Ok(out)
    }

    pub fn from_bytes(presentation_limit: u64, bytes: &[u8]) -> Result<Self> {
        let expected = Self::byte_len(presentation_limit)?;
        if bytes.len() != expected {
            return Err(ArcError::InvalidLength {
                expected,
                actual: bytes.len(),
            });
        }

        let elements = deserialize_elements(&bytes[..5 * NE], 5)?;
        Ok(Self {
            u: elements[0],
            u_prime_commit: elements[1],
            m1_commit: elements[2],
            tag: elements[3],
            nonce_commit: elements[4],
            proof: PresentationProof::from_bytes(presentation_limit, &bytes[5 * NE..])?,
        })
    }
}

impl PresentationState {
    pub fn new(
        credential: Credential,
        presentation_context: impl Into<Vec<u8>>,
        presentation_limit: u64,
    ) -> Result<Self> {
        compute_bases(presentation_limit)?;
        Ok(Self {
            credential,
            presentation_context: presentation_context.into(),
            presentation_limit,
            next_nonce: 0,
        })
    }

    pub fn next_nonce(&self) -> u64 {
        self.next_nonce
    }

    pub fn present<R: RngCore + ?Sized>(&mut self, rng: &mut R) -> Result<(u64, Presentation)> {
        if self.next_nonce >= self.presentation_limit {
            return Err(ArcError::LimitExceeded);
        }

        let nonce = self.next_nonce;
        let nonce_scalar = Scalar::from(nonce);
        let a = random_scalar(rng);
        let r = random_scalar(rng);
        let z = random_scalar(rng);

        let u = self.credential.u.mul(a);
        let u_prime = self.credential.u_prime.mul(a);
        let u_prime_commit = u_prime + generator_g().mul(r);
        let m1_commit = u.mul(self.credential.m1) + generator_h().mul(z);

        let nonce_blinding = random_scalar(rng);
        let nonce_commit = generator_g().mul(nonce_scalar) + generator_h().mul(nonce_blinding);
        let generator_t = hash_to_group(&self.presentation_context, b"Tag")?;
        let tag = generator_t.mul(scalar_inverse(self.credential.m1 + nonce_scalar)?);
        let v = self.credential.x1.mul(z) - generator_g().mul(r);

        let proof = make_presentation_proof(
            &self.credential,
            PresentationPublicInputs {
                u,
                u_prime_commit,
                m1_commit,
                tag,
                generator_t,
                nonce_commit,
                v,
            },
            r,
            z,
            nonce,
            nonce_blinding,
            self.presentation_limit,
            rng,
        )?;

        self.next_nonce += 1;
        Ok((
            nonce,
            Presentation {
                u,
                u_prime_commit,
                m1_commit,
                tag,
                nonce_commit,
                proof,
            },
        ))
    }
}

pub fn setup_server<R: RngCore + ?Sized>(rng: &mut R) -> Result<(ServerPrivateKey, ServerPublicKey)> {
    let x0 = random_scalar(rng);
    let x1 = random_scalar(rng);
    let x2 = random_scalar(rng);
    let x0_blinding = random_scalar(rng);
    let private_key = ServerPrivateKey {
        x0,
        x1,
        x2,
        x0_blinding,
    };
    let public_key = ServerPublicKey {
        x0: generator_g().mul(x0) + generator_h().mul(x0_blinding),
        x1: generator_h().mul(x1),
        x2: generator_h().mul(x2),
    };
    Ok((private_key, public_key))
}

pub fn request_credential<R: RngCore + ?Sized>(
    request_context: &[u8],
    rng: &mut R,
) -> Result<(ClientSecrets, CredentialRequest)> {
    let m1 = random_scalar(rng);
    let m2 = hash_to_scalar(request_context, b"requestContext")?;
    let r1 = random_scalar(rng);
    let r2 = random_scalar(rng);

    let m1_enc = generator_g().mul(m1) + generator_h().mul(r1);
    let m2_enc = generator_g().mul(m2) + generator_h().mul(r2);
    let request_proof = make_credential_request_proof(m1, m2, r1, r2, m1_enc, m2_enc, rng)?;

    Ok((
        ClientSecrets { m1, m2, r1, r2 },
        CredentialRequest {
            m1_enc,
            m2_enc,
            request_proof,
        },
    ))
}

pub fn verify_credential_request(request: &CredentialRequest) -> Result<bool> {
    let statement = credential_request_statement(request.m1_enc, request.m2_enc)?;
    verify(
        &[crate::group::CONTEXT_STRING, b"CredentialRequest"].concat(),
        &statement,
        &request.request_proof,
    )
}

pub fn respond_credential<R: RngCore + ?Sized>(
    private_key: &ServerPrivateKey,
    public_key: &ServerPublicKey,
    request: &CredentialRequest,
    rng: &mut R,
) -> Result<CredentialResponse> {
    if !verify_credential_request(request)? {
        return Err(ArcError::ProofVerificationFailed);
    }

    let b = random_scalar(rng);
    let u = generator_g().mul(b);
    let enc_u_prime = (public_key.x0 + request.m1_enc.mul(private_key.x1) + request.m2_enc.mul(private_key.x2)).mul(b);
    let x0_aux = generator_h().mul(b * private_key.x0_blinding);
    let x1_aux = public_key.x1.mul(b);
    let x2_aux = public_key.x2.mul(b);
    let h_aux = generator_h().mul(b);

    let mut response = CredentialResponse {
        u,
        enc_u_prime,
        x0_aux,
        x1_aux,
        x2_aux,
        h_aux,
        response_proof: Vec::new(),
    };
    response.response_proof =
        make_credential_response_proof(private_key, public_key, request, &response, b, rng)?;
    Ok(response)
}

pub fn verify_credential_response(
    public_key: &ServerPublicKey,
    request: &CredentialRequest,
    response: &CredentialResponse,
) -> Result<bool> {
    let statement = credential_response_statement(public_key, request, response)?;
    verify(
        &[crate::group::CONTEXT_STRING, b"CredentialResponse"].concat(),
        &statement,
        &response.response_proof,
    )
}

pub fn finalize_credential(
    client_secrets: &ClientSecrets,
    public_key: &ServerPublicKey,
    request: &CredentialRequest,
    response: &CredentialResponse,
) -> Result<Credential> {
    if !verify_credential_response(public_key, request, response)? {
        return Err(ArcError::ProofVerificationFailed);
    }

    let u_prime = response.enc_u_prime
        - response.x0_aux
        - response.x1_aux.mul(client_secrets.r1)
        - response.x2_aux.mul(client_secrets.r2);
    Ok(Credential {
        m1: client_secrets.m1,
        u: response.u,
        u_prime,
        x1: public_key.x1,
    })
}

pub fn verify_presentation(
    private_key: &ServerPrivateKey,
    public_key: &ServerPublicKey,
    request_context: &[u8],
    presentation_context: &[u8],
    presentation: &Presentation,
    presentation_limit: u64,
) -> Result<(bool, Element)> {
    compute_bases(presentation_limit)?;
    let valid = verify_presentation_proof(
        private_key,
        public_key,
        request_context,
        presentation_context,
        presentation,
        presentation_limit,
    )?;
    Ok((valid, presentation.tag))
}

pub(crate) fn credential_request_statement(
    m1_enc: Element,
    m2_enc: Element,
) -> Result<LinearRelation> {
    let mut statement = LinearRelation::new();
    let [m1_var, m2_var, r1_var, r2_var] = statement.allocate_scalars();
    let [gen_g_var, gen_h_var, m1_enc_var, m2_enc_var] = statement.allocate_elements();
    statement.set_elements(&[
        (gen_g_var, generator_g()),
        (gen_h_var, generator_h()),
        (m1_enc_var, m1_enc),
        (m2_enc_var, m2_enc),
    ])?;
    statement.append_equation(m1_enc_var, &[(m1_var, gen_g_var), (r1_var, gen_h_var)]);
    statement.append_equation(m2_enc_var, &[(m2_var, gen_g_var), (r2_var, gen_h_var)]);
    Ok(statement)
}

fn make_credential_request_proof<R: RngCore + ?Sized>(
    m1: Scalar,
    m2: Scalar,
    r1: Scalar,
    r2: Scalar,
    m1_enc: Element,
    m2_enc: Element,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let statement = credential_request_statement(m1_enc, m2_enc)?;
    prove(
        &[crate::group::CONTEXT_STRING, b"CredentialRequest"].concat(),
        &statement,
        &[m1, m2, r1, r2],
        rng,
    )
}

fn credential_response_statement(
    public_key: &ServerPublicKey,
    request: &CredentialRequest,
    response: &CredentialResponse,
) -> Result<LinearRelation> {
    let mut statement = LinearRelation::new();
    let [x0_var, x1_var, x2_var, xb_var, b_var, t1_var, t2_var] =
        statement.allocate_scalars();
    let [
        gen_g_var,
        gen_h_var,
        m1_enc_var,
        m2_enc_var,
        u_var,
        enc_u_prime_var,
        x0_var_el,
        x1_var_el,
        x2_var_el,
        x0_aux_var,
        x1_aux_var,
        x2_aux_var,
        h_aux_var,
    ] = statement.allocate_elements();

    statement.set_elements(&[
        (gen_g_var, generator_g()),
        (gen_h_var, generator_h()),
        (m1_enc_var, request.m1_enc),
        (m2_enc_var, request.m2_enc),
        (u_var, response.u),
        (enc_u_prime_var, response.enc_u_prime),
        (x0_var_el, public_key.x0),
        (x1_var_el, public_key.x1),
        (x2_var_el, public_key.x2),
        (x0_aux_var, response.x0_aux),
        (x1_aux_var, response.x1_aux),
        (x2_aux_var, response.x2_aux),
        (h_aux_var, response.h_aux),
    ])?;

    statement.append_equation(x0_var_el, &[(x0_var, gen_g_var), (xb_var, gen_h_var)]);
    statement.append_equation(x1_var_el, &[(x1_var, gen_h_var)]);
    statement.append_equation(x2_var_el, &[(x2_var, gen_h_var)]);
    statement.append_equation(h_aux_var, &[(b_var, gen_h_var)]);
    statement.append_equation(x0_aux_var, &[(xb_var, h_aux_var)]);
    statement.append_equation(x1_aux_var, &[(t1_var, gen_h_var)]);
    statement.append_equation(x1_aux_var, &[(b_var, x1_var_el)]);
    statement.append_equation(x2_aux_var, &[(b_var, x2_var_el)]);
    statement.append_equation(x2_aux_var, &[(t2_var, gen_h_var)]);
    statement.append_equation(u_var, &[(b_var, gen_g_var)]);
    statement.append_equation(
        enc_u_prime_var,
        &[(b_var, x0_var_el), (t1_var, m1_enc_var), (t2_var, m2_enc_var)],
    );
    Ok(statement)
}

fn make_credential_response_proof<R: RngCore + ?Sized>(
    private_key: &ServerPrivateKey,
    public_key: &ServerPublicKey,
    request: &CredentialRequest,
    response: &CredentialResponse,
    b: Scalar,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let statement = credential_response_statement(public_key, request, response)?;
    let witness = [
        private_key.x0,
        private_key.x1,
        private_key.x2,
        private_key.x0_blinding,
        b,
        b * private_key.x1,
        b * private_key.x2,
    ];
    prove(
        &[crate::group::CONTEXT_STRING, b"CredentialResponse"].concat(),
        &statement,
        &witness,
        rng,
    )
}

#[derive(Clone, Copy)]
struct PresentationPublicInputs {
    u: Element,
    u_prime_commit: Element,
    m1_commit: Element,
    tag: Element,
    generator_t: Element,
    nonce_commit: Element,
    v: Element,
}

fn presentation_statement(
    public_key_x1: Element,
    inputs: PresentationPublicInputs,
    range_d: Option<&[Element]>,
    nonce_commit: Element,
    presentation_limit: u64,
) -> Result<(LinearRelation, bool)> {
    let mut statement = LinearRelation::new();
    let [m1_var, z_var, r_neg_var, nonce_var, nonce_blinding_var] =
        statement.allocate_scalars();
    let [
        gen_g_var,
        gen_h_var,
        u_var,
        u_prime_commit_var,
        m1_commit_var,
        v_var,
        x1_var,
        tag_var,
        gen_t_var,
        nonce_commit_var,
    ] = statement.allocate_elements();

    statement.set_elements(&[
        (gen_g_var, generator_g()),
        (gen_h_var, generator_h()),
        (u_var, inputs.u),
        (u_prime_commit_var, inputs.u_prime_commit),
        (m1_commit_var, inputs.m1_commit),
        (v_var, inputs.v),
        (x1_var, public_key_x1),
        (tag_var, inputs.tag),
        (gen_t_var, inputs.generator_t),
        (nonce_commit_var, nonce_commit),
    ])?;

    statement.append_equation(m1_commit_var, &[(m1_var, u_var), (z_var, gen_h_var)]);
    statement.append_equation(v_var, &[(z_var, x1_var), (r_neg_var, gen_g_var)]);
    statement.append_equation(
        nonce_commit_var,
        &[(nonce_var, gen_g_var), (nonce_blinding_var, gen_h_var)],
    );
    statement.append_equation(gen_t_var, &[(m1_var, tag_var), (nonce_var, tag_var)]);

    let sum_valid = if let Some(d) = range_d {
        verify_range_proof_helper(
            &mut statement,
            d,
            nonce_commit,
            presentation_limit,
            gen_g_var,
            gen_h_var,
            nonce_commit_var,
        )?
    } else {
        true
    };

    Ok((statement, sum_valid))
}

fn make_presentation_proof<R: RngCore + ?Sized>(
    credential: &Credential,
    inputs: PresentationPublicInputs,
    r: Scalar,
    z: Scalar,
    nonce: u64,
    nonce_blinding: Scalar,
    presentation_limit: u64,
    rng: &mut R,
) -> Result<PresentationProof> {
    let (mut statement, _) = presentation_statement(
        credential.x1,
        inputs,
        None,
        inputs.nonce_commit,
        presentation_limit,
    )?;

    let [gen_g_var, gen_h_var, _, _, _, _, _, _, _, nonce_commit_var] =
        [0usize, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let (d, mut range_witness) = make_range_proof_helper(
        &mut statement,
        nonce,
        nonce_blinding,
        presentation_limit,
        gen_g_var,
        gen_h_var,
        nonce_commit_var,
        inputs.nonce_commit,
        rng,
    )?;

    let mut witness = vec![
        credential.m1,
        z,
        -r,
        Scalar::from(nonce),
        nonce_blinding,
    ];
    witness.append(&mut range_witness);

    let proof_bytes = prove(
        &[crate::group::CONTEXT_STRING, b"CredentialPresentation"].concat(),
        &statement,
        &witness,
        rng,
    )?;
    let scalars = deserialize_scalars(&proof_bytes, 1 + witness.len())?;

    Ok(PresentationProof {
        d,
        challenge: scalars[0],
        responses: scalars[1..].to_vec(),
    })
}

fn verify_presentation_proof(
    private_key: &ServerPrivateKey,
    public_key: &ServerPublicKey,
    request_context: &[u8],
    presentation_context: &[u8],
    presentation: &Presentation,
    presentation_limit: u64,
) -> Result<bool> {
    let m2 = hash_to_scalar(request_context, b"requestContext")?;
    let v = presentation.u.mul(private_key.x0)
        + presentation.m1_commit.mul(private_key.x1)
        + presentation.u.mul(private_key.x2 * m2)
        - presentation.u_prime_commit;
    let generator_t = hash_to_group(presentation_context, b"Tag")?;
    let inputs = PresentationPublicInputs {
        u: presentation.u,
        u_prime_commit: presentation.u_prime_commit,
        m1_commit: presentation.m1_commit,
        tag: presentation.tag,
        generator_t,
        nonce_commit: presentation.nonce_commit,
        v,
    };
    let (statement, sum_valid) = presentation_statement(
        public_key.x1,
        inputs,
        Some(&presentation.proof.d),
        presentation.nonce_commit,
        presentation_limit,
    )?;
    if !sum_valid {
        return Ok(false);
    }

    verify(
        &[crate::group::CONTEXT_STRING, b"CredentialPresentation"].concat(),
        &statement,
        &presentation.proof.schnorr_bytes(presentation_limit)?,
    )
}
