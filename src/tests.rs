use rand_core::{CryptoRng, Error as RandError, RngCore};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake128;

use crate::*;

const SHAKE128_RATE: usize = 168;

struct TestDrng {
    state: Shake128,
    offset: usize,
}

impl TestDrng {
    fn new(seed: &[u8; 32]) -> Self {
        let mut iv = [0u8; 64];
        iv[..b"sigma-proofs/TestDRNG/SHAKE128".len()]
            .copy_from_slice(b"sigma-proofs/TestDRNG/SHAKE128");
        let mut block = [0u8; SHAKE128_RATE];
        block[..64].copy_from_slice(&iv);

        let mut state = Shake128::default();
        state.update(&block);
        state.update(seed);
        Self { state, offset: 0 }
    }

    fn from_label(label: &[u8]) -> Self {
        let mut seed = [0u8; 32];
        seed[..label.len()].copy_from_slice(label);
        Self::new(&seed)
    }

    fn squeeze(&mut self, len: usize) -> Vec<u8> {
        let end = self.offset + len;
        let mut reader = self.state.clone().finalize_xof();
        let mut stream = vec![0u8; end];
        reader.read(&mut stream);
        let out = stream[self.offset..end].to_vec();
        self.offset = end;
        out
    }
}

impl RngCore for TestDrng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.copy_from_slice(&self.squeeze(dest.len()));
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), RandError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for TestDrng {}

fn hx(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn elem(s: &str) -> Element {
    Element::from_bytes(&hx(s)).unwrap()
}

fn scalar(s: &str) -> Scalar {
    scalar_from_bytes(&hx(s)).unwrap()
}

fn assert_scalar_eq(scalar: Scalar, expected: &str) {
    assert_eq!(scalar_to_bytes(scalar).to_vec(), hx(expected));
}

fn assert_element_eq(element: Element, expected: &str) {
    assert_eq!(element.to_bytes().unwrap().to_vec(), hx(expected));
}

fn vector_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[..b"test vector seed".len()].copy_from_slice(b"test vector seed");
    seed
}

#[test]
fn deterministic_flow_matches_draft_vectors() {
    let mut rng = TestDrng::new(&vector_seed());

    let (server_private, server_public) = setup_server(&mut rng).unwrap();
    assert_scalar_eq(server_private.x0, vectors::X0_SECRET);
    assert_scalar_eq(server_private.x1, vectors::X1_SECRET);
    assert_scalar_eq(server_private.x2, vectors::X2_SECRET);
    assert_scalar_eq(server_private.x0_blinding, vectors::XB_SECRET);
    assert_element_eq(server_public.x0, vectors::X0_PUBLIC);
    assert_element_eq(server_public.x1, vectors::X1_PUBLIC);
    assert_element_eq(server_public.x2, vectors::X2_PUBLIC);

    let (client_secrets, request) = request_credential(vectors::REQUEST_CONTEXT, &mut rng).unwrap();
    assert_scalar_eq(client_secrets.m1, vectors::M1);
    assert_scalar_eq(client_secrets.m2, vectors::M2);
    assert_scalar_eq(client_secrets.r1, vectors::R1);
    assert_scalar_eq(client_secrets.r2, vectors::R2);
    assert_element_eq(request.m1_enc, vectors::M1_ENC);
    assert_element_eq(request.m2_enc, vectors::M2_ENC);
    assert!(verify_credential_request(&request).unwrap());

    let response = respond_credential(&server_private, &server_public, &request, &mut rng).unwrap();
    assert_element_eq(response.u, vectors::RESPONSE_U);
    assert_element_eq(response.enc_u_prime, vectors::ENC_U_PRIME);
    assert_element_eq(response.x0_aux, vectors::X0_AUX);
    assert_element_eq(response.x1_aux, vectors::X1_AUX);
    assert_element_eq(response.x2_aux, vectors::X2_AUX);
    assert_element_eq(response.h_aux, vectors::H_AUX);
    assert!(verify_credential_response(&server_public, &request, &response).unwrap());

    let credential =
        finalize_credential(&client_secrets, &server_public, &request, &response).unwrap();
    assert_scalar_eq(credential.m1, vectors::CREDENTIAL_M1);
    assert_element_eq(credential.u, vectors::CREDENTIAL_U);
    assert_element_eq(credential.u_prime, vectors::U_PRIME);
    assert_element_eq(credential.x1, vectors::CREDENTIAL_X1);

    let mut state =
        PresentationState::new(credential, vectors::PRESENTATION_CONTEXT, 2).unwrap();
    let (nonce_1, presentation_1) = state.present(&mut rng).unwrap();
    assert_eq!(nonce_1, 0);
    assert_presentation_matches(&presentation_1, &vectors::P1);
    let (valid_1, tag_1) = verify_presentation(
        &server_private,
        &server_public,
        vectors::REQUEST_CONTEXT,
        vectors::PRESENTATION_CONTEXT,
        &presentation_1,
        2,
    )
    .unwrap();
    assert!(valid_1);
    assert_eq!(tag_1, presentation_1.tag);

    let (nonce_2, presentation_2) = state.present(&mut rng).unwrap();
    assert_eq!(nonce_2, 1);
    assert_presentation_matches(&presentation_2, &vectors::P2);
    let (valid_2, tag_2) = verify_presentation(
        &server_private,
        &server_public,
        vectors::REQUEST_CONTEXT,
        vectors::PRESENTATION_CONTEXT,
        &presentation_2,
        2,
    )
    .unwrap();
    assert!(valid_2);
    assert_eq!(tag_2, presentation_2.tag);
    assert_ne!(tag_1, tag_2);
    assert_eq!(state.present(&mut rng), Err(ArcError::LimitExceeded));
}

#[test]
fn published_vectors_verify_from_wire_bytes() {
    let private_key = ServerPrivateKey {
        x0: scalar(vectors::X0_SECRET),
        x1: scalar(vectors::X1_SECRET),
        x2: scalar(vectors::X2_SECRET),
        x0_blinding: scalar(vectors::XB_SECRET),
    };
    let public_key = ServerPublicKey {
        x0: elem(vectors::X0_PUBLIC),
        x1: elem(vectors::X1_PUBLIC),
        x2: elem(vectors::X2_PUBLIC),
    };
    let request = CredentialRequest {
        m1_enc: elem(vectors::M1_ENC),
        m2_enc: elem(vectors::M2_ENC),
        request_proof: hx(vectors::REQUEST_PROOF),
    };
    let response = CredentialResponse {
        u: elem(vectors::RESPONSE_U),
        enc_u_prime: elem(vectors::ENC_U_PRIME),
        x0_aux: elem(vectors::X0_AUX),
        x1_aux: elem(vectors::X1_AUX),
        x2_aux: elem(vectors::X2_AUX),
        h_aux: elem(vectors::H_AUX),
        response_proof: hx(vectors::RESPONSE_PROOF),
    };
    let client_secrets = ClientSecrets {
        m1: scalar(vectors::M1),
        m2: scalar(vectors::M2),
        r1: scalar(vectors::R1),
        r2: scalar(vectors::R2),
    };

    let request_wire = request.to_bytes().unwrap();
    assert_eq!(
        CredentialRequest::from_bytes(&request_wire).unwrap(),
        request
    );
    let response_wire = response.to_bytes().unwrap();
    assert_eq!(
        CredentialResponse::from_bytes(&response_wire).unwrap(),
        response
    );
    let unchecked_u_prime = response.enc_u_prime
        - response.x0_aux
        - response.x1_aux.mul(client_secrets.r1)
        - response.x2_aux.mul(client_secrets.r2);
    assert_element_eq(unchecked_u_prime, vectors::U_PRIME);

    let p1 = presentation_from_vectors(&vectors::P1);
    let p1_wire = p1.to_bytes(2).unwrap();
    assert_eq!(Presentation::from_bytes(2, &p1_wire).unwrap(), p1);
    let _ = (private_key, public_key);
}

#[test]
fn e2e_limit_and_negative_cases() {
    let mut rng = TestDrng::from_label(b"arc e2e negative seed");
    let (server_private, server_public) = setup_server(&mut rng).unwrap();
    let (client_secrets, request) = request_credential(b"request ctx", &mut rng).unwrap();
    let response = respond_credential(&server_private, &server_public, &request, &mut rng).unwrap();
    let credential =
        finalize_credential(&client_secrets, &server_public, &request, &response).unwrap();

    let mut bad_request = request.clone();
    bad_request.request_proof[0] ^= 1;
    assert_eq!(
        respond_credential(&server_private, &server_public, &bad_request, &mut rng).unwrap_err(),
        ArcError::ProofVerificationFailed
    );

    let mut bad_response = response.clone();
    bad_response.response_proof[0] ^= 1;
    assert_eq!(
        finalize_credential(&client_secrets, &server_public, &request, &bad_response).unwrap_err(),
        ArcError::ProofVerificationFailed
    );

    let mut state = PresentationState::new(credential, b"presentation ctx", 5).unwrap();
    let mut tags = Vec::new();
    for _ in 0..5 {
        let (_, presentation) = state.present(&mut rng).unwrap();
        let (valid, tag) = verify_presentation(
            &server_private,
            &server_public,
            b"request ctx",
            b"presentation ctx",
            &presentation,
            5,
        )
        .unwrap();
        assert!(valid);
        assert!(!tags.contains(&tag));
        tags.push(tag);

        let mut tampered = presentation.clone();
        tampered.tag = generator_g();
        assert!(
            !verify_presentation(
                &server_private,
                &server_public,
                b"request ctx",
                b"presentation ctx",
                &tampered,
                5,
            )
            .unwrap()
            .0
        );
        assert!(
            !verify_presentation(
                &server_private,
                &server_public,
                b"wrong request ctx",
                b"presentation ctx",
                &presentation,
                5,
            )
            .unwrap()
            .0
        );
    }
    assert_eq!(state.present(&mut rng), Err(ArcError::LimitExceeded));
}

#[test]
fn malformed_inputs_and_hash_domain_separation() {
    assert!(CredentialRequest::from_bytes(&[0u8; 8]).is_err());
    assert!(Element::from_bytes(&[0u8; NE]).is_err());
    assert!(scalar_from_bytes(&[0xff; NS]).is_err());
    assert_eq!(
        PresentationState::new(
            Credential {
                m1: Scalar::ONE,
                u: generator_g(),
                u_prime: generator_h(),
                x1: generator_h(),
            },
            b"ctx",
            0,
        )
        .unwrap_err(),
        ArcError::InvalidPresentationLimit
    );

    assert_eq!(
        hash_to_group(b"abc", b"domain").unwrap(),
        hash_to_group(b"abc", b"domain").unwrap()
    );
    assert_ne!(
        hash_to_group(b"abc", b"domain").unwrap(),
        hash_to_group(b"abc", b"other").unwrap()
    );
    assert_eq!(
        hash_to_scalar(b"abc", b"domain").unwrap(),
        hash_to_scalar(b"abc", b"domain").unwrap()
    );
    assert_ne!(
        hash_to_scalar(b"abc", b"domain").unwrap(),
        hash_to_scalar(b"abc", b"other").unwrap()
    );
}

fn assert_presentation_matches(presentation: &Presentation, expected: &ExpectedPresentation) {
    assert_element_eq(presentation.u, expected.u);
    assert_element_eq(presentation.u_prime_commit, expected.u_prime_commit);
    assert_element_eq(presentation.m1_commit, expected.m1_commit);
    assert_element_eq(presentation.nonce_commit, expected.nonce_commit);
    assert_element_eq(presentation.tag, expected.tag);
    assert_eq!(presentation.proof.d.len(), 1);
    assert_element_eq(presentation.proof.d[0], expected.d0);
}

fn presentation_from_vectors(expected: &ExpectedPresentation) -> Presentation {
    Presentation {
        u: elem(expected.u),
        u_prime_commit: elem(expected.u_prime_commit),
        m1_commit: elem(expected.m1_commit),
        tag: elem(expected.tag),
        nonce_commit: elem(expected.nonce_commit),
        proof: PresentationProof::from_bytes(2, &hx(expected.proof)).unwrap(),
    }
}

struct ExpectedPresentation {
    u: &'static str,
    u_prime_commit: &'static str,
    m1_commit: &'static str,
    nonce_commit: &'static str,
    tag: &'static str,
    d0: &'static str,
    proof: &'static str,
}

mod vectors {
    use super::ExpectedPresentation;

    pub const REQUEST_CONTEXT: &[u8] = b"test request context";
    pub const PRESENTATION_CONTEXT: &[u8] = b"test presentation context";

    pub const X0_SECRET: &str =
        "1008f2c706ae2157c75e41b2d75695c7bf480d0632a1ef447036cafe4cabb021";
    pub const X1_SECRET: &str =
        "526e009578f6f25fdec992343f09f5e6c58489c31fcf8a934bbaf85797121bdd";
    pub const X2_SECRET: &str =
        "549075ccd3d1c36b3546725c43e71943414409a23b980b2c47a3fc2b9c37679b";
    pub const XB_SECRET: &str =
        "7276533ce3c89f04a007c2e8aa7d2e3b36829d0eaab5631347d8336c2da09a8e";
    pub const X0_PUBLIC: &str =
        "03bad54cc48293ef3472ac1ada55c9c9fdb3eb99ee47369bbe1d3ce46b300cd7b3";
    pub const X1_PUBLIC: &str =
        "02a0323862a05707d76862bfa8477eed468441ceae14c8fb1659e0b3020b8a24e1";
    pub const X2_PUBLIC: &str =
        "031d16ef08ede5a347e94a8eca071bec7bedb9d8ba943d24bde912a4e1578e529b";

    pub const M1: &str =
        "141c4ca5e614af8e5e323eb47a7e7673ebb67caf49dfa8e109f45f231227f7a0";
    pub const M2: &str =
        "911fb315257d9ae29d47ecb48c6fa27074dee6860a0489f8db6ac9a486be6a3e";
    pub const R1: &str =
        "5c183d2dea942eb2780afb90cfd94983ae6575d60e350021c8c93008ac503973";
    pub const R2: &str =
        "044d4a5b5daf00dd1fb4444ca2f8c3facc95d537d5ad0e0a2815c912e98a431d";
    pub const M1_ENC: &str =
        "033fe5d950712f711e5d292d68f804fad4c35fb7f3f1866516448647d4aab12590";
    pub const M2_ENC: &str =
        "026502a833ed1d972ee27175e750b1719adee12726c653125887c0d32b1f3747ab";
    pub const REQUEST_PROOF: &str =
        "2a088673e302502a3dc80d6100a1bb709083ac7b31da34f9a7c52e7cfeaa2ea30b7341133086e64b79dfc6cdac9f348ddbed0b087746f0167ea238d3ddf17e613880b73e85f499c7eddc6555355ea71487b49862400091b5b32cb219d7104f571306bc6f2487bab299bb2e9a1078dee94d83b6536ed570f8114ee9c97b8b602bfacbeb3764f6a22915a19c24895a6bf7048c663337f7690f0182a1f866586d9e";

    pub const RESPONSE_U: &str =
        "021cf52318c97c33472cc8fb42a5b5a774f83c3b36e6c782209d53e5945d99a493";
    pub const ENC_U_PRIME: &str =
        "02ae23020d5427c7f785a72d77c24997f955e66ab7c378c334b7c259dabdf572d7";
    pub const X0_AUX: &str =
        "031523abe64e436e65e592abdae322dc556fcbea707757e18d4160ba57d574cd87";
    pub const X1_AUX: &str =
        "023cc3b53807f6e0082b675794ae9f6b370483ca5a3e6d688c3b81f2fdb6d4ec00";
    pub const X2_AUX: &str =
        "0329dc7c93f8a231a1f16ec69f0fba446e022ce69945b20f37386a7fda3e573b79";
    pub const H_AUX: &str =
        "0389746891b6dbf062511619eae7d72ae87630bea1e277a925708fdfef8363a1d4";
    pub const RESPONSE_PROOF: &str =
        "ec342aee0d481435379ea6bbe919edd5d2eb9c12198a083e0e899da1f14dbc46a8048f5a12c5cae21e5f5949fe08d1c15c266c63544615400def4ce9a6cf8aee32052ced26e7a9d854f2c45ea23ffea0f6bf977f6155d412991abc0e2d1ad83504129c1ac8319b2a45940c52c4b41bde80969313641b9cb727445e20b44d0ea884e9b180cd152442883038b97d72772201f281d76a18d22e374bd989accd76548067399162428c4d25daf1b7f68f3580a38cc4564a88f28494649064500f06c5b946dde032a389f8fe337605627ce91a92c20db911100a2c7c42ae15fde5a5cbd9d078b819a80423593192c40d70ce77f1a6d377770fe5c05781782bd1eaa43f";

    pub const CREDENTIAL_M1: &str = M1;
    pub const CREDENTIAL_U: &str = RESPONSE_U;
    pub const U_PRIME: &str =
        "02646199272c28911165b4d1c5f4ffbd8a83f686948fd4c7250e28c81dbfecd354";
    pub const CREDENTIAL_X1: &str = X1_PUBLIC;

    pub const P1: ExpectedPresentation = ExpectedPresentation {
        u: "0216af8901c1ad38a703bf9003fabea440b411b4f072fd23b5254cb17d1b5bf33d",
        u_prime_commit: "03140f8e6f6c5eab3d03a7fba5d542362a9bc00a89d80caa5051b4e4446b0b01f3",
        m1_commit: "0214d0297c21120d621cc6fed75852569de3cbf0bd9f5a8a812cf6b024bf51e627",
        nonce_commit: "032326abcd4eb2fd1a47053ec9ce1aab3ee91e98373d610e9752a7d16a5c1e38d8",
        tag: "0281428e61688f4e7989dbe8dab170705c81b294c4a73b785a0754712fc968eb40",
        d0: "032326abcd4eb2fd1a47053ec9ce1aab3ee91e98373d610e9752a7d16a5c1e38d8",
        proof: "032326abcd4eb2fd1a47053ec9ce1aab3ee91e98373d610e9752a7d16a5c1e38d8946f5f0b44e34f826b41ec59a4e2dcfaa826b8a39cc278e10b1b02b5dbaafdb6e789639885a8d2d69269a9fea55830f1d7e1fd0a771183b7b4eebe5e03e0c0255d1ba614de7e31d4f46eb93a24e0ffe9864b002527109a516a10dc1ad718b8d984efd16ab245d7a5dfabe2d0027e23796981422b19c2821a831cb46a8e9b8b566bbdb55b649021bf2f777b9130c2e375f560eee4691d04bd38e9571d9451257858d9128002a2f8908d7e4521510a2185244fa533e2502b61e502fd157d974f91acc4f2ba0d724f2bfd182d5df4d038e74b5c35cc7c4aa7622c2682e040877eebcc18fe822cc6abab5d3adc9db836991d3d1ecf699658245b8b0756946ba0d7756b433aae3b476ccbc2186b2fe2ecc2fe0da30df264802829254df8196a8307f0",
    };

    pub const P2: ExpectedPresentation = ExpectedPresentation {
        u: "0357e53851143e7cc34311bdba0d44d4d3c9192180434ce247b8766232b5de1e08",
        u_prime_commit: "02bad8dc9b0179dff7a1d63d03d92810520085cbc41b65b667d3cbe2203eb7c544",
        m1_commit: "02455589d2b92a24e49ff8c2e8287f6eeb05cbfddc16aba66dfe9ab97702bc3c35",
        nonce_commit: "0363d6bd2969b64a42354ba896be33a4abce479261d7dec0001fa1af7fbdeecb41",
        tag: "02ad6c293325d0c2c388c8b2240b6d8ab9e52395297ef5921fb78ace6a1274b03b",
        d0: "0363d6bd2969b64a42354ba896be33a4abce479261d7dec0001fa1af7fbdeecb41",
        proof: "0363d6bd2969b64a42354ba896be33a4abce479261d7dec0001fa1af7fbdeecb417c59300e0aafb0d58e3f85423030401dabe5dd39566924f07e99cae5b3be62f45e736890857cfe0950c22c93c52d56e6ade5f5a1c1d486e9261e7788b74543870115370c46e62e376b17844a287bbb6722dc5e5848fdbd8d19d259ec1cec83851a1ef4a21dadefeef3f5222eb19361facbb2ec3ba640aef22cd5700a17ea17fc3ece772f5b5cca1e119bf32cfa7f3459c2184d6d8c777d281c91b416187ee949c9557fece8afb0ac785c7b8c4854e622f8b005daf5c0682cfdc2d900150087bae0090d44b7bac130c7f4067bb8b3374b159106d0c03e30f9577063de0b52d15d1f5f41328b335ee23d10ca7dc4e0717bd9e919e3f6f580e594b3c48b358baa7a320ec9e1019260efe2cbf6e9cba6871ffee3b5566d5e865c729c5e1d48529559",
    };
}
