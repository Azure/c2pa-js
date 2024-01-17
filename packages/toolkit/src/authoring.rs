use std::{convert::TryInto, str::FromStr};

use async_trait::async_trait;
use c2pa::{AsyncSigner, SigningAlg};
use js_sys::{Function, Promise, Uint8Array};
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;
use x509_certificate::DigestAlgorithm;

fn get_digest_algorithm(alg: SigningAlg) -> DigestAlgorithm {
    match alg {
        SigningAlg::Es256 | SigningAlg::Ps256 => DigestAlgorithm::Sha256,
        SigningAlg::Es384 | SigningAlg::Ps384 => DigestAlgorithm::Sha384,
        SigningAlg::Es512 | SigningAlg::Ps512 | SigningAlg::Ed25519 => DigestAlgorithm::Sha512,
    }
}

pub fn rfc3161_time_stamp_message(
    alg: SigningAlg,
    digest: &[u8],
    random: [u8; 8],
) -> c2pa::Result<Vec<u8>> {
    use bcder::encode::Values;

    let request = c2pa::TimeStampReq {
        version: bcder::Integer::from(1_u8),
        message_imprint: c2pa::MessageImprint {
            hash_algorithm: get_digest_algorithm(alg).into(),
            hashed_message: bcder::OctetString::new(bytes::Bytes::copy_from_slice(digest)),
        },
        req_policy: None,
        nonce: Some(bcder::Integer::from(u64::from_le_bytes(random))),
        cert_req: Some(true),
        extensions: None,
    };
    let mut body = Vec::<u8>::new();
    request
        .encode_ref()
        .write_encoded(bcder::Mode::Der, &mut body)?;
    Ok(body)
}

pub struct KeyVaultSigner {
    pub sign: Function,
    pub digest: Function,
    pub random: Function,
    pub timestamp: Option<Function>,
    pub alg: SigningAlg,
    certs: Vec<Vec<u8>>,
}

impl KeyVaultSigner {
    pub fn new(
        sign: Function,
        digest: Function,
        random: Function,
        timestamp: Option<Function>,
        certs: Vec<Vec<u8>>,
        alg: &str,
    ) -> Self {
        Self {
            sign,
            digest,
            random,
            timestamp,
            alg: SigningAlg::from_str(alg).unwrap(),
            certs,
        }
    }

    async fn async_callback_with_arg(func: &Function, arg: &JsValue) -> c2pa::Result<Vec<u8>> {
        let this = JsValue::null();
        let promise = func.call1(&this, arg).unwrap();
        let future = JsFuture::from(Promise::from(promise));
        let result = future.await.unwrap();
        let data = Uint8Array::new(&result).to_vec();
        Ok(data)
    }

    async fn async_callback_with_buffer(func: &Function, data: &[u8]) -> c2pa::Result<Vec<u8>> {
        let array = Uint8Array::new_with_length(data.len() as u32);
        array.copy_from(data);
        let arg = array.into();
        Self::async_callback_with_arg(func, &arg).await
    }
}

unsafe impl Sync for KeyVaultSigner {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl AsyncSigner for KeyVaultSigner {
    async fn sign(&self, data: Vec<u8>) -> c2pa::Result<Vec<u8>> {
        let digest = Self::async_callback_with_buffer(&self.digest, &data).await?;
        let result = Self::async_callback_with_buffer(&self.sign, &digest)
            .await
            .unwrap();
        Ok(result)
    }

    fn alg(&self) -> SigningAlg {
        self.alg
    }

    fn certs(&self) -> c2pa::Result<Vec<Vec<u8>>> {
        Ok(self.certs.clone())
    }

    // Good enough estimate but needs to be based on algorithm.
    fn reserve_size(&self) -> usize {
        8192 + self.certs.iter().map(|x| x.len()).sum::<usize>()
    }

    async fn send_timestamp_request(&self, message: &[u8]) -> Option<c2pa::Result<Vec<u8>>> {
        if let Some(timestamp) = self.timestamp.clone() {
            let digest = Self::async_callback_with_buffer(&self.digest, message)
                .await
                .ok()?;
            let random = Self::async_callback_with_arg(&self.random, &8usize.into())
                .await
                .ok()?;

            let body =
                rfc3161_time_stamp_message(self.alg, &digest, random.try_into().unwrap()).ok()?;

            let result = Self::async_callback_with_buffer(&timestamp, &body).await;
            return Some(result);
        }
        None
    }
}
