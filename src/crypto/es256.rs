use std::{borrow::Cow, num::NonZeroUsize};

use p256::ecdsa::{
    signature::{DigestSigner, DigestVerifier},
    Signature, SigningKey, VerifyingKey,
};
use sha2::{Digest, Sha256};

use crate::{AlgoSignature, Algorithm, SigningKey as SKey, VerifyingKey as VKey};

impl AlgoSignature for Signature {
    const LENGTH: Option<NonZeroUsize> = NonZeroUsize::new(64);

    fn try_from_slice(slice: &[u8]) -> crate::Result<Self> {
        Ok(Signature::try_from(slice)?)
    }

    fn as_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.to_bytes().to_vec())
    }
}

/// `ES256` signing algorithm.
#[derive(Debug, Default)]
pub struct Es256;

impl Algorithm for Es256 {
    type SigningKey = SigningKey;
    type VerifyingKey = VerifyingKey;
    type Signature = Signature;

    fn name(&self) -> Cow<'static, str> {
        Cow::Borrowed("ES256")
    }

    fn curve(&self) -> Cow<'static, str> {
        Cow::Borrowed("P-256")
    }

    fn generate_signing_key(&self) -> Self::SigningKey {
        Self::SigningKey::random(&mut rand::thread_rng())
    }

    /// Signs a message with a `SigningKey` (private key) and returns a `Signature`.
    /// Using Sha256 as the digest to hash the message before signing as per the es256 spec.
    fn sign(&self, signing_key: &Self::SigningKey, message: &[u8]) -> Self::Signature {
        let mut digest = Sha256::default();
        digest.update(message);
        signing_key.sign_digest(digest)
    }

    /// Verifies a signature given a message and a `VerifyingKey`.
    /// Uses Sha256 as the digest to hash the message before verifying as per the es256 spec.
    fn verify_signature(
        &self,
        signature: &Self::Signature,
        verifying_key: &Self::VerifyingKey,
        message: &[u8],
    ) -> bool {
        let mut digest = Sha256::default();
        digest.update(message);

        verifying_key.verify_digest(digest, signature).is_ok()
    }
}

impl SKey<Es256> for SigningKey {
    fn from_slice(raw: &[u8]) -> crate::Result<Self> {
        Ok(Self::from_slice(raw)?)
    }

    /// Returns a `VerifyingKey` aka a public key from the private key.
    fn to_verifying_key(&self) -> VerifyingKey {
        *self.verifying_key()
    }

    fn as_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.to_bytes().to_vec())
    }
}

impl VKey<Es256> for VerifyingKey {
    /// Takes a slice of bytes in sec1 format and returns a `VerifyingKey`.
    ///
    /// Sec1format is a format where the first byte indicates the type of key.
    fn from_slice(raw: &[u8]) -> crate::Result<Self> {
        Ok(Self::from_sec1_bytes(raw)?)
    }

    /// Serializes the key to a compressed encoded point format.  Will include a leading byte indicating the type of key.
    ///
    /// Should maybe expose the ability to change whether or not the key is compressed.
    fn as_bytes(&self) -> Cow<'_, [u8]> {
        let bytes = self.to_encoded_point(true).as_bytes().to_vec();
        Cow::Owned(bytes)
    }
}
