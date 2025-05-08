use crate::generator::{Generator, PrivateKey, PublicKey};
use base64::{
    Engine,
    engine::general_purpose::{
        STANDARD as BASE64_STANDARD, STANDARD_NO_PAD as BASE64_STANDARD_NO_PAD,
    },
};
use regex::RegexSet;

pub struct WireGuardGenerator;

impl Generator for WireGuardGenerator {
    type PrivateKey = x25519_dalek::StaticSecret;
    type PublicKey = x25519_dalek::PublicKey;

    fn generate_matching(
        &self,
        patterns: &RegexSet,
        _match_key_material: bool,
    ) -> Option<(Self::PrivateKey, Self::PublicKey)> {
        let private = x25519_dalek::StaticSecret::random();
        let public = x25519_dalek::PublicKey::from(&private);
        let enc_public = BASE64_STANDARD_NO_PAD.encode(public.to_bytes());

        patterns.is_match(&enc_public).then_some((private, public))
    }
}

impl PrivateKey for x25519_dalek::StaticSecret {
    fn to_canonical_key_string(&self) -> String {
        BASE64_STANDARD.encode(self.to_bytes())
    }
}

impl PublicKey for x25519_dalek::PublicKey {
    fn to_canonical_key_string(&self) -> String {
        BASE64_STANDARD.encode(self.to_bytes())
    }
}
