use crate::generator::{Generator, PrivateKey, PublicKey};
use rand_core::OsRng;
use regex::RegexSet;
use ssh_key::{
    LineEnding,
    private::{Ed25519Keypair, Ed25519PrivateKey},
    public::Ed25519PublicKey,
};

pub struct SshEd25519Generator;

impl Generator for SshEd25519Generator {
    type PrivateKey = Ed25519PrivateKey;
    type PublicKey = Ed25519PublicKey;

    fn generate_matching(
        &self,
        patterns: &RegexSet,
    ) -> Option<(Self::PrivateKey, Self::PublicKey)> {
        let mut rng = OsRng;
        let keypair = Ed25519Keypair::random(&mut rng);

        let Ok(enc_public) =
            ssh_key::public::PublicKey::from(keypair.public).to_openssh()
        else {
            unreachable!("failed to encode public key");
        };

        let enc_public = &enc_public[enc_public.len() - 43..];

        patterns
            .is_match(enc_public)
            .then_some((keypair.private, keypair.public))
    }
}

impl PrivateKey for Ed25519PrivateKey {
    fn to_canonical_key_string(&self) -> String {
        if let Ok(enc) = ssh_key::private::PrivateKey::from(
            Ed25519Keypair::from(self.clone()),
        )
        .to_openssh(LineEnding::default())
        {
            (*enc).trim().to_owned()
        } else {
            unreachable!("failed to encode private key");
        }
    }
}

impl PublicKey for Ed25519PublicKey {
    fn to_canonical_key_string(&self) -> String {
        if let Ok(enc) = ssh_key::public::PublicKey::from(*self).to_openssh() {
            enc
        } else {
            unreachable!("failed to encode public key");
        }
    }
}
