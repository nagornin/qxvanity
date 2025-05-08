use crate::generator::{Generator, PrivateKey, PublicKey};
use rand_core::OsRng;
use regex::RegexSet;
use ssh_encoding::{Base64Writer, Encode};
use ssh_key::{
    LineEnding,
    private::{Ed25519Keypair, Ed25519PrivateKey},
    public::{Ed25519PublicKey, KeyData},
};

pub struct SshEd25519Generator;

impl Generator for SshEd25519Generator {
    type PrivateKey = Ed25519PrivateKey;
    type PublicKey = Ed25519PublicKey;

    fn generate_matching(
        &self,
        patterns: &RegexSet,
        match_key_material: bool,
    ) -> Option<(Self::PrivateKey, Self::PublicKey)> {
        let mut rng = OsRng;
        let keypair = Ed25519Keypair::random(&mut rng);
        let key_data = KeyData::Ed25519(keypair.public);
        let bytes_len = key_data.encoded_len().unwrap();
        let base64_len = base64::encoded_len(bytes_len, true).unwrap();
        let mut buf = vec![0; base64_len];
        let mut writer = Base64Writer::new(&mut buf).unwrap();
        key_data.encode(&mut writer).unwrap();
        let mut enc_public = writer.finish().unwrap();

        if match_key_material {
            enc_public = &enc_public[25..];
        }

        patterns
            .is_match(enc_public)
            .then_some((keypair.private, keypair.public))
    }
}

impl PrivateKey for Ed25519PrivateKey {
    fn to_canonical_key_string(&self) -> String {
        ssh_key::private::PrivateKey::from(Ed25519Keypair::from(self.clone()))
            .to_openssh(LineEnding::default())
            .map(|x| (*x).trim().into())
            .unwrap()
    }
}

impl PublicKey for Ed25519PublicKey {
    fn to_canonical_key_string(&self) -> String {
        ssh_key::public::PublicKey::from(*self)
            .to_openssh()
            .unwrap()
    }
}
