use regex::RegexSet;

pub trait Generator {
    type PrivateKey: PrivateKey;
    type PublicKey: PublicKey;

    fn generate_matching(
        &self,
        patterns: &RegexSet,
    ) -> Option<(Self::PrivateKey, Self::PublicKey)>;
}

pub trait PrivateKey {
    fn to_canonical_key_string(&self) -> String;
}

pub trait PublicKey {
    fn to_canonical_key_string(&self) -> String;
}
