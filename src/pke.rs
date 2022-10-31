pub trait Pke {
    type PublicKey;
    type SecretKey;
    type Ciphertext;
    type Plaintext;

    fn keygen(&self) -> (Self::PublicKey, Self::SecretKey);
    fn encrypt(&self, pk: &Self::PublicKey, m: &Self::Plaintext) -> Self::Ciphertext;
    fn decrypt(&self, sk: &Self::SecretKey, c: &Self::Ciphertext) -> Self::Plaintext;
}
