use sha1::Digest as _;

pub fn hash_to_u128(data: impl AsRef<[u8]>, prefix: Option<&[u8]>) -> u128 {
    let mut hasher = sha1::Sha1::new();

    prefix.into_iter().for_each(|prefix| hasher.update(prefix));
    hasher.update(data);

    let hash = hasher.finalize();
    u128::from_be_bytes(hash[..16].try_into().unwrap())
}
