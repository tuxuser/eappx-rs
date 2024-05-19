use std::{any::Any, io::Read};

use aes::{Aes128, cipher::KeyInit, cipher::generic_array::GenericArray};
use sha2::{Sha256, Digest};
use xts_mode::Xts128;

use crate::utils::{self};

pub struct AesXtsReader<T: Read> {
    inner: T,
    ctx: CryptoFileContext,
    sector: u128,
}

impl<T: Read> AesXtsReader<T>
{
    pub fn new(inner: T, ctx: CryptoFileContext) -> Self {
        Self {
            inner,
            ctx,
            sector: 0
        }
    }
}

impl<T: Read> Read for AesXtsReader<T>
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let aligned_size = utils::align_to_sector(buf.len());
        let mut tmp = vec![0u8; aligned_size];

        self.inner.read_exact(&mut tmp)?;
        self.ctx.cipher.0.decrypt_area(&mut tmp, utils::SECTOR_SIZE, self.sector, |sector| self.ctx.for_sector(sector));

        buf.copy_from_slice(&tmp[..buf.len()]);
        self.sector += (aligned_size / utils::SECTOR_SIZE) as u128;

        Ok(buf.len())
    }
}

pub struct CryptoFileContext {
    pub cipher: AesXtsCipher,
    pub tweak: u128
}

impl CryptoFileContext {
    pub fn for_sector(&self, sector: u128) -> [u8; 16] {
        let val = (self.tweak + sector).to_le_bytes();
        log::trace!("Tweak for sector {sector}: {}", hex::encode(val));
        val
    }
}

pub struct AesXtsCipher(pub Xts128::<Aes128>);

impl std::fmt::Debug for AesXtsCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Xts128").field("type_id", &self.0.type_id()).finish()
    }
}

pub fn get_tweak_for_file(app_name: &str, publisher_id: &str, filename: &str) -> u128 {
    let pfn = format!("{}_{}", app_name, publisher_id);
    get_tweak_value(filename, &pfn)
}

pub fn create_cipher(key: &[u8; 32]) -> AesXtsCipher {
    AesXtsCipher(Xts128::<Aes128>::new(
        Aes128::new(GenericArray::from_slice(&key[..16])),
        Aes128::new(GenericArray::from_slice(&key[16..]))
    ))
}

pub fn fold_hash_xor(hash: &[u8]) -> Vec<u8> {
    // Step 1: Take the first 8 bytes of the SHA256 hash
    let mut folded_hash = hash[0..8].to_vec();

    // Step 2: Iterate over the rest of the hash in 8-byte chunks
    for i in (8..hash.len()).step_by(8) {
        // Step 3: Perform an XOR operation with the current folded_hash and update folded_hash with the result
        folded_hash = folded_hash
            .iter()
            .zip(hash[i..i+8].iter())
            .map(|(&x, &y)| x ^ y)
            .collect();
    }

    // Step 4: Return the final folded_hash
    folded_hash
}

pub fn hash_for_file_tweak(filepath: &str, pfn: &str) -> Vec<u8> {
    let prefixed_path = match filepath.starts_with('\\') {
        true => {
            filepath.to_string()
        },
        false => {
            "\\".to_string() + filepath
        },
    };
    let lowercase_pfn = pfn.to_lowercase();

    log::trace!("Hashing Filepath: {prefixed_path} PFN: {lowercase_pfn} for file tweak");
    // Convert filepath to UTF-16 as-is
    let filepath_utf16 = utils::str_to_utf16_bytes(&prefixed_path);
    // Convert all-lowercase PFN to UTF-16
    let pfn_lower_utf16 = utils::str_to_utf16_bytes(&lowercase_pfn);

    // Create hash over filepath + (lowercase) PFN
    let mut hasher = Sha256::new();
    hasher.update(&filepath_utf16);
    hasher.update(&pfn_lower_utf16);
    hasher.finalize().to_vec()
}

pub fn get_tweak_value(filepath: &str, pfn: &str) -> u128 {
    
    let tweak_hash = hash_for_file_tweak(filepath, pfn);
    log::trace!("Hash for file tweak: {}", hex::encode(&tweak_hash));
    let folded = fold_hash_xor(&tweak_hash);
    log::trace!("Folded tweak hash: {}", hex::encode(&folded));

    u64::from_le_bytes(folded[..8].try_into().unwrap()) as u128
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xts128_cipher() -> AesXtsCipher {
        AesXtsCipher(Xts128::new(
            Aes128::new(GenericArray::from_slice(&[0u8; 16])),
            Aes128::new(GenericArray::from_slice(&[0u8; 16]))
        ))
    }

    #[test]
    fn test_tweak() {
        let tweak = CryptoFileContext {
            cipher: xts128_cipher(),
            tweak: 0x2A7D4F58F4A696A3
        };
        assert_eq!(hex::encode(tweak.for_sector(0)), "a396a6f4584f7d2a0000000000000000".to_lowercase())
    }

    #[test]
    fn test_get_tweak_value() {
        let pfn = utils::generate_pfn("TestApp", "CN=SomeCommonName");
        let base_tweak = get_tweak_value(r#"\Assets\LockScreenLogo.scale-200.png"#, &pfn);

        assert_eq!(base_tweak, 0xB5D77C157B3F1860);
    }

    #[test]
    fn test_tweak_hash() {
        let expected = "98254280ac79f4b4799b1cd78bffb41ffeaa59f1ee70268b7f0c38dddc8ab195";
        let hash = hash_for_file_tweak(r#"\Assets\LockScreenLogo.scale-200.png"#, "testapp_bst25f6z33ccc");
        assert_eq!(hex::encode(hash), expected);
    }

    #[test]
    fn test_tweak_hash_non_prefixed_filepath() {
        let expected = "98254280ac79f4b4799b1cd78bffb41ffeaa59f1ee70268b7f0c38dddc8ab195";
        let hash = hash_for_file_tweak(r#"Assets\LockScreenLogo.scale-200.png"#, "testapp_bst25f6z33ccc");
        assert_eq!(hex::encode(hash), expected);
    }

    #[test]
    fn test_fold_sha256_xor() {
        let hash = hex::decode("446dc620c5e5a6bb3566b6314f129ae8dcb7b752f39e14640e2a61b72126551d").unwrap();
        assert_eq!(hex::encode(fold_hash_xor(&hash)), "a396a6f4584f7d2a");
    }
}