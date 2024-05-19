use sha2::{Sha256, Digest};

pub const SECTOR_SIZE: usize = 0x200;
pub const BLOCK_SIZE: usize = 0x10000;


pub fn get_filesize_with_unit(bytes: u64) -> String {
    let kb = bytes / 1024;
    let mb = kb / 1024;
    let gb = mb / 1024;

    if gb > 0 {
        format!("{} GB", gb)
    } else if mb > 0 {
        format!("{} MB", mb)
    } else if kb > 0 {
        format!("{} KB", kb)
    } else {
        format!("{} B", bytes)
    }
}

/// Align size to sector boundary
/// 
/// Examples
/// ```
/// use eappx::utils::{self};
/// 
/// assert_eq!(utils::align_to_sector(0x200), 0x200);
/// assert_eq!(utils::align_to_sector(0x221), 0x400);
/// assert_eq!(utils::align_to_sector(0x3FF), 0x400);
/// assert_eq!(utils::align_to_sector(0x201), 0x400);
/// assert_eq!(utils::align_to_sector(0x1FFFFF), 0x200000);
/// ```
pub fn align_to_sector(total_size: usize) -> usize {
    (((total_size - 1) / SECTOR_SIZE) + 1) * SECTOR_SIZE
}

/// Convert a string slice to UTF-16 bytes (without BOM)
/// 
/// Examples
/// ```
/// # use eappx::utils::str_to_utf16_bytes;
/// let utf16_bytes = str_to_utf16_bytes("Hello");
/// assert_eq!(
///    utf16_bytes,
///    ['H' as u8, 0x00, 'e' as u8, 0x00, 'l' as u8, 0x00, 'l' as u8, 0x00, 'o' as u8, 0x00]
/// );
/// ```
pub fn str_to_utf16_bytes(string: &str) -> Vec<u8> {
    string
        .encode_utf16()
        .flat_map(|x| x.to_le_bytes())
        .collect::<Vec<u8>>()
}

/// Generate publisher Id from publisher-string
/// 
/// Examples
/// ```
/// # use eappx::utils::generate_publisher_id;
/// const publisher: &'static str = "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US";
/// assert_eq!(generate_publisher_id(publisher), "8wekyb3d8bbwe");
/// ```
pub fn generate_publisher_id(publisher: &str) -> String {
    // Step 1: Convert the publisher name to Unicode bytes
    let publisher_as_unicode = str_to_utf16_bytes(publisher);
    
    // Step 2: Compute the SHA256 hash of the Unicode bytes
    let mut hasher = Sha256::new();
    hasher.update(&publisher_as_unicode);
    let publisher_sha256 = hasher.finalize();
    
    // Step 3: Take the first 8 bytes of the hash
    let publisher_sha256_first_8_bytes = &publisher_sha256[0..8];
    
    // Step 4: Convert these bytes to a binary string
    let publisher_sha256_as_binary = publisher_sha256_first_8_bytes.iter().map(|b| format!("{:08b}", b)).collect::<Vec<String>>().join("");
    
    // Step 5: Pad the binary string to ensure it's 65 characters long
    let as_binary_string_with_padding = format!("{:0<65}", publisher_sha256_as_binary);
    
    // Step 6: Encode the binary string into a base32 string using a custom encoding table
    let encoding_table = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut result = String::new();
    for i in (0..as_binary_string_with_padding.len()).step_by(5) {
        let as_index = u32::from_str_radix(&as_binary_string_with_padding[i..i+5], 2).unwrap();
        result.push(encoding_table.chars().nth(as_index as usize).unwrap());
    }
    
    // Step 7: Return the result in lowercase
    result.to_lowercase()
}

/// Generate package family name
/// 
/// Examples
/// ```
/// # use eappx::utils::generate_pfn;
/// let pfn = generate_pfn("MyCoolCalculator", "CN=SomeDev");
/// assert_eq!(pfn, "MyCoolCalculator_kp0adwb0dpv7r");
/// ```
pub fn generate_pfn(app_name: &str, publisher: &str) -> String {
    format!("{app_name}_{}", generate_publisher_id(publisher))
}

#[cfg(test)]
mod tests {
    
}