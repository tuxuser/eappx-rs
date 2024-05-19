use std::{collections::HashMap, str::FromStr};


use binrw::{BinRead, BinWrite};
use uuid::{uuid, Uuid};
use base64ct::{Base64, Encoding};
use crate::error::Error;

const SHORT_KEY_GUID_PREFIX: Uuid = uuid!("BB1755DB-5052-4B10-B2AB-F3ABF5CA5B41");

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum KeyId {
    Numeric(u16),
    Guid((Uuid, Uuid))
}

impl BinRead for KeyId {
    type Args<'a> = ();

    fn read_options<R: std::io::prelude::Read + std::io::prelude::Seek>(
        reader: &mut R,
        endian: binrw::Endian,
        _: Self::Args<'_>,
    ) -> binrw::prelude::BinResult<Self> {
        let mut buf = [0u8; 32];
        reader.read_exact(&mut buf)?;

        let key_id = match endian {
            binrw::Endian::Big => {
                KeyId::Guid((
                    Uuid::from_bytes(buf[..16].try_into().unwrap()),
                    Uuid::from_bytes(buf[16..].try_into().unwrap()),
                ))
            },
            binrw::Endian::Little => {
                KeyId::Guid((
                    Uuid::from_bytes_le(buf[..16].try_into().unwrap()),
                    Uuid::from_bytes_le(buf[16..].try_into().unwrap()),
                ))
            },
        };

        Ok(key_id)
    }
}

impl BinWrite for KeyId {
    type Args<'a> = ();

    fn write_options<W: std::io::prelude::Write + std::io::prelude::Seek>(
        &self,
        writer: &mut W,
        endian: binrw::Endian,
        _: Self::Args<'_>,
    ) -> binrw::prelude::BinResult<()> {
        match self {
            KeyId::Numeric(_) => panic!("Cannot serialize numeric keyid into binary"),
            KeyId::Guid(keyid) => {
                match endian {
                    binrw::Endian::Big => {
                        let _ = writer.write(keyid.0.as_bytes())?;
                        let _ = writer.write(keyid.1.as_bytes())?;
                    },
                    binrw::Endian::Little => {
                        let _ = writer.write(&keyid.0.to_bytes_le())?;
                        let _ = writer.write(&keyid.1.to_bytes_le())?;
                    },
                }
            },
        }

        Ok(())
    }
}

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyId {{ {} }}",
            match self {
                KeyId::Numeric(numeric) => numeric.to_string(),
                KeyId::Guid(guid) => {
                    format!("0: {} 1: {}" ,guid.0, guid.1)
                },
            }
        )
        
    }
}

#[derive(Debug, Default)]
pub struct KeyCollection {
    pub keys: HashMap<KeyId, Vec<u8>>,
}

impl KeyCollection {
    /// Check if all keys are contained
    /// It gets passed the list of key-ids in the file-header
    pub fn has_required_keys(&self, key_ids: &[KeyId]) -> bool {
        key_ids.iter().all(|k|self.keys.contains_key(k))
    }

    /// Create a new instance of KeyCollection
    pub fn new(keys: &HashMap<KeyId, Vec<u8>>) -> Self {
        Self {
            keys: keys.to_owned()
        }
    }

    /// Add a key by key-id and keydata
    pub fn add(&mut self, keyid: KeyId, keydata: Vec<u8>) {
        self.keys.insert(keyid, keydata);
    }

    /// Extend the key collection with a mapping of key-id -> keydata
    pub fn extend(&mut self, entries: HashMap<KeyId, Vec<u8>>) {
        self.keys.extend(entries)
    }

    pub fn from_reader<T: std::io::Read>(reader: &mut T) -> Result<Self, Error> {
        let mut buf = String::new();
        reader.read_to_string(&mut buf)?;
        Self::from_str(&buf)
    }
}


impl FromStr for KeyCollection {
    type Err = Error;

    /// Deserialize a string
    /// 
    /// ```
    /// # use eappx::keys::KeyCollection;
    /// # use std::str::FromStr;
    /// let keystr = r#"
    /// [Keys]
    /// "8iBHoOceuO0lsmiRNJyAAvmOPCpau0nvEYeJfg6H4hU=" "BAheoEHgSsMqshmRvAQMO5/dff91n42OYG4Va0bqgL4="
    /// "#;
    /// 
    /// assert!(KeyCollection::from_str(keystr).is_ok());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut keys = HashMap::new();
        let data = s.trim();

        if !data.starts_with("[Keys]") {
            panic!("Invalid keyfile magic, expected [Keys]");
        }

        for line in data.split('\n') {
            let line = line.trim();
            if line.is_empty() {
                continue;
            } else if line.starts_with('\"') {
                let mut parts = line.split_whitespace();
                let key_id_str = parts.next().unwrap().replace('\"', "");
                let key_str = parts.next().unwrap().replace('\"', "");

                let key = Base64::decode_vec(&key_str)
                    .map_err(|e| Error::DecodeError(e.to_string()))?;

                if let Ok(bytes_keyid) = Base64::decode_vec(&key_id_str) {
                    let keyid = match bytes_keyid.len() {
                        16 => {
                            // 16 bytes KeyID - prefix it with a static value
                            KeyId::Guid((
                                SHORT_KEY_GUID_PREFIX,
                                Uuid::from_bytes_le(bytes_keyid.try_into().unwrap())
                            ))
                        },
                        32 => {
                            KeyId::Guid((
                                Uuid::from_bytes_le(bytes_keyid[..16].try_into().unwrap()),
                                Uuid::from_bytes_le(bytes_keyid[16..32].try_into().unwrap())
                            )) 
                        },
                        _len => {
                            return Err(Error::DecodeError("Unsupported KeyId Guid length".into()))
                        }
                    };
                    keys.insert(keyid, key);
                } else if let Ok(numeric_keyid) = key_id_str.parse::<u16>() {
                    let keyid = KeyId::Numeric(numeric_keyid);
                    keys.insert(keyid, key);
                }
            }
        }

        Ok(Self { keys })
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use uuid::uuid;

    const KEY_FILE: &str = include_str!("../testdata/keys.txt");
    const KEY_ID_0: Uuid = uuid!("a04720f2-1ee7-edb8-25b2-6891349c8002");
    const KEY_ID_1: Uuid = uuid!("2a3c8ef9-bb5a-ef49-1187-897e0e87e215");
    const KEY_DATA: &str = "04085ea041e04ac32ab21991bc040c3b9fdd7dff759f8d8e606e156b46ea80be";

    #[test]
    fn test_from_str() {
        let keys = KeyCollection::from_str(KEY_FILE).unwrap();
        assert_eq!(keys.keys.len(), 1);
        assert_eq!(keys.keys.keys().next().unwrap(), &KeyId::Guid((KEY_ID_0, KEY_ID_1)));
        assert_eq!(keys.keys.values().next().unwrap(), &hex::decode(KEY_DATA).unwrap())
    }

    #[test]
    fn test_from_reader() {
        let mut cursor = std::io::Cursor::new(KEY_FILE.as_bytes());
        let keys = KeyCollection::from_reader(&mut cursor).unwrap();
        assert_eq!(keys.keys.len(), 1);
        assert_eq!(keys.keys.keys().next().unwrap(), &KeyId::Guid((KEY_ID_0, KEY_ID_1)));
        assert_eq!(keys.keys.values().next().unwrap(), &hex::decode(KEY_DATA).unwrap())
    }
}