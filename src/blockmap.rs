use base64ct::{Base64, Encoding};
use xmlserde_derives::{XmlDeserialize, XmlSerialize};

const DEFAULT_HASH_METHOD: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

pub trait Hash {
    fn hash_bytes(&self) -> Vec<u8>;
}

/// Defines the root element of the app package block map. The BlockMap element
/// specifies the algorithm that is used to compute cryptographic hashes and
/// contains a sequence of File child elements that are associated with each
/// file that is stored in the package.
#[derive(Clone, Debug, PartialEq, Eq, XmlDeserialize, XmlSerialize)]
#[xmlserde(root=b"b2:BlockMap")]
#[xmlserde(with_ns = b"http://schemas.microsoft.com/appx/2010/blockmap")]
#[xmlserde(with_custom_ns(b"b2", b"http://schemas.microsoft.com/appx/2015/blockmap"))]
pub struct AppxBlockMap {
    #[xmlserde(name = b"HashMethod", ty = "attr")]
    hash_method: String,
    /// Files in the package.
    #[xmlserde(name = b"b2:File", ty = "child")]
    pub files: Vec<File>,
}

impl Default for AppxBlockMap {
    fn default() -> Self {
        Self {
            hash_method: DEFAULT_HASH_METHOD.into(),
            files: Default::default(),
        }
    }
}

/// Represents a file contained in the package.
#[derive(Clone, Debug, PartialEq, Eq, Default, XmlDeserialize, XmlSerialize)]
pub struct File {
    /// Root path and file name.
    #[xmlserde(name = b"Name", ty = "attr")]
    pub name: String,
    #[xmlserde(name = b"Id", ty = "attr")]
    pub id: String,
    /// Size, in bytes, of the file's uncompressed data.
    #[xmlserde(name = b"Size", ty = "attr")]
    pub size: u64,
    
    #[xmlserde(name = b"Encrypted", ty = "attr")]
    pub encrypted: String,
    /// Blocks that make up the file.
    #[xmlserde(name = b"Block", ty = "child")]
    pub blocks: Vec<Block>,

    #[xmlserde(name = b"b2:FileHash", ty = "child")]
    pub filehash: Option<FileHash>,
}

impl File {
    pub fn id(&self) -> u64 {
        u64::from_str_radix(&self.id, 16).unwrap()
    }

    pub fn is_encrypted(&self) -> bool {
        self.encrypted == "true"
    }

    pub fn filehash_bytes(&self) -> Option<Vec<u8>> {
        self.filehash.as_ref()
            .and_then(|h|Some(h.hash_bytes()))
    }

    pub fn block_hashes(&self) -> Vec<Vec<u8>> {
        self.blocks.iter().map(|b|b.hash_bytes())
            .collect()
    }
}

/// Represents a 64kib block of binary data contained in a file.
#[derive(Clone, Debug, PartialEq, Eq, Default, XmlDeserialize, XmlSerialize)]
pub struct Block {
    /// The hash value of the uncompressed data block.
    #[xmlserde(name = b"Hash", ty = "attr")]
    pub hash: String,
    /// The size, in bytes, of the data block when stored in the package. If
    /// the file data is compressed, the size of each compressed block
    /// potentially varies in size.
    #[xmlserde(name = b"Size", ty = "attr")]
    pub size: Option<u16>,
}

impl Hash for Block {
    fn hash_bytes(&self) -> Vec<u8> {
        Base64::decode_vec(&self.hash).unwrap()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default, XmlDeserialize, XmlSerialize)]
pub struct FileHash {
    /// The hash value of the entire uncompressed file.
    #[xmlserde(name = b"Hash", ty = "attr")]
    pub hash: String,
}

impl Hash for FileHash {
    fn hash_bytes(&self) -> Vec<u8> {
        Base64::decode_vec(&self.hash).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmlserde::{xml_deserialize_from_str, xml_serialize};
    const XML_DATA: &str = include_str!("../testdata/blockmap.xml");
    const XML_DATA_BIG: &str = include_str!("../testdata/blockmap_big.xml");
    const XML_DATA_SIZE0: &str = include_str!("../testdata/blockmap_size_0.xml");
    const XML_ENCODING: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="no"?>"#;

    #[test]
    fn test_serialize() {
        let map = AppxBlockMap {
            files: vec![
                File {
                    name: "AppxManifest.xml".into(),
                    id: format!("{:X}", 0),
                    size: 3337,
                    encrypted: "false".into(),
                    filehash: Some(FileHash {
                        hash: "KNW6qWLAKsPZKbVF0DQc4gxxL0eAsCtFxUa+stWfKB8=".into(),
                    }),
                    blocks: vec![
                        Block {
                            hash: "KNW6qWLAKsPZKbVF0DQc4gxxL0eAsCtFxUa+stWfKB8=".into(),
                            size: Some(1236)
                        }
                    ]
                }
            ],
            ..Default::default()
        };

        let ser = xml_serialize(map);
        assert_eq!(XML_ENCODING.to_owned() + "\n" + &ser, XML_DATA);
    }

    #[test]
    fn test_deserialize() {
        let res = xml_deserialize_from_str::<AppxBlockMap>(XML_DATA)
            .expect("Failed to deserialize XML");

        assert_eq!(res.hash_method, "http://www.w3.org/2001/04/xmlenc#sha256");
        assert_eq!(res.files.len(), 1);
        assert_eq!(res.files.first().unwrap().name, "AppxManifest.xml");
        assert_eq!(res.files.first().unwrap().id, "0");
        assert_eq!(res.files.first().unwrap().id(), 0);
        assert_eq!(res.files.first().unwrap().size, 3337);
        assert_eq!(res.files.first().unwrap().encrypted, "false");
        assert!(!res.files.first().unwrap().is_encrypted());
        assert_eq!(res.files.first().unwrap().blocks.first().unwrap().hash_bytes(), hex::decode("28d5baa962c02ac3d929b545d0341ce20c712f4780b02b45c546beb2d59f281f").unwrap());
        assert_eq!(res.files.first().unwrap().filehash.as_ref().unwrap().hash_bytes(), hex::decode("28d5baa962c02ac3d929b545d0341ce20c712f4780b02b45c546beb2d59f281f").unwrap());
    }

    #[test]
    fn test_deserialize_big() {
        xml_deserialize_from_str::<AppxBlockMap>(XML_DATA_BIG).expect("Failed to deserialize XML (big)");
    }

    #[test]
    fn test_deserialize_size0() {
        xml_deserialize_from_str::<AppxBlockMap>(XML_DATA_SIZE0).expect("Failed to deserialize XML (size 0)");
    }
}