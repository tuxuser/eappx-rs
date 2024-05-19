use xmlserde_derives::{XmlDeserialize, XmlSerialize};

fn default_ignorable_namespaces() -> String {
    "uap mp rescap build".into()
}

#[derive(Clone, Debug, Default, XmlDeserialize, XmlSerialize)]
#[xmlserde(root=b"Package")]
#[xmlserde(with_ns = b"http://schemas.microsoft.com/appx/manifest/foundation/windows10")]
#[xmlserde(with_custom_ns(b"mp", b"http://schemas.microsoft.com/appx/2014/phone/manifest"))]
#[xmlserde(with_custom_ns(b"uap", b"http://schemas.microsoft.com/appx/manifest/uap/windows10"))]
#[xmlserde(with_custom_ns(b"rescap", b"http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"))]
#[xmlserde(with_custom_ns(b"desktop", b"http://schemas.microsoft.com/appx/manifest/desktop/windows10"))]
#[xmlserde(with_custom_ns(b"build", b"http://schemas.microsoft.com/developer/appx/2015/build"))]
pub struct AppxManifest {
    #[xmlserde(name = b"IgnorableNamespaces", ty = "attr", default = "default_ignorable_namespaces")]
    ignorable_namespaces: String,

    #[xmlserde(name = b"Identity", ty = "child")]
    pub identity: Identity,
}

#[derive(Clone, Debug, Default, XmlDeserialize, XmlSerialize)]
pub struct Packages {
    #[xmlserde(name = b"Package", ty = "child")]
    pub package: Vec<Package>,
}

#[derive(Clone, Debug, Default, XmlDeserialize, XmlSerialize)]
pub struct Package {
    #[xmlserde(name = b"Type", ty = "attr")]
    pub typ: String,
    #[xmlserde(name = b"Version", ty = "attr")]
    pub version: String,
    #[xmlserde(name = b"ResourceId", ty = "attr")]
    pub resource_id: Option<String>,
    #[xmlserde(name = b"Architecture", ty = "attr")]
    pub arch: Option<String>,
    #[xmlserde(name = b"FileName", ty = "attr")]
    pub filename: String,
    #[xmlserde(name = b"Offset", ty = "attr")]
    pub offset: u64, 
    #[xmlserde(name = b"Size", ty = "attr")]
    pub size: u64,
}

#[derive(Clone, Debug, Default, XmlDeserialize, XmlSerialize)]
pub struct Identity {
    /// Name
    #[xmlserde(name = b"Name", ty = "attr")]
    pub name: String,
    /// Publisher
    #[xmlserde(name = b"Publisher", ty = "attr")]
    pub publisher: String,
    /// Version
    #[xmlserde(name = b"Version", ty = "attr")]
    pub version: String,
    /// Processor architecture
    #[xmlserde(name = b"ProcessorArchitecture", ty = "attr")]
    pub arch: Option<String>,
}



#[cfg(test)]
mod tests {
    use super::*;
    use xmlserde::{xml_deserialize_from_str, xml_serialize};
    const XML_DATA: &str = include_str!("../testdata/manifest.xml");
    const XML_ENCODING: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>"#;

    #[test]
    #[ignore]
    fn test_serialize() {
        let map = AppxManifest {
            identity: Identity {
                name: "TestApp".into(),
                publisher: "CN=SomeCommonName".into(),
                version: "1.0.24.0".into(),
                arch: Some("x64".into()),
            },
            ..Default::default()
        };

        let ser = xml_serialize(map);
        assert_eq!(XML_ENCODING.to_owned() + "\n" + &ser, XML_DATA);
    }

    #[test]
    fn test_deserialize() {
        let manifest = xml_deserialize_from_str::<AppxManifest>(XML_DATA).expect("Failed to deserialize XML");
        assert_eq!(manifest.ignorable_namespaces, "uap mp rescap build");
        assert_eq!(manifest.identity.name, "TestApp");
        assert_eq!(manifest.identity.publisher, "CN=SomeCommonName");
        assert_eq!(manifest.identity.version, "1.0.24.0");
        assert_eq!(manifest.identity.arch, Some("x64".into()));
    }
}