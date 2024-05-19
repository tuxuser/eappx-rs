use crate::manifest::{Identity, Packages, Package};
use xmlserde_derives::{XmlDeserialize, XmlSerialize};

fn default_ignorable_namespaces_bundle() -> String {
    "b4 b5".into()
}

#[derive(Clone, Debug, Default, XmlDeserialize, XmlSerialize)]
#[xmlserde(root=b"Bundle")]
#[xmlserde(with_ns = b"http://schemas.microsoft.com/appx/2013/bundle")]
#[xmlserde(with_custom_ns(b"b4", b"http://schemas.microsoft.com/appx/2018/bundle"))]
#[xmlserde(with_custom_ns(b"b5", b"http://schemas.microsoft.com/appx/2019/bundle"))]
pub struct AppxBundleManifest {
    #[xmlserde(name = b"IgnorableNamespaces", ty = "attr", default = "default_ignorable_namespaces_bundle")]
    pub ignorable_namespaces: String,

    #[xmlserde(name = b"SchemaVersion", ty = "attr")]
    pub schema_version: String,

    #[xmlserde(name = b"Identity", ty = "child")]
    pub identity: Identity,

    #[xmlserde(name = b"Packages", ty = "child")]
    pub packages: Packages,

    #[xmlserde(name = b"OptionalBundle", ty = "child")]
    pub optional_bundle: Option<OptionalBundle>,
}

/// Defines optional bundles relative to the main bundle.
/// Optional bundles contain additional packages that apply to the main app package or bundle.
/// 
/// Reference: <https://learn.microsoft.com/en-us/uwp/schemas/bundlemanifestschema/element-optionalbundle>
#[derive(Clone, Debug, Default, XmlDeserialize, XmlSerialize)]
pub struct OptionalBundle {
    /// Name
    #[xmlserde(name = b"Name", ty = "attr")]
    pub name: String,
    /// Publisher
    #[xmlserde(name = b"Publisher", ty = "attr")]
    pub publisher: String,
    /// Version
    #[xmlserde(name = b"Version", ty = "attr")]
    pub version: Option<String>,
    /// File name
    #[xmlserde(name = b"FileName", ty = "attr")]
    pub filename: Option<String>,
    /// Packages
    #[xmlserde(name = b"Package", ty = "child")]
    pub packages: Vec<Package>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmlserde::xml_deserialize_from_str;
    const XML_DATA_BUNDLE: &str = include_str!("../testdata/manifest_bundle.xml");
    const XML_ENCODING: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>"#;

    #[test]
    fn test_serialize_bundle() {

    }

    #[test]
    fn test_deserialize_bundle() {
        let manifest = xml_deserialize_from_str::<AppxBundleManifest>(XML_DATA_BUNDLE).expect("Failed to deserialize XML");
        assert_eq!(manifest.ignorable_namespaces, "b4 b5");
        assert_eq!(manifest.identity.name, "SomeGame");
        assert_eq!(manifest.identity.publisher, "CN=A68B71A2-D31D-464B-859A-CCB951AA6E69");
        assert_eq!(manifest.identity.version, "1.5.54.2");
        assert_eq!(manifest.identity.arch, None);
        assert_eq!(manifest.packages.package.len(), 1);
        assert_eq!(manifest.packages.package.first().unwrap().typ, "resource");
        assert_eq!(manifest.packages.package.first().unwrap().version, "1.5.54.2");
        assert_eq!(manifest.packages.package.first().unwrap().resource_id, Some("split.scale-100".into()));
        assert_eq!(manifest.packages.package.first().unwrap().filename, "SomeGame_1.5.54.2_scale-100.msix");
        assert_eq!(manifest.packages.package.first().unwrap().offset, 392);
        assert_eq!(manifest.packages.package.first().unwrap().size, 576406);
    }
}