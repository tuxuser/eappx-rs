use std::{collections::HashMap, io::{Cursor, Read}, path::Path};
use std::convert::From;
use binrw::{binrw, BinRead};
use blockmap::AppxBlockMap;
use crypto::{create_cipher, get_tweak_for_file, AesXtsReader, CryptoFileContext};
use keys::{KeyCollection, KeyId};
use manifest::AppxManifest;
use sha2::{Digest, Sha256};
use xmlserde::xml_deserialize_from_reader;

use crate::{error::Error, bundle_manifest::AppxBundleManifest};

pub mod blockmap;
pub mod bundle_manifest;
pub mod crypto;
pub mod error;
pub mod keys;
pub mod manifest;
pub mod utils;


#[binrw]
#[derive(Debug, PartialEq, Eq)]
pub enum EAppxMagic {
    /// Single
    #[brw(magic(0x48505845u32))]
    EXPH,
    /// ?
    #[brw(magic(0x48535845u32))]
    EXSH,
    /// Bundle
    #[brw(magic(0x48425845u32))]
    EXBH,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct FileInfo {
    pub key_id_index: u16,
    pub compression_type: u16,
    pub offset_to_file: u64,
    pub uncompressed_length: u64,
    pub compressed_length: u64,
    pub filehash: Option<Vec<u8>>,
    pub block_hashes: Option<Vec<Vec<u8>>>,
}

impl From<&EAppxFooter> for FileInfo {
    fn from(value: &EAppxFooter) -> Self {
        FileInfo {
            key_id_index: value.key_id_index,
            compression_type: value.compression_type,
            offset_to_file: value.offset_to_file,
            uncompressed_length: value.uncompressed_length,
            compressed_length: value.compressed_length,
            filehash: None,
            block_hashes: None
        }
    }
}

#[binrw]
#[brw(little)]
#[derive(Debug, PartialEq, Eq)]
pub struct EAppxHeader {
    pub magic: EAppxMagic,
    pub header_size: u16,
    pub version: u64,
    pub footer_offset: u64,
    pub footer_length: u64,
    pub file_count: u64,
    pub signature_offset: u64,
    pub signature_compression_type: u16,
    pub signature_uncompressed_length: u32,
    pub signature_length: u32,
    pub code_integrity_offset: u64,
    pub code_integrity_compression_type: u16,
    pub code_integrity_uncompressed_length: u32,
    pub code_integrity_length: u32,
    pub block_map_file_id: u64,
    pub key_length: u32,
    #[bw(try_calc(u16::try_from(key_ids.len())))]
    pub(crate) key_id_count: u16,
    #[br(count = key_id_count)]
    pub key_ids: Vec<KeyId>,
    #[bw(try_calc(u16::try_from(package_full_name.len())))]
    pub(crate) _package_full_name_str_len: u16,
    #[bw(try_calc(u16::try_from(package_full_name.len() * 2)))]
    pub(crate) package_full_name_byte_len: u16,
    #[br(count = package_full_name_byte_len / 2)]
    pub(crate) package_full_name: Vec<u16>,
    #[bw(try_calc(u16::try_from(crypto_algo.len() * 2)))]
    pub(crate) crypto_algo_length: u16,
    #[br(count = crypto_algo_length / 2)]
    pub(crate) crypto_algo: Vec<u16>,
    pub diffusion_support_enabled: u16,
    pub(crate) block_map_hash_algo_length: u16,
    #[br(count = block_map_hash_algo_length / 2)]
    pub(crate) block_map_hash_algo: Vec<u16>,
    #[bw(try_calc(u16::try_from(block_map_hash.len())))]
    pub(crate) block_map_hash_length: u16,
    #[br(count = block_map_hash_length)]
    pub block_map_hash: Vec<u8>,
}

impl EAppxHeader {
    pub fn is_bundle(&self) -> bool {
        self.magic == EAppxMagic::EXBH
    }

    pub fn package_full_name(&self) -> String {
        String::from_utf16(&self.package_full_name).unwrap()
    }

    pub fn crypto_algo(&self) -> String {
        String::from_utf16(&self.crypto_algo).unwrap()
    }

    pub fn block_map_hash_algo(&self) -> String {
        String::from_utf16(&self.block_map_hash_algo).unwrap()
    }

    pub fn has_footer(&self) -> bool {
        self.footer_offset > 0 && self.footer_length > 0
    }

    pub fn is_code_integrity_protected(&self) -> bool {
        self.code_integrity_offset > 0 && self.code_integrity_length > 0
    }

    pub fn is_signed(&self) -> bool {
        self.signature_offset > 0 && self.signature_length > 0
    }

    pub fn appx_signature_fileinfo(&self) -> Option<FileInfo> {
        if !self.is_signed() {
            return None;
        }

        Some(FileInfo {
            key_id_index: 0xFFFF,
            compression_type: self.signature_compression_type,
            offset_to_file: self.signature_offset,
            uncompressed_length: self.signature_uncompressed_length as u64,
            compressed_length: self.signature_length as u64,
            filehash: None,
            block_hashes: None,
        })
    }

    pub fn code_integrity_fileinfo(&self) -> Option<FileInfo> {
        if !self.is_code_integrity_protected() {
            return None;
        }

        Some(FileInfo {
            key_id_index: 0xFFFF,
            compression_type: self.code_integrity_compression_type,
            offset_to_file: self.code_integrity_offset,
            uncompressed_length: self.code_integrity_uncompressed_length as u64,
            compressed_length: self.code_integrity_length as u64,
            filehash: None,
            block_hashes: None,
        })
    }

    pub fn footer_count(&self) -> usize {
        self.footer_length as usize / std::mem::size_of::<EAppxFooter>()
    }

    pub fn app_name(&self) -> String {
        self.package_full_name()
            .split("_")
            .next()
            .unwrap()
            .to_owned()
    }

    pub fn publisher_id(&self) -> String {
        self.package_full_name()
            .split("_")
            .last()
            .unwrap()
            .to_owned()
    }
}

impl std::fmt::Display for EAppxHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "EAppxHeader {{ ")?;
        writeln!(f, "  Magic: {:?}", self.magic)?;
        writeln!(f, "  HeaderSize: {:#02x}", self.header_size)?;
        writeln!(f, "  Version: {:#08x}", self.version)?;
        writeln!(f, "  FooterOffset: {:#08x}", self.footer_offset)?;
        writeln!(f, "  FooterLength: {:#08x}", self.footer_length)?;
        writeln!(f, "  FileCount: {:#08x}", self.file_count)?;
        writeln!(f, "  SignatureOffset: {:#08x}", self.signature_offset)?;
        writeln!(f, "  SignatureCompressionType: {:#02x}", self.signature_compression_type)?;
        writeln!(f, "  SignatureUncompressedLength: {:#04x}", self.signature_uncompressed_length)?;
        writeln!(f, "  SignatureLength: {:#04x}", self.signature_length)?;
        writeln!(f, "  CodeIntegrityOffset: {:#08x}", self.code_integrity_offset)?;
        writeln!(f, "  CodeIntegrityCompressionType: {:#02x}", self.code_integrity_compression_type)?;
        writeln!(f, "  CodeIntegrityUncompressedLength: {:#04x}", self.code_integrity_uncompressed_length)?;
        writeln!(f, "  CodeIntegrityLength: {:#04x}", self.code_integrity_length)?;
        writeln!(f, "  BlockMapFileId: {:#08x}", self.block_map_file_id)?;
        writeln!(f, "  KeyLength: {:#04x}", self.key_length)?;
        writeln!(f, "  KeyIds: {}", self.key_ids.len())?;
        for key in &self.key_ids {
            writeln!(f, "  - {}", key)?;
        }
        writeln!(f, "  PackageFullName: {} (name={}, publisherId={})", self.package_full_name(), self.app_name(), self.publisher_id())?;
        writeln!(f, "  CryptoAlgo: {}", self.crypto_algo())?;
        writeln!(f, "  DiffusionSupportEnabled: {:#02x}", self.diffusion_support_enabled)?;
        writeln!(f, "  BlockMapHashAlgoLength: {:#02x}", self.block_map_hash_algo_length)?;
        writeln!(f, "  BlockMapHashAlgo: {}", self.block_map_hash_algo())?;
        writeln!(f, "  BlockMapHash: {}", hex::encode(&self.block_map_hash))?;
        writeln!(f, "}}")?;

        Ok(())
    }
}

#[binrw]
#[brw(little)]
#[derive(Debug, PartialEq, Eq)]
pub struct EAppxFooter {
    pub magic: u16, // Assuming "EF" is represented as 0x4546
    pub footer_size: u16,
    pub key_id_index: u16,
    pub compression_type: u16,
    pub file_id: u64,
    pub offset_to_file: u64,
    pub uncompressed_length: u64,
    pub compressed_length: u64,
}

impl std::fmt::Display for EAppxFooter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EAppxFooter {{ ")?;
        write!(f, "Magic: {:?}, ", self.magic)?;
        write!(f, "FooterSize: {:#02x}, ", self.footer_size)?;
        write!(f, "KeyIDIndex: {:#06x}, ", self.key_id_index)?;
        write!(f, "CompressionType: {:#02x}, ", self.compression_type)?;
        write!(f, "FileId: {:#08x}, ", self.file_id)?;
        write!(f, "OffsetToFile: {:#08x}, ", self.offset_to_file)?;
        write!(f, "UncompressedLength: {:#08x}, ", self.uncompressed_length)?;
        write!(f, "CompressedLength: {:#08x}", self.compressed_length)?;
        write!(f, " }}")?;

        Ok(())
    }
}

#[derive(Debug)]
pub enum Manifest {
    Manifest(AppxManifest),
    BundleManifest(AppxBundleManifest),
}

impl Manifest {
    pub fn get_name(&self) -> String {
        match self {
            Manifest::Manifest(m) => m.identity.name.clone(),
            Manifest::BundleManifest(m) => m.identity.name.clone(),
        }
    }

    pub fn get_publisher(&self) -> String{
        match self {
            Manifest::Manifest(m) => m.identity.publisher.clone(),
            Manifest::BundleManifest(m) => m.identity.publisher.clone(),
        }
    }
}

#[derive(Debug)]
pub struct EAppxFile {
    pub header: EAppxHeader,
    pub file_len: u64,
    pub footers: Vec<EAppxFooter>,
    pub blockmap: AppxBlockMap,
    pub keys: HashMap<KeyId, Vec<u8>>,
    pub do_checksum_check: bool,
}

impl EAppxFile {
    fn create_reader<'a, R: std::io::Read + 'a>(
        stream: &'a mut R,
        encrypted: bool,
        compressed: bool,
        crypto: Option<CryptoFileContext>,
    ) -> Result<Box<dyn std::io::Read + 'a>, Error> {
        let mut reader: Box<dyn Read +  'a> = Box::new(stream);

        if compressed {
            reader = Box::new(flate2::read::DeflateDecoder::new(reader));
        }

        if encrypted {
            if let Some(crypto) = crypto {
                reader = Box::new(AesXtsReader::new(reader, crypto));
            } else {
                panic!("File is encrypted but no CryptoContext was passed. Were the apprioriate keys loaded?");
            }
        }

        Ok(reader)
    }

    pub fn read_file<R: std::io::Read + std::io::Seek, W: std::io::Write, I: Into<FileInfo>>(
        stream: &mut R,
        writer: &mut W,
        fileinfo: I,
        from_bundle: bool,
        crypto: Option<CryptoFileContext>,
        do_checksum_checks: bool,
    ) -> Result<(), Error> {
        let fileinfo: FileInfo = fileinfo.into();
        // Files itself in bundles are not encrypted
        let is_encrypted = fileinfo.key_id_index != 0xFFFF && !from_bundle;
        let is_compressed = fileinfo.compression_type == 0x1;

        stream.seek(std::io::SeekFrom::Start(fileinfo.offset_to_file))?;

        let mut reader = Self::create_reader(
            stream,
            is_encrypted,
            is_compressed,
            crypto
        )?;

        let mut pos = 0;
        let mut block = 0;
        let chunk_size = utils::BLOCK_SIZE;
        let mut buf = vec![0u8; chunk_size];
        let mut hasher = Sha256::new();

        loop {
            let read_amount = std::cmp::min(chunk_size, (fileinfo.uncompressed_length as usize) - pos);
            reader.read_exact(&mut buf[..read_amount])?;

            if !is_encrypted && do_checksum_checks {
                // Hashblocks are calculated over the uncompressed, encrypted data
                if let Some(block_hash) = fileinfo.block_hashes.as_ref().and_then(|sq| sq.get(block)) {
                    println!("Verifying block hash, block size: {:#X} (total: {:#X}", read_amount, fileinfo.uncompressed_length);
                    assert_eq!(hex::encode(Sha256::digest(&buf[..read_amount])), hex::encode(block_hash), "Invalid block hash");
                }
            }

            let _ = writer.write(&buf[..read_amount])?;
            if do_checksum_checks {
                hasher.update(&buf[..read_amount]);
            }

            pos += read_amount;

            if pos >= (fileinfo.uncompressed_length) as usize {
                break;
            }

            block += 1;
        }

        if fileinfo.uncompressed_length != pos as u64 {
            return Err(Error::DataError("Invalid filesize".into()));
        }

        if do_checksum_checks {
            if let Some(hash) = fileinfo.filehash {
                let final_hash = hasher.finalize();
                assert_eq!(hex::encode(&final_hash.as_slice()), hex::encode(&hash), "Hash mismatch for file");
            }
        }

        Ok(())
    }

    pub fn verify_file<R: std::io::Read + std::io::Seek, I: Into<FileInfo>>(
        stream: &mut R,
        fileinfo: I,
        from_bundle: bool,
    ) -> Result<(), Error> {
        let fileinfo: FileInfo = fileinfo.into();
        let is_encrypted = fileinfo.key_id_index != 0xFFFF && !from_bundle;
        let is_compressed = fileinfo.compression_type == 0x1;

        stream.seek(std::io::SeekFrom::Start(fileinfo.offset_to_file))?;

        let mut reader = Self::create_reader(
            stream,
            false,
            is_compressed,
            None
        )?;

        let mut pos = 0;
        let mut block = 0;
        let chunk_size = utils::BLOCK_SIZE;
        let mut buf = vec![0u8; chunk_size];

        loop {
            let mut read_amount = std::cmp::min(chunk_size, (fileinfo.uncompressed_length as usize) - pos);
            if is_encrypted {
                read_amount = utils::align_to_sector(read_amount);
            }

            reader.read_exact(&mut buf[..read_amount])?;
            if let Some(block_hash) = fileinfo.block_hashes.as_ref().and_then(|sq| sq.get(block)) {
                // println!("Verifying block hash, block size: {:#X} (total: {:#X})", read_amount, fileinfo.uncompressed_length);
                assert_eq!(hex::encode(Sha256::digest(&buf[..read_amount])), hex::encode(block_hash), "Invalid block hash");
            }

            pos += read_amount;

            if pos >= (fileinfo.uncompressed_length) as usize {
                break;
            }

            block += 1;
        }

        Ok(())
    }

    pub fn read_file_to_buf<R: std::io::Read + std::io::Seek, I: Into<FileInfo> + Clone>(
        stream: &mut R,
        fileinfo: I,
        is_bundle: bool,
    ) -> Result<Vec<u8>, Error> {
        let mut buf = vec![];
        let mut c = Cursor::new(&mut buf);
        Self::read_file(stream, &mut c, fileinfo, is_bundle, None, true)?;

        Ok(buf)
    }

    pub fn save_file_to_fs<R: std::io::BufRead + std::io::Seek, I: Into<FileInfo>>(
        &self,
        stream: &mut R,
        fileinfo: I,
        destination_path: &Path,
        filename: &str
    ) -> Result<(), Error> {
        let fileinfo: FileInfo = fileinfo.into();
        let crypto =self.get_cipher_for_key_index(fileinfo.key_id_index).map(|cipher| 
            CryptoFileContext {
                cipher: create_cipher(&cipher),
                tweak: get_tweak_for_file(&self.header.app_name(), &self.header.publisher_id(), filename)
            }
        );

        // Convert to os-specific seperators
        let filename = match cfg!(windows) {
            true => filename.to_owned(),
            false => filename.replace("\\", "/"),
        };

        // Assemble target filepath
        let target_filepath = destination_path.join(filename);
        std::fs::create_dir_all(target_filepath.parent().unwrap())?;

        // Open target file handle and read data into it
        let mut file = std::fs::File::create(target_filepath)?;
        Self::read_file(stream, &mut file, fileinfo, self.header.is_bundle(), crypto, self.do_checksum_check)
    }

    pub fn load_keys(&mut self, key_collection: &KeyCollection) -> Result<(), Error> {
        key_collection.keys.iter()
            .for_each(|(key_id, keydata)| {
                self.keys.insert(key_id.clone(), keydata.to_vec());
            });
        
        Ok(())
    }

    pub fn find_footer_for_file(&self, file_id: u64) -> Option<&EAppxFooter> {
        return self.footers
            .iter()
            .find(|footer| footer.file_id == file_id)
    }

    fn get_cipher_for_key_index(&self, key_index: u16) -> Option<[u8; 32]> {
        if key_index == 0xFFFF {
            return None;
        }
        else if let Some(key_id) = self.header.key_ids.get(key_index as usize) {
            return self.keys
                .get(key_id)
                .map(|e| e.to_vec().try_into().unwrap());
        }

        None
    }

    fn read_footers<S: std::io::BufRead + std::io::Seek>(stream: &mut S, offset: u64, count: usize) -> Result<Vec<EAppxFooter>, Error> {
        stream.seek(std::io::SeekFrom::Start(offset))?;
        
        let footers = (0..count)
            .map(|_| EAppxFooter::read(stream).unwrap())
            .collect::<Vec<_>>();
    
        Ok(footers)
    }

    pub fn from_stream<S: std::io::BufRead + std::io::Seek>(stream: &mut S) -> Result<Self, Error> {        
        let file_len = stream.seek(std::io::SeekFrom::End(0)).unwrap();
        stream.rewind().unwrap();

        // Read header
        let header = EAppxHeader::read(stream).unwrap();

        // Read footers
        let footers: Vec<EAppxFooter> = Self::read_footers(stream, header.footer_offset, header.footer_count())?;
     
        // Get blockmap metadata
        let mut blockmap_fileinfo: FileInfo = footers.get(header.block_map_file_id as usize)
            .ok_or(Error::DataError("Failed to find blockmap file".into()))?
            .into();
        blockmap_fileinfo.filehash = Some(header.block_map_hash.clone());

        // Deserialize blockmap
        let buf = Self::read_file_to_buf(stream, blockmap_fileinfo, header.is_bundle())?;
        let blockmap: AppxBlockMap = xml_deserialize_from_reader(Cursor::new(buf))
            .map_err(Error::DecodeError)?;

        Ok(Self {
            header,
            file_len,
            footers,
            blockmap,
            keys: HashMap::new(),
            do_checksum_check: false,
        })
    }

    pub fn read_manifest<S: std::io::BufRead + std::io::Seek>(&self, stream: &mut S) -> Result<Manifest, Error> {
        // First entry should always be the bundle-/manifest
        let file = self.blockmap.files
            .first()
            .ok_or(Error::DataError("Could not get first blockmap file".into()))?;
        let footer = self.find_footer_for_file(file.id())
            .ok_or(Error::DataError("Could not get Footer info for blockmap file".into()))?;

        let buf = Self::read_file_to_buf(stream, footer, self.header.is_bundle())?;
        let manifest = match file.name.split('\\').last().ok_or(Error::DataError("Could not determine filename from blockmap filename".into()))? {
            "AppxManifest.xml" => {
                let res: AppxManifest = xml_deserialize_from_reader(Cursor::new(buf))
                    .map_err(Error::DecodeError)?;
                Manifest::Manifest(res)
            },
            "AppxBundleManifest.xml" => {
                let res: AppxBundleManifest = xml_deserialize_from_reader(Cursor::new(buf))
                    .map_err(Error::DecodeError)?;
                Manifest::BundleManifest(res)
            },
            _ => return Err(Error::DataError("Expected Manifest to be first file in blockmap".into()))
        };

        Ok(manifest)
    }

    pub fn extract_footprint_files<T: std::io::BufRead + std::io::Seek>(
        &self,
        stream: &mut T,
        target_filepath: &Path,
    ) -> Result<(), Error> {
        // Read blockmap here again, to have the original representation instead
        // of the already deserialized
        // reason: the schema is not implemented 100%
        let blockmap_fileinfo = self.find_footer_for_file(self.header.block_map_file_id)
            .ok_or(Error::DataError("Failed to find blockmap file".into()))?;
        self.save_file_to_fs(stream, blockmap_fileinfo, target_filepath, "AppxBlockmap.xml")?;

        if let Some(signature_fileinfo) = self.header.appx_signature_fileinfo() {
            println!("Saving signature..");
            if signature_fileinfo.offset_to_file < self.file_len {
                self.save_file_to_fs(stream, signature_fileinfo, target_filepath, "AppxSignature.p7x")?;
            }
        }
        
        if let Some(ci_fileinfo) = self.header.code_integrity_fileinfo() {
            println!("Saving code integrity..");
            if ci_fileinfo.offset_to_file < self.file_len {
                self.save_file_to_fs(stream, ci_fileinfo, target_filepath, "CodeIntegrity.cat")?;
            }
        }

        Ok(())
    }

    pub fn verify_blockmap_files<T: std::io::BufRead + std::io::Seek>(
        &self,
        stream: &mut T
    ) -> Result<(), Error> {
        println!("Verifying blockmap files...");

        for file in &self.blockmap.files {
            let mut file_footer: FileInfo = self.find_footer_for_file(file.id())
                .ok_or(Error::DataError(format!("Failed to find footer for file {file:?}")))?
                .into();

            file_footer.filehash = file.filehash_bytes();
            file_footer.block_hashes = Some(file.block_hashes());

            assert_eq!(file.size, file_footer.uncompressed_length,
                "BlockMap vs. Footer file offset mismatch (manifest: {}, footer: {})", file.size, file_footer.uncompressed_length);

            println!("* File: {} (encrypted={}, compressed={} id: {}) size: {}",
                file.name, file.is_encrypted(), file_footer.compression_type, file.id(), utils::get_filesize_with_unit(file.size));

            Self::verify_file(stream, file_footer, self.header.is_bundle())?;
        }

        Ok(())
    }

    pub fn extract_blockmap_files<T: std::io::BufRead + std::io::Seek>(
        &self,
        stream: &mut T,
        target_filepath: &Path
    ) -> Result<(), Error> {
        println!("Extracting blockmap files...");

        for file in &self.blockmap.files {
            let mut file_footer: FileInfo = self.find_footer_for_file(file.id())
                .ok_or(Error::DataError(format!("Failed to find footer for file {file:?}")))?
                .into();

            file_footer.filehash = file.filehash_bytes();
            file_footer.block_hashes = Some(file.block_hashes());

            assert_eq!(file.size, file_footer.uncompressed_length,
                "BlockMap vs. Footer file offset mismatch (manifest: {}, footer: {})", file.size, file_footer.uncompressed_length);

            println!("* File: {} (encrypted={}, compressed={} id: {}) size: {}",
                file.name, file.is_encrypted(), file_footer.compression_type, file.id(), utils::get_filesize_with_unit(file.size));

            self.save_file_to_fs(stream, file_footer, target_filepath, &file.name)?;
        }

        Ok(())
    }

    pub fn extract_bundle_files<T: std::io::BufRead + std::io::Seek>(
        &self,
        stream: &mut T,
        target_filepath: &Path,
    ) -> Result<(), Error> {
        let manifest = self.read_manifest(stream)?;
        let bundle_manifest = match manifest {
            Manifest::Manifest(_) => return Err(Error::DataError("Expected bundle manifest".into())),
            Manifest::BundleManifest(bundle_manifest) => bundle_manifest,
        };

        for (bundle_file_index, package) in bundle_manifest.packages.package.into_iter().enumerate() {
            println!("* Bundle file: {}", &package.filename);
            let file_meta = self.find_footer_for_file(bundle_file_index as u64)
                .ok_or(Error::DataError(format!("File {} not found in footers", package.filename)))?;

            assert_eq!(package.offset, file_meta.offset_to_file,
                "Bundle Manifest vs. Footer file offset mismatch (manifest: {}, footer: {})", package.offset, file_meta.offset_to_file);

            self.save_file_to_fs(stream, file_meta, target_filepath, &package.filename)?;
        }

        Ok(())
    }

    pub fn extract<T: std::io::BufRead + std::io::Seek>(
        &self,
        stream: &mut T,
        target_filepath: &Path
    ) -> Result<(), Error> {
        self.extract_footprint_files(stream, target_filepath)?;
        self.extract_blockmap_files(stream, target_filepath)?;
        if self.header.is_bundle()
        {
            self.extract_bundle_files(stream, target_filepath)?;
        }

        Ok(())
    }
}

impl std::fmt::Display for EAppxFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.header)?;

        for (footer_idx, footer) in self.footers.iter().enumerate() {
            writeln!(f, "{footer_idx:#04x}: {footer}")?;
        }

        writeln!(f, "* Code Integrity: {}", self.header.is_code_integrity_protected())?;
        writeln!(f, "* Signed: {}", self.header.is_signed())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::EAppxFile;

    #[test]
    #[should_panic(expected = "parsing field 'magic'")]
    pub fn parse_invalid_header() {
        let data = [0u8; 0x1000];
        let mut reader = Cursor::new(&data);

        EAppxFile::from_stream(&mut reader).unwrap();
    }
}