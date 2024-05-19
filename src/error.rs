use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Decode error")]
    DecodeError(String),
    #[error("I/O Error")]
    IoError(#[from] std::io::Error),
    #[error("Invalid data error")]
    DataError(String),
}