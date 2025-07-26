use std::fmt;

#[derive(Debug)]
#[allow(dead_code)]
pub enum DDoSError {
    NetworkError(String),
    ModelError(String),
    ConfigError(String),
    LockError(String),
    IoError(String),
    ParseError(String),
}

impl fmt::Display for DDoSError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DDoSError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            DDoSError::ModelError(msg) => write!(f, "Model error: {}", msg),
            DDoSError::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
            DDoSError::LockError(msg) => write!(f, "Lock error: {}", msg),
            DDoSError::IoError(msg) => write!(f, "IO error: {}", msg),
            DDoSError::ParseError(msg) => write!(f, "Parse error: {}", msg),
        }
    }
}

impl std::error::Error for DDoSError {}

impl From<std::io::Error> for DDoSError {
    fn from(err: std::io::Error) -> Self {
        DDoSError::IoError(err.to_string())
    }
}

impl From<csv::Error> for DDoSError {
    fn from(err: csv::Error) -> Self {
        DDoSError::IoError(err.to_string())
    }
}

impl From<std::num::ParseIntError> for DDoSError {
    fn from(err: std::num::ParseIntError) -> Self {
        DDoSError::ParseError(err.to_string())
    }
}

impl From<&str> for DDoSError {
    fn from(msg: &str) -> Self {
        DDoSError::ConfigError(msg.to_string())
    }
}

impl From<String> for DDoSError {
    fn from(msg: String) -> Self {
        DDoSError::ConfigError(msg)
    }
}

impl From<ctrlc::Error> for DDoSError {
    fn from(err: ctrlc::Error) -> Self {
        DDoSError::ConfigError(err.to_string())
    }
}

impl From<Box<dyn std::error::Error>> for DDoSError {
    fn from(err: Box<dyn std::error::Error>) -> Self {
        DDoSError::ModelError(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, DDoSError>;
