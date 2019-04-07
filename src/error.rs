use std::fmt;

#[derive(Debug, Clone)]
pub struct InvalidKeyLength;

impl fmt::Display for InvalidKeyLength {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid key length")
    }
}
