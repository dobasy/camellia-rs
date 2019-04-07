//! Rust implementation of Camellia cipher.
//!
//! # Safety
//!
//! Unsafe codes are only used in Block.index() and index_mut().

mod block;
mod camellia;
mod consts;
mod error;

pub use crate::{block::Block, camellia::CamelliaCipher, error::InvalidKeyLength};

#[cfg(test)]
mod tests;
