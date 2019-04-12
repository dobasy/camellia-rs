use std::ops::{BitXor, BitXorAssign, Index, IndexMut};

#[derive(Debug, Copy, Clone, PartialEq)]
pub(crate) enum NthU32 {
    First,
    Second,
    Third,
    Fourth,
}

/// A structure containing 16 bytes of data in big-endian format.
#[repr(C, align(16))]
#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub struct Block {
    pub bytes: [u8; 16],
}

impl From<[u8; 16]> for Block {
    fn from(bytes: [u8; 16]) -> Self {
        Block { bytes }
    }
}

impl Into<[u8; 16]> for Block {
    fn into(self) -> [u8; 16] {
        self.bytes
    }
}

impl Index<NthU32> for Block {
    type Output = u32;

    fn index(&self, index: NthU32) -> &u32 {
        unsafe {
            let ptr = (self as *const Block as *const u32).add(index as usize);
            &*ptr
        }
    }
}

impl IndexMut<NthU32> for Block {
    fn index_mut(&mut self, index: NthU32) -> &mut u32 {
        unsafe {
            let ptr = (self as *mut Block as *mut u32).add(index as usize);
            &mut *ptr
        }
    }
}

impl BitXor for Block {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self {
        Self::from((u128::from_ne_bytes(self.bytes) ^ u128::from_ne_bytes(rhs.bytes)).to_ne_bytes())
    }
}

impl BitXorAssign for Block {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.bytes =
            (u128::from_ne_bytes(self.bytes) ^ u128::from_ne_bytes(rhs.bytes)).to_ne_bytes();
    }
}

impl Block {
    /// Swaps first 8 bytes and last 8 bytes.
    pub(crate) fn swap_halves(&mut self) {
        let tmp = u128::from_ne_bytes(self.bytes);
        self.bytes = ((tmp >> 64) | (tmp << 64)).to_ne_bytes();
    }

    /// Rotates all bits to left by specified amount.
    pub(crate) fn bit_rotate_left(&mut self, n: u32) {
        self.bytes = u128::from_be_bytes(self.bytes).rotate_left(n).to_be_bytes();
    }
}

#[test]
fn rotl15() {
    let mut data = Block::from([
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x77,
    ]);
    data.bit_rotate_left(15);
    assert_eq!(
        data,
        Block::from([
            0xa2, 0xb3, 0xc4, 0xd5, 0xe6, 0xf7, 0x80, 0x08, 0x91, 0x19, 0xa2, 0x2a, 0xb3, 0x3b,
            0x80, 0x91
        ])
    )
}

#[test]
fn rotl34() {
    let mut data = Block::from([
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x77,
    ]);
    data.bit_rotate_left(34);
    assert_eq!(
        data,
        Block::from([
            0x26, 0xaf, 0x37, 0xbc, 0x00, 0x44, 0x88, 0xcd, 0x11, 0x55, 0x99, 0xdc, 0x04, 0x8d,
            0x15, 0x9e
        ])
    )
}
