use self::CamelliaKeyLength::*;
use crate::{
    block::{Block, NthU32::*},
    consts::*,
    error::InvalidKeyLength,
};

type CamelliaResult<T> = Result<T, InvalidKeyLength>;

#[derive(Debug, Copy, Clone, PartialEq)]
enum CamelliaKeyLength {
    Short,
    Medium,
    Long,
}

impl CamelliaKeyLength {
    fn from_key(key: &[u8]) -> CamelliaResult<Self> {
        match key.len() {
            16 => Ok(Short),
            24 => Ok(Medium),
            32 => Ok(Long),
            _ => Err(InvalidKeyLength),
        }
    }
}

#[derive(Debug, Default, Clone)]
struct CamelliaSubkeys {
    whitening: [Block; 2],
    keys: [[u32; 2]; 30],
}

/// A structure representing cipher.
#[derive(Debug, Clone)]
pub struct CamelliaCipher {
    subkeys: CamelliaSubkeys,
    key_len: CamelliaKeyLength,
}

impl CamelliaCipher {
    /// Creates new CamelliaCipher instance from variable length key.
    ///
    /// # Errors
    ///
    /// If key.len() is other than 16, 24 and 32, an error will be returned.
    ///
    /// # Examples
    ///
    /// ```
    /// # use camellia_rs::*;
    /// let key = [0u8; 16];
    /// let cipher = CamelliaCipher::new(&key).unwrap();
    /// ```
    pub fn new(key: &[u8]) -> CamelliaResult<Self> {
        let (subkeys, key_len) = Self::key_schedule(key)?;
        Ok(CamelliaCipher { subkeys, key_len })
    }

    fn key_schedule(key: &[u8]) -> CamelliaResult<(CamelliaSubkeys, CamelliaKeyLength)> {
        let key_len = CamelliaKeyLength::from_key(key)?;

        let mut kl = Block::from([
            key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], key[8], key[9],
            key[10], key[11], key[12], key[13], key[14], key[15],
        ]);

        let mut subkeys = CamelliaSubkeys::default();

        if key_len == Short {
            let mut ka = kl;
            Self::double_feistel(&mut ka, SIGMA[0], SIGMA[1]);
            ka ^= kl;
            Self::double_feistel(&mut ka, SIGMA[2], SIGMA[3]);

            subkeys.whitening[0] = kl;

            subkeys.keys[0] = [ka[First], ka[Second]];
            subkeys.keys[1] = [ka[Third], ka[Fourth]];
            kl.bit_rotate_left(15);
            subkeys.keys[2] = [kl[First], kl[Second]];
            subkeys.keys[3] = [kl[Third], kl[Fourth]];
            ka.bit_rotate_left(15);
            subkeys.keys[4] = [ka[First], ka[Second]];
            subkeys.keys[5] = [ka[Third], ka[Fourth]];

            ka.bit_rotate_left(15);
            subkeys.keys[6] = [ka[First], ka[Second]];
            subkeys.keys[7] = [ka[Third], ka[Fourth]];

            kl.bit_rotate_left(30);
            subkeys.keys[8] = [kl[First], kl[Second]];
            subkeys.keys[9] = [kl[Third], kl[Fourth]];
            ka.bit_rotate_left(15);
            subkeys.keys[10] = [ka[First], ka[Second]];
            kl.bit_rotate_left(15);
            subkeys.keys[11] = [kl[Third], kl[Fourth]];
            ka.bit_rotate_left(15);
            subkeys.keys[12] = [ka[First], ka[Second]];
            subkeys.keys[13] = [ka[Third], ka[Fourth]];

            kl.bit_rotate_left(17);
            subkeys.keys[14] = [kl[First], kl[Second]];
            subkeys.keys[15] = [kl[Third], kl[Fourth]];

            kl.bit_rotate_left(17);
            subkeys.keys[16] = [kl[First], kl[Second]];
            subkeys.keys[17] = [kl[Third], kl[Fourth]];
            ka.bit_rotate_left(34);
            subkeys.keys[18] = [ka[First], ka[Second]];
            subkeys.keys[19] = [ka[Third], ka[Fourth]];
            kl.bit_rotate_left(17);
            subkeys.keys[20] = [kl[First], kl[Second]];
            subkeys.keys[21] = [kl[Third], kl[Fourth]];

            ka.bit_rotate_left(17);
            subkeys.whitening[1] = ka;
        } else {
            let mut kr = if key_len == Medium {
                Block::from([
                    key[16], key[17], key[18], key[19], key[20], key[21], key[22], key[23],
                    !key[16], !key[17], !key[18], !key[19], !key[20], !key[21], !key[22], !key[23],
                ])
            } else {
                Block::from([
                    key[16], key[17], key[18], key[19], key[20], key[21], key[22], key[23],
                    key[24], key[25], key[26], key[27], key[28], key[29], key[30], key[31],
                ])
            };

            let mut ka = kl ^ kr;
            Self::double_feistel(&mut ka, SIGMA[0], SIGMA[1]);
            ka ^= kl;
            Self::double_feistel(&mut ka, SIGMA[2], SIGMA[3]);

            let mut kb = ka ^ kr;
            Self::double_feistel(&mut kb, SIGMA[4], SIGMA[5]);

            subkeys.whitening[0] = kl;

            subkeys.keys[0] = [kb[First], kb[Second]];
            subkeys.keys[1] = [kb[Third], kb[Fourth]];
            kr.bit_rotate_left(15);
            subkeys.keys[2] = [kr[First], kr[Second]];
            subkeys.keys[3] = [kr[Third], kr[Fourth]];
            ka.bit_rotate_left(15);
            subkeys.keys[4] = [ka[First], ka[Second]];
            subkeys.keys[5] = [ka[Third], ka[Fourth]];

            kr.bit_rotate_left(15);
            subkeys.keys[6] = [kr[First], kr[Second]];
            subkeys.keys[7] = [kr[Third], kr[Fourth]];

            kb.bit_rotate_left(30);
            subkeys.keys[8] = [kb[First], kb[Second]];
            subkeys.keys[9] = [kb[Third], kb[Fourth]];
            kl.bit_rotate_left(45);
            subkeys.keys[10] = [kl[First], kl[Second]];
            subkeys.keys[11] = [kl[Third], kl[Fourth]];
            ka.bit_rotate_left(30);
            subkeys.keys[12] = [ka[First], ka[Second]];
            subkeys.keys[13] = [ka[Third], ka[Fourth]];

            kl.bit_rotate_left(15);
            subkeys.keys[14] = [kl[First], kl[Second]];
            subkeys.keys[15] = [kl[Third], kl[Fourth]];

            kr.bit_rotate_left(30);
            subkeys.keys[16] = [kr[First], kr[Second]];
            subkeys.keys[17] = [kr[Third], kr[Fourth]];
            kb.bit_rotate_left(30);
            subkeys.keys[18] = [kb[First], kb[Second]];
            subkeys.keys[19] = [kb[Third], kb[Fourth]];
            kl.bit_rotate_left(17);
            subkeys.keys[20] = [kl[First], kl[Second]];
            subkeys.keys[21] = [kl[Third], kl[Fourth]];

            ka.bit_rotate_left(32);
            subkeys.keys[22] = [ka[First], ka[Second]];
            subkeys.keys[23] = [ka[Third], ka[Fourth]];

            kr.bit_rotate_left(34);
            subkeys.keys[24] = [kr[First], kr[Second]];
            subkeys.keys[25] = [kr[Third], kr[Fourth]];
            ka.bit_rotate_left(17);
            subkeys.keys[26] = [ka[First], ka[Second]];
            subkeys.keys[27] = [ka[Third], ka[Fourth]];
            kl.bit_rotate_left(34);
            subkeys.keys[28] = [kl[First], kl[Second]];
            subkeys.keys[29] = [kl[Third], kl[Fourth]];

            kb.bit_rotate_left(51);
            subkeys.whitening[1] = kb;
        }

        Ok((subkeys, key_len))
    }

    fn f(left: &mut [u32; 2], key: [u32; 2]) {
        let mut d = 0u32;
        let mut u = 0u32;
        d ^= SP1110[0][(left[1] ^ key[1]).to_ne_bytes()[3] as usize];
        u ^= SP1110[0][(left[0] ^ key[0]).to_ne_bytes()[0] as usize];
        d ^= SP1110[1][(left[1] ^ key[1]).to_ne_bytes()[0] as usize];
        u ^= SP1110[1][(left[0] ^ key[0]).to_ne_bytes()[1] as usize];
        d ^= SP1110[2][(left[1] ^ key[1]).to_ne_bytes()[1] as usize];
        u ^= SP1110[2][(left[0] ^ key[0]).to_ne_bytes()[2] as usize];
        d ^= SP1110[3][(left[1] ^ key[1]).to_ne_bytes()[2] as usize];
        u ^= SP1110[3][(left[0] ^ key[0]).to_ne_bytes()[3] as usize];

        left[0] = d ^ u;
        left[1] = left[0]
            ^ if cfg!(target_endian = "big") {
                u.rotate_right(8)
            } else {
                u.rotate_left(8)
            };
    }

    fn double_feistel(block: &mut Block, key1: [u32; 2], key2: [u32; 2]) {
        let mut half: [u32; 2];

        half = [block[First], block[Second]];
        Self::f(&mut half, key1);
        block[Third] ^= half[0];
        block[Fourth] ^= half[1];

        half = [block[Third], block[Fourth]];
        Self::f(&mut half, key2);
        block[First] ^= half[0];
        block[Second] ^= half[1];
    }

    fn fl_layer(block: &mut Block, key1: [u32; 2], key2: [u32; 2]) {
        let mut fll = block[First] & key1[0];
        fll = u32::from_be(fll).rotate_left(1).to_be();
        block[Second] ^= fll;
        block[First] ^= block[Second] | key1[1];

        block[Third] ^= block[Fourth] | key2[1];
        let mut flr = block[Third] & key2[0];
        flr = u32::from_be(flr).rotate_left(1).to_be();
        block[Fourth] ^= flr;
    }

    /// Encrypts given block in-place.
    ///
    /// # Examples
    ///
    /// ```
    /// # use camellia_rs::*;
    /// let key = [0u8; 16];
    /// let cipher = CamelliaCipher::new(&key).unwrap();
    /// let data = [0u8; 16];
    /// let mut block = Block::from(data);
    /// cipher.encrypt(&mut block);
    /// let encrypted: [u8; 16] = block.into();
    /// ```
    pub fn encrypt(&self, block: &mut Block) {
        *block ^= self.subkeys.whitening[0];

        Self::double_feistel(block, self.subkeys.keys[0], self.subkeys.keys[1]);
        Self::double_feistel(block, self.subkeys.keys[2], self.subkeys.keys[3]);
        Self::double_feistel(block, self.subkeys.keys[4], self.subkeys.keys[5]);

        Self::fl_layer(block, self.subkeys.keys[6], self.subkeys.keys[7]);

        Self::double_feistel(block, self.subkeys.keys[8], self.subkeys.keys[9]);
        Self::double_feistel(block, self.subkeys.keys[10], self.subkeys.keys[11]);
        Self::double_feistel(block, self.subkeys.keys[12], self.subkeys.keys[13]);

        Self::fl_layer(block, self.subkeys.keys[14], self.subkeys.keys[15]);

        Self::double_feistel(block, self.subkeys.keys[16], self.subkeys.keys[17]);
        Self::double_feistel(block, self.subkeys.keys[18], self.subkeys.keys[19]);
        Self::double_feistel(block, self.subkeys.keys[20], self.subkeys.keys[21]);

        if self.key_len != Short {
            Self::fl_layer(block, self.subkeys.keys[22], self.subkeys.keys[23]);

            Self::double_feistel(block, self.subkeys.keys[24], self.subkeys.keys[25]);
            Self::double_feistel(block, self.subkeys.keys[26], self.subkeys.keys[27]);
            Self::double_feistel(block, self.subkeys.keys[28], self.subkeys.keys[29]);
        }

        block.swap_halves();
        *block ^= self.subkeys.whitening[1];
    }

    /// Decrypts given block in-place.
    ///
    /// # Examples
    ///
    /// ```
    /// # use camellia_rs::*;
    /// let key = [0u8; 16];
    /// let cipher = CamelliaCipher::new(&key).unwrap();
    /// let data = [0u8; 16];
    /// let mut block = Block::from(data);
    /// cipher.decrypt(&mut block);
    /// let decrypted: [u8; 16] = block.into();
    /// ```
    pub fn decrypt(&self, block: &mut Block) {
        *block ^= self.subkeys.whitening[1];

        if self.key_len != Short {
            Self::double_feistel(block, self.subkeys.keys[29], self.subkeys.keys[28]);
            Self::double_feistel(block, self.subkeys.keys[27], self.subkeys.keys[26]);
            Self::double_feistel(block, self.subkeys.keys[25], self.subkeys.keys[24]);

            Self::fl_layer(block, self.subkeys.keys[23], self.subkeys.keys[22]);
        }

        Self::double_feistel(block, self.subkeys.keys[21], self.subkeys.keys[20]);
        Self::double_feistel(block, self.subkeys.keys[19], self.subkeys.keys[18]);
        Self::double_feistel(block, self.subkeys.keys[17], self.subkeys.keys[16]);

        Self::fl_layer(block, self.subkeys.keys[15], self.subkeys.keys[14]);

        Self::double_feistel(block, self.subkeys.keys[13], self.subkeys.keys[12]);
        Self::double_feistel(block, self.subkeys.keys[11], self.subkeys.keys[10]);
        Self::double_feistel(block, self.subkeys.keys[9], self.subkeys.keys[8]);

        Self::fl_layer(block, self.subkeys.keys[7], self.subkeys.keys[6]);

        Self::double_feistel(block, self.subkeys.keys[5], self.subkeys.keys[4]);
        Self::double_feistel(block, self.subkeys.keys[3], self.subkeys.keys[2]);
        Self::double_feistel(block, self.subkeys.keys[1], self.subkeys.keys[0]);

        block.swap_halves();
        *block ^= self.subkeys.whitening[0];
    }
}
