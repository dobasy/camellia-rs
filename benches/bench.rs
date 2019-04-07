#![feature(test)]

extern crate test;
use camellia_rs::*;
use test::Bencher;

#[bench]
pub fn bench_camellia_128_new(b: &mut Bencher) {
    b.iter(|| CamelliaCipher::new(&[0u8; 16]));
}

#[bench]
pub fn bench_camellia_128_enc(b: &mut Bencher) {
    b.bytes = 16;
    let c = CamelliaCipher::new(&[0u8; 16]).unwrap();
    let mut data = Block::default();
    b.iter(|| c.encrypt(&mut data));
}

#[bench]
pub fn bench_camellia_128_dec(b: &mut Bencher) {
    b.bytes = 16;
    let c = CamelliaCipher::new(&[0u8; 16]).unwrap();
    let mut data = Block::default();
    b.iter(|| c.decrypt(&mut data));
}

#[bench]
pub fn bench_camellia_192_new(b: &mut Bencher) {
    b.iter(|| CamelliaCipher::new(&[0u8; 24]));
}

#[bench]
pub fn bench_camellia_192_enc(b: &mut Bencher) {
    b.bytes = 16;
    let c = CamelliaCipher::new(&[0u8; 24]).unwrap();
    let mut data = Block::default();
    b.iter(|| c.encrypt(&mut data));
}

#[bench]
pub fn bench_camellia_192_dec(b: &mut Bencher) {
    b.bytes = 16;
    let c = CamelliaCipher::new(&[0u8; 24]).unwrap();
    let mut data = Block::default();
    b.iter(|| c.decrypt(&mut data));
}

#[bench]
pub fn bench_camellia_256_new(b: &mut Bencher) {
    b.iter(|| CamelliaCipher::new(&[0u8; 32]));
}

#[bench]
pub fn bench_camellia_256_enc(b: &mut Bencher) {
    b.bytes = 16;
    let c = CamelliaCipher::new(&[0u8; 32]).unwrap();
    let mut data = Block::default();
    b.iter(|| c.encrypt(&mut data));
}

#[bench]
pub fn bench_camellia_256_dec(b: &mut Bencher) {
    b.bytes = 16;
    let c = CamelliaCipher::new(&[0u8; 32]).unwrap();
    let mut data = Block::default();
    b.iter(|| c.decrypt(&mut data));
}
