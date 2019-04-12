# camellia-rs
Rust implementation of Camellia cipher.

## Usage
```rust
use camellia_rs::*;

fn encrypt(key: &[u8], data: &mut [u8]) {
    assert_eq!(data.len() % 16, 0);
    let cipher = CamelliaCipher::new(key).unwrap();
    let mut buf = Block::default();

    for i in (0..key.len()).step_by(16) {
        buf.bytes.copy_from_slice(&data[i..(i + 16)]);
        cipher.encrypt(&mut buf);
        data[i..(i + 16)].copy_from_slice(&buf.bytes);
    }
}
```

## License
This library is licensed under MIT License.
