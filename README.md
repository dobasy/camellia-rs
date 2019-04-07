# camellia-rs
Rust implementation of Camellia cipher.

## Usage
```rust
use camellia_rs::*;

fn encrypt_block(key: &[u8], data: &mut [u8; 16]) -> Result<(), InvalidKeyLength> {
    let c = CamelliaCipher::new(key)?;
    let mut buf = Block::from(*data);
    c.encrypt(&mut buf);
    *data = buf.into();
    Ok(())
}
```

## License
This library is licensed under MIT License.
