use librsodium::core::crypto_core::hsalsa20;

#[ctor::ctor(unsafe)]
fn init() {
    librsodium::init().expect("libsodium init failed");
}

#[test]
fn constants_are_correct() {
    assert_eq!(hsalsa20::INPUTBYTES, 16);
    assert_eq!(hsalsa20::KEYBYTES, 32);
    assert_eq!(hsalsa20::CONSTBYTES, 16);
    assert_eq!(hsalsa20::OUTPUTBYTES, 32);
}

#[test]
fn hsalsa20_ok_without_constant() {
    let input = [0u8; 16];
    let key = [0u8; 32];
    let out = hsalsa20::hsalsa20(&input, &key, None).unwrap();
    assert_eq!(out.len(), 32);
}

#[test]
fn hsalsa20_ok_with_constant() {
    let input = [0u8; 16];
    let key = [0u8; 32];
    let constant = [0u8; 16];
    let out = hsalsa20::hsalsa20(&input, &key, Some(&constant)).unwrap();
    assert_eq!(out.len(), 32);
}

#[test]
fn hsalsa20_with_constant_gives_different_result() {
    let input = [1u8; 16];
    let key = [2u8; 32];
    let constant1 = [0u8; 16];
    let constant2 = [3u8; 16];
    let out1 = hsalsa20::hsalsa20(&input, &key, Some(&constant1)).unwrap();
    let out2 = hsalsa20::hsalsa20(&input, &key, Some(&constant2)).unwrap();
    assert_ne!(out1, out2);
}

#[test]
fn hsalsa20_invalid_input_length() {
    let input = [0u8; 10];
    let key = [0u8; 32];
    assert!(hsalsa20::hsalsa20(&input, &key, None).is_err());
}

#[test]
fn hsalsa20_invalid_key_length() {
    let input = [0u8; 16];
    let key = [0u8; 10];
    assert!(hsalsa20::hsalsa20(&input, &key, None).is_err());
}

#[test]
fn hsalsa20_invalid_constant_length() {
    let input = [0u8; 16];
    let key = [0u8; 32];
    let constant = [0u8; 10];
    assert!(hsalsa20::hsalsa20(&input, &key, Some(&constant)).is_err());
}
