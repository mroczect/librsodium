use librsodium::core::crypto_core::salsa2012;

#[ctor::ctor(unsafe)]
fn init() {
    librsodium::init().expect("libsodium init failed");
}

#[test]
fn constants_are_correct() {
    assert_eq!(salsa2012::INPUTBYTES, 16);
    assert_eq!(salsa2012::KEYBYTES, 32);
    assert_eq!(salsa2012::CONSTBYTES, 16);
    assert_eq!(salsa2012::OUTPUTBYTES, 64);
}

#[test]
fn salsa2012_ok_without_constant() {
    let input = [0u8; 16];
    let key = [0u8; 32];
    let out = salsa2012::salsa2012(&input, &key, None).unwrap();
    assert_eq!(out.len(), 64);
}

#[test]
fn salsa2012_ok_with_constant() {
    let input = [0u8; 16];
    let key = [0u8; 32];
    let constant = [0u8; 16];
    let out = salsa2012::salsa2012(&input, &key, Some(&constant)).unwrap();
    assert_eq!(out.len(), 64);
}

#[test]
fn salsa2012_with_constant_gives_different_result() {
    let input = [1u8; 16];
    let key = [2u8; 32];
    let constant1 = [0u8; 16];
    let constant2 = [3u8; 16];
    let out1 = salsa2012::salsa2012(&input, &key, Some(&constant1)).unwrap();
    let out2 = salsa2012::salsa2012(&input, &key, Some(&constant2)).unwrap();
    assert_ne!(out1, out2);
}

#[test]
fn salsa2012_invalid_input_length() {
    let input = [0u8; 10];
    let key = [0u8; 32];
    assert!(salsa2012::salsa2012(&input, &key, None).is_err());
}

#[test]
fn salsa2012_invalid_key_length() {
    let input = [0u8; 16];
    let key = [0u8; 10];
    assert!(salsa2012::salsa2012(&input, &key, None).is_err());
}

#[test]
fn salsa2012_invalid_constant_length() {
    let input = [0u8; 16];
    let key = [0u8; 32];
    let constant = [0u8; 10];
    assert!(salsa2012::salsa2012(&input, &key, Some(&constant)).is_err());
}
