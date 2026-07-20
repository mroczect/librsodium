use librsodium::core::crypto_core::ed25519;
use librsodium::core::random;

#[ctor::ctor(unsafe)]
fn init() {
    librsodium::init().expect("libsodium init failed");
}

#[test]
fn constants_are_correct() {
    assert_eq!(ed25519::BYTES, 32);
    assert_eq!(ed25519::SCALARBYTES, 32);
    assert_eq!(ed25519::NONREDUCEDSCALARBYTES, 64);
    assert_eq!(ed25519::UNIFORMBYTES, 32);
}

#[test]
fn random_point_is_valid() {
    let p = ed25519::random();
    assert!(ed25519::is_valid_point(&p).unwrap());
}

#[test]
fn add_sub_consistency() {
    let p = ed25519::random();
    let q = ed25519::random();
    let sum = ed25519::add(&p, &q).unwrap();
    let diff = ed25519::sub(&sum, &q).unwrap();
    assert_eq!(diff, p);
}

#[test]
fn scalar_arithmetic_properties() {
    let x = ed25519::scalar_random();
    let y = ed25519::scalar_random();

    let xy = ed25519::scalar_add(&x, &y).unwrap();
    let yx = ed25519::scalar_add(&y, &x).unwrap();
    assert_eq!(xy, yx);

    let xy_mul = ed25519::scalar_mul(&x, &y).unwrap();
    let yx_mul = ed25519::scalar_mul(&y, &x).unwrap();
    assert_eq!(xy_mul, yx_mul);
}

#[test]
fn scalar_invert_identity() {
    let mut s = ed25519::scalar_random();
    s[0] |= 1; 
    let inv = ed25519::scalar_invert(&s).unwrap();
    let prod = ed25519::scalar_mul(&s, &inv).unwrap();
    assert_eq!(prod[0], 1);
    for b in &prod[1..] {
        assert_eq!(*b, 0);
    }
}

#[test]
fn scalar_invert_zero_fails() {
    let zero = [0u8; ed25519::SCALARBYTES];
    assert!(ed25519::scalar_invert(&zero).is_err());
}

#[test]
fn from_uniform_produces_valid_point() {
    let uniform = random::bytes(ed25519::UNIFORMBYTES).unwrap();
    let point = ed25519::from_uniform(&uniform).unwrap();
    assert!(ed25519::is_valid_point(&point).unwrap());
}
