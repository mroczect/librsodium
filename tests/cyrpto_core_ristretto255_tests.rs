use librsodium::core::crypto_core::ristretto255;
use librsodium::core::random;

#[ctor::ctor(unsafe)]
fn init() {
    librsodium::init().expect("libsodium init failed");
}

#[test]
fn random_point_is_valid() {
    let p = ristretto255::random().unwrap();
    assert!(ristretto255::is_valid_point(&p).unwrap());
}

#[test]
fn add_sub_consistency() {
    let p = ristretto255::random().unwrap();
    let q = ristretto255::random().unwrap();
    let sum = ristretto255::add(&p, &q).unwrap();
    let diff = ristretto255::sub(&sum, &q).unwrap();
    assert_eq!(diff, p);
}

#[test]
fn scalar_arithmetic_properties() {
    let x = ristretto255::scalar_random().unwrap();
    let y = ristretto255::scalar_random().unwrap();

    let xy = ristretto255::scalar_add(&x, &y).unwrap();
    let yx = ristretto255::scalar_add(&y, &x).unwrap();
    assert_eq!(xy, yx);

    let xy_mul = ristretto255::scalar_mul(&x, &y).unwrap();
    let yx_mul = ristretto255::scalar_mul(&y, &x).unwrap();
    assert_eq!(xy_mul, yx_mul);
}

#[test]
fn scalar_invert_identity() {
    let mut s = ristretto255::scalar_random().unwrap();
    s[0] |= 1;
    let inv = ristretto255::scalar_invert(&s).unwrap();
    let prod = ristretto255::scalar_mul(&s, &inv).unwrap();
    assert_eq!(prod[0], 1);
    for b in &prod[1..] {
        assert_eq!(*b, 0);
    }
}

#[test]
fn scalar_invert_zero_fails() {
    let zero = [0u8; ristretto255::SCALARBYTES];
    assert!(ristretto255::scalar_invert(&zero).is_err());
}

#[test]
fn from_hash_produces_valid_point() {
    let hash = random::bytes(ristretto255::HASHBYTES).unwrap();
    let point = ristretto255::from_hash(&hash).unwrap();
    assert!(ristretto255::is_valid_point(&point).unwrap());
}
