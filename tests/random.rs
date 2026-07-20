use librsodium::core::random;

#[ctor::ctor(unsafe)]
fn initialize() {
    librsodium::init().expect("libsodium init failed");
}

#[test]
fn bytes_ok() {
    let res = random::bytes(32);
    assert!(res.success);
    let data = res.data.unwrap();
    assert_eq!(data.len(), 32);
    assert!(data.iter().any(|&b| b != 0));
}

#[test]
fn bytes_zero_fails() {
    let res = random::bytes(0);
    assert!(!res.success);
    let err = res.error.unwrap();
    assert_eq!(err.code, "INVALID_SIZE");
}

#[test]
fn bytes_max_ok() {
    let res = random::bytes(1_073_741_824);
    assert!(res.success);
}

#[test]
fn bytes_too_large_fails() {
    let res = random::bytes(1_073_741_825);
    assert!(!res.success);
    let err = res.error.unwrap();
    assert_eq!(err.code, "INVALID_SIZE");
}

#[test]
fn fill_bytes_ok() {
    let mut buf = [0u8; 64];
    let res = random::fill_bytes(&mut buf);
    assert!(res.success);
    assert!(buf.iter().any(|&b| b != 0));
}

#[test]
fn fill_bytes_empty_fails() {
    let res = random::fill_bytes(&mut []);
    assert!(!res.success);
    let err = res.error.unwrap();
    assert_eq!(err.code, "INVALID_SIZE");
}

#[test]
fn u32_ok() {
    let res = random::u32();
    assert!(res.success);
}

#[test]
fn u32_multiple_calls_give_different_values() {
    let v1 = random::u32().data.unwrap();
    let v2 = random::u32().data.unwrap();
    assert_ne!(v1, v2);
}

#[test]
fn uniform_ok() {
    let res = random::uniform(100);
    assert!(res.success);
    assert!(res.data.unwrap() < 100);
}

#[test]
fn uniform_zero_fails() {
    let res = random::uniform(0);
    assert!(!res.success);
    let err = res.error.unwrap();
    assert_eq!(err.code, "INVALID_INPUT");
}

#[test]
fn uniform_distribution() {
    let bound = 10;
    let mut counts = [0usize; 10];
    for _ in 0..1000 {
        let n = random::uniform(bound).data.unwrap() as usize;
        counts[n] += 1;
    }
    assert!(counts.iter().all(|&c| c > 0));
}

#[test]
fn test_random_json_serialization() {
    let res = random::bytes(16);
    let json = res.to_json();
    assert!(json.contains("\"success\":true"));
    assert!(json.contains("\"data\":["));
}
