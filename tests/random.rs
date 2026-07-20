use librsodium::LibrsodiumResponse;
use librsodium::core::random;

#[ctor::ctor(unsafe)]
fn initialize() {
    librsodium::init().expect("libsodium init failed");
}

#[test]
fn bytes_ok() {
    let data = random::bytes(32).expect("bytes should succeed");
    assert_eq!(data.len(), 32);
    assert!(data.iter().any(|&b| b != 0));
}

#[test]
fn bytes_zero_fails() {
    let err = random::bytes(0).unwrap_err();
    assert_eq!(err.to_string(), "Invalid size: expected 1, got 0");
}

#[test]
fn bytes_max_ok() {
    random::bytes(1_073_741_824).expect("1 GB bytes should succeed");
}

#[test]
fn bytes_too_large_fails() {
    let err = random::bytes(1_073_741_825).unwrap_err();
    assert!(err.to_string().contains("Invalid size"));
}

#[test]
fn fill_bytes_ok() {
    let mut buf = [0u8; 64];
    random::fill_bytes(&mut buf).expect("fill_bytes should succeed");
    assert!(buf.iter().any(|&b| b != 0));
}

#[test]
fn fill_bytes_empty_fails() {
    let err = random::fill_bytes(&mut []).unwrap_err();
    assert_eq!(err.to_string(), "Invalid size: expected 1, got 0");
}

#[test]
fn u32_ok() {
    random::u32().expect("u32 should succeed");
}

#[test]
fn u32_multiple_calls_give_different_values() {
    let v1 = random::u32().unwrap();
    let v2 = random::u32().unwrap();
    assert_ne!(v1, v2);
}

#[test]
fn uniform_ok() {
    let n = random::uniform(100).unwrap();
    assert!(n < 100);
}

#[test]
fn uniform_zero_fails() {
    assert!(random::uniform(0).is_err());
}

#[test]
fn uniform_distribution() {
    let bound = 10;
    let mut counts = [0usize; 10];
    for _ in 0..1000 {
        let n = random::uniform(bound).unwrap() as usize;
        counts[n] += 1;
    }
    assert!(counts.iter().all(|&c| c > 0));
}

#[test]
fn test_random_json_serialization() {
    let result = random::bytes(16);
    let response = LibrsodiumResponse::from(result);
    let json = response
        .to_json()
        .expect("JSON serialization should succeed");
    assert!(json.contains("\"success\":true"));
    assert!(json.contains("\"data\":["));
}
