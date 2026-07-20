use librsodium::core::crypto_core::keccak1600;

#[ctor::ctor(unsafe)]
fn init() {
    librsodium::init().expect("libsodium init failed");
}

#[test]
fn constants_are_correct() {
    assert_eq!(keccak1600::STATEBYTES, 224);
    assert_eq!(keccak1600::statebytes(), 224);
}

#[test]
fn new_state_is_initialized() {
    let state = keccak1600::State::new();
    let mut out = [0xFFu8; 136];
    state.extract_bytes(&mut out, 0);
    assert!(out.iter().all(|&b| b == 0), "State should be zeroed");
}

#[test]
fn xor_and_extract() {
    let mut state = keccak1600::State::new();
    let input = [0x42u8; 136];
    state.xor_bytes(&input, 0);

    let mut out = [0u8; 136];
    state.extract_bytes(&mut out, 0);
    assert_eq!(&out[..], &input[..]);
}

#[test]
fn permute_24_changes_state() {
    let mut state = keccak1600::State::new();
    let input = [0x01u8; 136];
    state.xor_bytes(&input, 0);

    let mut before = [0u8; 136];
    state.extract_bytes(&mut before, 0);

    state.permute_24();

    let mut after = [0u8; 136];
    state.extract_bytes(&mut after, 0);
    assert_ne!(&before[..], &after[..]);
}

#[test]
fn permute_12_changes_state() {
    let mut state = keccak1600::State::new();
    let input = [0x01u8; 136];
    state.xor_bytes(&input, 0);

    let mut before = [0u8; 136];
    state.extract_bytes(&mut before, 0);

    state.permute_12();

    let mut after = [0u8; 136];
    state.extract_bytes(&mut after, 0);
    assert_ne!(&before[..], &after[..]);
}

#[test]
fn permute_24_vs_12_different() {
    let mut state24 = keccak1600::State::new();
    let mut state12 = keccak1600::State::new();
    let input = [0x01u8; 136];
    state24.xor_bytes(&input, 0);
    state12.xor_bytes(&input, 0);

    state24.permute_24();
    state12.permute_12();

    let mut out24 = [0u8; 136];
    let mut out12 = [0u8; 136];
    state24.extract_bytes(&mut out24, 0);
    state12.extract_bytes(&mut out12, 0);
    assert_ne!(&out24[..], &out12[..]);
}

#[test]
fn clone_state() {
    let mut state1 = keccak1600::State::new();
    state1.xor_bytes(&[0x42u8; 100], 0);
    state1.permute_24();

    let state2 = state1.clone();
    let mut out1 = [0u8; 100];
    let mut out2 = [0u8; 100];
    state1.extract_bytes(&mut out1, 0);
    state2.extract_bytes(&mut out2, 0);
    assert_eq!(&out1[..], &out2[..]);
}

#[test]
fn reinit_clears_state() {
    let mut state = keccak1600::State::new();
    state.xor_bytes(&[0x42u8; 100], 0);
    state.permute_24();
    state.init();

    let mut out = [0xFFu8; 100];
    state.extract_bytes(&mut out, 0);
    assert!(
        out.iter().all(|&b| b == 0),
        "State should be cleared after reinit"
    );
}

#[test]
fn offset_xor() {
    let mut state = keccak1600::State::new();
    state.xor_bytes(&[0x01], 0);
    state.xor_bytes(&[0x02], 50);
    state.xor_bytes(&[0x03], 100);

    let mut out = [0u8; 1];
    state.extract_bytes(&mut out, 0);
    assert_eq!(out[0], 0x01);
    state.extract_bytes(&mut out, 50);
    assert_eq!(out[0], 0x02);
    state.extract_bytes(&mut out, 100);
    assert_eq!(out[0], 0x03);
}

#[test]
#[should_panic(expected = "offset + length must be <= 200")]
fn xor_overflow_panics() {
    let mut state = keccak1600::State::new();
    state.xor_bytes(&[0u8; 10], 195);
}

#[test]
#[should_panic(expected = "offset + length must be <= 200")]
fn extract_overflow_panics() {
    let state = keccak1600::State::new();
    let mut out = [0u8; 10];
    state.extract_bytes(&mut out, 195);
}
