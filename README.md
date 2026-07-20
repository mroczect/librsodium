# librsodium

A safe, simple, and consistent Rust wrapper around the [libsodium-rs](https://github.com/jedisct1/libsodium-rs) crate.  
`librsodium` exposes a clean, JSON‑ready API for all cryptographic primitives provided by libsodium, making them easier to use and harder to misuse.

## Why a wrapper?

`libsodium-rs` already provides excellent bindings to the C libsodium library.  
However, its API is low‑level and requires manual error handling, memory management, and type juggling.

`librsodium` adds:

- **Uniform response type** – every function returns `LibrsodiumResponse<T>` with `success`, `data`, and `error` fields. Call `.to_json()` for instant JSON serialization.
- **Strict input validation** – invalid sizes, empty buffers, or out‑of‑range values are rejected immediately with machine‑readable error codes.
- **Consistent naming** – all functions follow a predictable naming scheme.
- **Full test coverage** – every function is tested for both success and error paths.
- **Zero unsafe in user code** – the wrapper uses `libsodium-rs` internally, so you never touch `unsafe`.

## License

This project is licensed under the [MIT License](LICENSE).

## Acknowledgments

`librsodium` is built on top of the excellent [libsodium-rs](https://github.com/jedisct1/libsodium-rs) bindings by Frank Denis and contributors.

## Status

**This project is still under development**