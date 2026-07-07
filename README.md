# CryptoPP C++ DLL API

`main.h` / `main.cpp` expose a flat, `extern "C"` / `cdecl` API around
[Crypto++](https://www.cryptopp.com/) so the library can be consumed from
non-C++ callers (e.g. the companion Delphi wrapper in [my other repo](https://github.com/alimtolman/cryptopp-api-delphi)). It is
built as a Windows DLL (`cryptopp.dll`).

## Requirements

- Crypto++ library sources/headers (tested against the headers included by
  a standard Crypto++ distribution).
- A C++ compiler with Windows DLL export support (MSVC recommended, since
  `__declspec(dllexport)` is used).
- `CRYPTOPP_ENABLE_NAMESPACE_WEAK` is defined so weak/legacy algorithms
  (MD2, MD4, MD5) remain available via `CryptoPP::Weak::`.

## Building

1. Add `main.cpp` to a Crypto++-linked DLL project (or a project that
   builds Crypto++ from source alongside it).
2. Ensure the project type is a **Dynamic Library (.dll)**.
3. Build in Release/x64 (or whichever bitness matches your consumer, e.g.
   the Delphi application) as `cryptopp.dll`.
4. `delete_byte_array` and every other exported function use the C
   calling convention (`extern "C"`) with `__cdecl`, matching the Delphi
   side's `cdecl` import declarations.

## Design conventions

- **Memory ownership**: functions documented with `@note Caller MUST
  delete 'output_bytes' with helper function 'delete_byte_array'`
  allocate their output buffer inside the DLL with `new byte[]`. The
  caller must pass that pointer back to `delete_byte_array()` — never
  `free()`/`delete[]` it from the caller's own heap, since CRT heaps can
  differ between the DLL and the host application.
- **Caller-allocated buffers**: functions documented with `@note Caller
  MUST allocate 'output_bytes' with size ...` write directly into a
  buffer the caller already owns (typical for stream ciphers/hashes with
  a known, fixed output size). No `delete_byte_array` call is needed for
  these.
- **Hex-encoded big integers**: `big_integer_*` and `dh_*` functions take
  values as `"0x..."`-prefixed hex C-strings (`const char*`), consistent
  with `CryptoPP::Integer`'s string constructor.
- **Elliptic curve selector**: `ecdh_*`/`ecdsa_*` take a `byte
  elliptic_curve` selector: `0 = secp256k1`, `1 = secp256r1`, `2 =
  secp384r1`, `3 = secp521r1` (anything else falls back to secp256k1).
- **Padding**: AES CBC/ECB expose a `zeros_padding` flag
  (`false` = PKCS#7, `true` = zero padding). Other modes (CFB, CTR, GCM,
  stream ciphers) do not need block padding.

## API reference by category

| Region | Functions | Notes |
|---|---|---|
| helpers | `delete_byte_array` | Frees DLL-allocated output buffers. |
| aes | `aes_cbc_*`, `aes_cfb_*`, `aes_ctr_*`, `aes_ecb_*`, `aes_gcm_*` | GCM uses a fixed 16-byte authentication tag appended to ciphertext. |
| big integer | `big_integer_add/mod/mod_pow/multiply/subtract` | Operates on hex-string encoded `Integer`s. |
| blowfish | `blowfish_cbc_*` | 16-byte IV. |
| camellia | `camellia_cbc_*` | 16-byte IV. |
| chacha20 | `chacha20_encrypt/decrypt` | 16/32-byte key, 8-byte IV (classic ChaCha, not IETF/XChaCha). |
| diffie-hellman | `dh_key_pair`, `dh_shared_key` | Classic finite-field DH with caller-supplied `p`/`g`. |
| ecdh | `ecdh_key_pair`, `ecdh_shared_key` | Curve selected via `elliptic_curve` byte. |
| ecdsa | `ecdsa_export_public_key`, `ecdsa_key_pair`, `ecdsa_sha1_sign/verify`, `ecdsa_sha256_sign/verify` | Signatures are Crypto++'s **raw** `R \|\| S` format (each component's size == curve order size), *not* DER. |
| ed25519 | `ed25519_export_public_key`, `ed25519_key_pair`, `ed25519_sign`, `ed25519_verify` | Keys/signatures use standard PKCS8 (private) / X.509 SubjectPublicKeyInfo (public) DER encoding via `xed25519.h`. |
| hash | `md2`, `md4`, `md5`, `poly1305_tls` | Fixed 16-byte digest. `poly1305_tls` is the IETF one-time-key variant (32-byte key). |
| pbkdf2 | `pbkdf2_hmac_sha1/256/512` | Output length is caller-defined via `output_size`. |
| rsa | `rsa_ecb_*`, `rsa_export_public_key`, `rsa_key_pair`, `rsa_no_padding_*`, `rsa_oaep_{md2,md4,md5,sha1,sha224,sha256,sha384,sha512}_*`, `rsa_pss_sha{1,224,256,384,512}_{sign,verify}`, `rsa_{md2,md5,sha1,sha224,sha256,sha384,sha512}_{sign,verify}` | ECB/OAEP encrypt-decrypt loop over key-sized blocks so arbitrary-length input is supported. |
| salsa20 | `salsa20_encrypt/decrypt` | 16/32-byte key, 8-byte IV. |
| x25519 | `x25519_key_pair`, `x25519_shared_key` | Raw 32-byte keys (no DER wrapping), per Crypto++'s `x25519` class. |
| xsalsa20 | `xsalsa20_encrypt/decrypt`, `xsalsa20_poly1305_tls_{encrypt,decrypt}` | 32-byte key, 24-byte IV. The AEAD variant prepends/verifies a 16-byte Poly1305 tag. |

## Security notes

- `xsalsa20_poly1305_tls_decrypt` performs the Poly1305 tag comparison in
  **constant time** (`CryptoPP::VerifyBufsEqual`) and reports the result
  via the `verified` out-parameter. **Always check `verified`** — if it
  is `false`, `output_bytes` is zero-filled rather than containing
  unauthenticated plaintext.
- AES-ECB is exposed because some legacy protocols require it, but it
  does not hide data patterns — prefer CBC/CTR/GCM for new designs.
- MD2/MD4/MD5 and SHA-1 based RSA/ECDSA signature schemes are provided
  for legacy interoperability only; they are not recommended for new
  designs.
- Private keys, symmetric keys and derived secrets are handled as plain
  `byte`/`byte*` buffers with no automatic zeroization on free — callers
  are responsible for wiping sensitive buffers after use if required by
  their threat model.
