#pragma once
#define CRYPTOPP_EXPORT __declspec(dllexport)

#pragma region helpers

/**
 * Delete allocated in library byte array
 *
 * @note byte array MUST be allocated in library
 *
 * @param bytes - byte array
 */
extern "C" CRYPTOPP_EXPORT void delete_byte_array(const CryptoPP::byte* bytes);

#pragma endregion

#pragma region aes

/**
 * Decrypt data with aes-cbc
 *
 * @note Caller MUST allocate for 'iv_bytes' 16 bytes
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param key_size - size of 'key_bytes'
 * @param iv_bytes - initialization vector byte array
 * @param output_bytes - pointer to null byte array to store decrypted data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 * @param zeros_padding - define padding, default value = false (zeros_padding ? ZEROS : PKCS)
 */
extern "C" CRYPTOPP_EXPORT void aes_cbc_decrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* key_bytes, const unsigned int key_size, const CryptoPP::byte* iv_bytes, CryptoPP::byte** output_bytes, unsigned int* output_size, const bool zeros_padding);

/**
 * Encrypt data with aes-cbc
 *
 * @note Caller MUST allocate for 'iv_bytes' 16 bytes
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param key_size - size of 'key_bytes'
 * @param iv_bytes - initialization vector byte array
 * @param output_bytes - pointer to null byte array to store cipher data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 * @param zeros_padding - define padding, default value = false (zeros_padding ? ZEROS : PKCS)
 */
extern "C" CRYPTOPP_EXPORT void aes_cbc_encrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* key_bytes, const unsigned int key_size, const CryptoPP::byte* iv_bytes, CryptoPP::byte** output_bytes, unsigned int* output_size, const bool zeros_padding);

/**
 * Decrypt data with aes-cfb
 *
 * @note Caller MUST allocate for 'iv_bytes' 16 bytes
 * @note Caller MUST allocate for 'output_bytes' same count of bytes as for 'input_bytes'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param key_size - size of 'key_bytes'
 * @param iv_bytes - initialization vector byte array
 * @param output_bytes - pointer to byte array with defined size to store decrypted data
 */
extern "C" CRYPTOPP_EXPORT void aes_cfb_decrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* key_bytes, const unsigned int key_size, const CryptoPP::byte* iv_bytes, CryptoPP::byte** output_bytes);

/**
 * Encrypt data with aes-cfb
 *
 * @note Caller MUST allocate for 'iv_bytes' 16 bytes
 * @note Caller MUST allocate for 'output_bytes' same count of bytes as for 'input_bytes'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param key_size - size of 'key_bytes'
 * @param iv_bytes - initialization vector byte array
 * @param output_bytes - pointer to byte array with defined size to store cipher data
 */
extern "C" CRYPTOPP_EXPORT void aes_cfb_encrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* key_bytes, const unsigned int key_size, const CryptoPP::byte* iv_bytes, CryptoPP::byte** output_bytes);

/**
 * Decrypt data with aes-ctr
 *
 * @note Caller MUST allocate for 'iv_bytes' 16 bytes
 * @note Caller MUST allocate for 'output_bytes' same count of bytes as for 'input_bytes'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param key_size - size of 'key_bytes'
 * @param iv_bytes - initialization vector byte array
 * @param output_bytes - pointer to byte array with defined size to store decrypted data
 */
extern "C" CRYPTOPP_EXPORT void aes_ctr_decrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* key_bytes, const unsigned int key_size, const CryptoPP::byte* iv_bytes, CryptoPP::byte** output_bytes);

/**
 * Encrypt data with aes-ctr
 *
 * @note Caller MUST allocate for 'iv_bytes' 16 bytes
 * @note Caller MUST allocate for 'output_bytes' same count of bytes as for 'input_bytes'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param key_size - size of 'key_bytes'
 * @param iv_bytes - initialization vector byte array
 * @param output_bytes - pointer to byte array with defined size to store cipher data
 */
extern "C" CRYPTOPP_EXPORT void aes_ctr_encrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* key_bytes, const unsigned int key_size, const CryptoPP::byte* iv_bytes, CryptoPP::byte** output_bytes);

/**
 * Decrypt data with aes-ecb
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param key_size - size of 'key_bytes'
 * @param output_bytes - pointer to null byte array to store decrypted data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 * @param zeros_padding - define padding, default value = false (zeros_padding ? ZEROS : PKCS)
 */
extern "C" CRYPTOPP_EXPORT void aes_ecb_decrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* key_bytes, const unsigned int key_size, CryptoPP::byte** output_bytes, unsigned int* output_size, const bool zeros_padding);

/**
 * Encrypt data with aes-ecb
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param key_size - size of 'key_bytes'
 * @param output_bytes - pointer to null byte array to store cipher data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 * @param zeros_padding - define padding, default value = false (zeros_padding ? ZEROS : PKCS)
 */
extern "C" CRYPTOPP_EXPORT void aes_ecb_encrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* key_bytes, const unsigned int key_size, CryptoPP::byte** output_bytes, unsigned int* output_size, const bool zeros_padding);

/**
 * Decrypt data with aes-gcm
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param key_size - size of 'key_bytes'
 * @param iv_bytes - initialization vector byte array
 * @param iv_size - size of 'iv_bytes'
 * @param output_bytes - pointer to null byte array to store decrypted data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void aes_gcm_decrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* key_bytes, const unsigned int key_size, const CryptoPP::byte* iv_bytes, const unsigned int iv_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Encrypt data with aes-gcm
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param key_size - size of 'key_bytes'
 * @param iv_bytes - initialization vector byte array
 * @param iv_size - size of 'iv_bytes'
 * @param output_bytes - pointer to null byte array to store cipher data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void aes_gcm_encrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* key_bytes, const unsigned int key_size, const CryptoPP::byte* iv_bytes, const unsigned int iv_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

#pragma endregion

#pragma region big integer

/**
 * result = value_1 + value_2
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param value_1_hex - value in hex format (e.g. "0x01020304...")
 * @param value_2_hex - exponent in hex format (e.g. "0x01020304...")
 * @param output_bytes - pointer to null byte array to store result
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void big_integer_add(const char* value_1_hex, const char* value_2_hex, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * result = value_1 % value_2
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param value_1_hex - value in hex format (e.g. "0x01020304...")
 * @param value_2_hex - exponent in hex format (e.g. "0x01020304...")
 * @param output_bytes - pointer to null byte array to store result
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void big_integer_mod(const char* value_1_hex, const char* value_2_hex, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * result = (value ^ exponent) % modulus
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param value_hex - value in hex format (e.g. "0x01020304...")
 * @param exponent_hex - exponent in hex format (e.g. "0x01020304...")
 * @param modulus_hex - modulus in hex format (e.g. "0x01020304...")
 * @param output_bytes - pointer to null byte array to store result
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void big_integer_mod_pow(const char* value_hex, const char* exponent_hex, const char* modulus_hex, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * result = value_1 * value_2
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param value_1_hex - value in hex format (e.g. "0x01020304...")
 * @param value_2_hex - exponent in hex format (e.g. "0x01020304...")
 * @param output_bytes - pointer to null byte array to store result
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void big_integer_multiply(const char* value_1_hex, const char* value_2_hex, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * result = value_1 - value_2
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param value_1_hex - value in hex format (e.g. "0x01020304...")
 * @param value_2_hex - exponent in hex format (e.g. "0x01020304...")
 * @param output_bytes - pointer to null byte array to store result
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void big_integer_subtract(const char* value_1_hex, const char* value_2_hex, CryptoPP::byte** output_bytes, unsigned int* output_size);

#pragma endregion

#pragma region blowfish

/**
 * Decrypt data with blowfish-cbc
 *
 * @note Caller MUST allocate for 'iv_bytes' 16 bytes
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param key_size - size of 'key_bytes'
 * @param iv_bytes - initialization vector byte array
 * @param output_bytes - pointer to null byte array to store decrypted data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void blowfish_cbc_decrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* key_bytes, const unsigned int key_size, const CryptoPP::byte* iv_bytes, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Encrypt data with blowfish-cbc
 *
 * @note Caller MUST allocate for 'iv_bytes' 16 bytes
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param key_size - size of 'key_bytes'
 * @param iv_bytes - initialization vector byte array
 * @param output_bytes - pointer to null byte array to store cipher data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void blowfish_cbc_encrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* key_bytes, const unsigned int key_size, const CryptoPP::byte* iv_bytes, CryptoPP::byte** output_bytes, unsigned int* output_size);

#pragma endregion

#pragma region camellia

/**
 * Decrypt data with camellia-cbc
 *
 * @note Caller MUST allocate for 'iv_bytes' 16 bytes
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param key_size - size of 'key_bytes'
 * @param iv_bytes - initialization vector byte array
 * @param output_bytes - pointer to null byte array to store decrypted data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void camellia_cbc_decrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* key_bytes, const unsigned int key_size, const CryptoPP::byte* iv_bytes, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Encrypt data with camellia-cbc
 *
 * @note Caller MUST allocate for 'iv_bytes' 16 bytes
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param key_size - size of 'key_bytes'
 * @param iv_bytes - initialization vector byte array
 * @param output_bytes - pointer to null byte array to store cipher data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void camellia_cbc_encrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* key_bytes, const unsigned int key_size, const CryptoPP::byte* iv_bytes, CryptoPP::byte** output_bytes, unsigned int* output_size);

#pragma endregion

#pragma region chacha20

/**
 * Decrypt data with chacha20
 *
 * @note Caller MUST allocate for 'key_bytes' 16 or 32 bytes
 * @note Caller MUST allocate for 'iv_bytes' 8 bytes
 * @note Caller MUST allocate 'output_bytes' with size 'input_size'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param key_size - size of 'key_bytes'
 * @param iv_bytes - initialization vector byte array
 * @param output_bytes - pointer to byte array with defined size to store decrypted data
 */
extern "C" CRYPTOPP_EXPORT void chacha20_decrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* key_bytes, const unsigned int key_size, const CryptoPP::byte* iv_bytes, CryptoPP::byte** output_bytes);

/**
 * Encrypt data with chacha20
 *
 * @note Caller MUST allocate for 'key_bytes' 16 or 32 bytes
 * @note Caller MUST allocate for 'iv_bytes' 8 bytes
 * @note Caller MUST allocate 'output_bytes' with size 'input_size'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param key_size - size of 'key_bytes'
 * @param iv_bytes - initialization vector byte array
 * @param output_bytes - pointer to byte array with defined size to store cipher data
 */
extern "C" CRYPTOPP_EXPORT void chacha20_encrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* key_bytes, const unsigned int key_size, const CryptoPP::byte* iv_bytes, CryptoPP::byte** output_bytes);

#pragma endregion

#pragma region diffie-hellman

/**
 * Generate public and private keys
 *
 * @note Caller MUST delete 'private_key_bytes' with helper function 'delete_byte_array'
 * @note Caller MUST delete 'public_key_bytes' with helper function 'delete_byte_array'
 *
 * @param p_hex - 'p' value in hex format (e.g. "0x01020304...")
 * @param g_hex - 'g' value in hex format (e.g. "0x01020304...")
 * @param private_key_bytes - pointer to null byte array to store private key
 * @param private_key_size - pointer to unsigned integer to store 'private_key_bytes' size
 * @param public_key_bytes - pointer to null byte array to store public key
 * @param public_key_size - pointer to unsigned integer to store 'public_key_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void dh_key_pair(const char* p_hex, const char* g_hex, CryptoPP::byte** private_key_bytes, unsigned int* private_key_size, CryptoPP::byte** public_key_bytes, unsigned int* public_key_size);

/**
 * Generate shared key
 *
 * @note Caller MUST delete 'shared_key_bytes' with helper function 'delete_byte_array'
 *
 * @param p_hex - 'p' value in hex format (e.g. "0x01020304...")
 * @param g_hex - 'g' value in hex format (e.g. "0x01020304...")
 * @param private_key_bytes - private key byte array
 * @param other_public_key_bytes - other public key byte array
 * @param shared_key_bytes - pointer to null byte array to store shared key
 * @param shared_key_size - pointer to unsigned integer to store 'shared_key_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void dh_shared_key(const char* p_hex, const char* g_hex, const CryptoPP::byte* private_key_bytes, const CryptoPP::byte* other_public_key_bytes, CryptoPP::byte** shared_key_bytes, unsigned int* shared_key_size);

#pragma endregion

#pragma region ecdh

/**
 * Generate public and private keys
 *
 * @note Caller MUST delete 'private_key_bytes' with helper function 'delete_byte_array'
 * @note Caller MUST delete 'public_key_bytes' with helper function 'delete_byte_array'
 *
 * @param elliptic_curve - known elliptic curve, where 0 is 'secp256k1', 1 is 'secp256r1', 2 is 'secp384r1', 3 is 'secp521r1'
 * @param private_key_bytes - pointer to null byte array to store private key
 * @param private_key_size - pointer to unsigned integer to store 'private_key_bytes' size
 * @param public_key_bytes - pointer to null byte array to store public key
 * @param public_key_size - pointer to unsigned integer to store 'public_key_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void ecdh_key_pair(const CryptoPP::byte elliptic_curve, CryptoPP::byte** private_key_bytes, unsigned int* private_key_size, CryptoPP::byte** public_key_bytes, unsigned int* public_key_size);

/**
 * Generate shared key
 *
 * @note Caller MUST delete 'shared_key_bytes' with helper function 'delete_byte_array'
 *
 * @param elliptic_curve - known elliptic curve, where 0 is 'secp256k1', 1 is 'secp256r1', 2 is 'secp384r1', 3 is 'secp521r1'
 * @param private_key_bytes - private key byte array
 * @param other_public_key_bytes - other public key byte array
 * @param shared_key_bytes - pointer to null byte array to store shared key
 * @param shared_key_size - pointer to unsigned integer to store 'shared_key_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void ecdh_shared_key(const CryptoPP::byte elliptic_curve, const CryptoPP::byte* private_key_bytes, const CryptoPP::byte* other_public_key_bytes, CryptoPP::byte** shared_key_bytes, unsigned int* shared_key_size);

#pragma endregion

#pragma region ecdsa

/**
 * Export public key from private key
 *
 * @note Caller MUST delete 'public_key_bytes' with helper function 'delete_byte_array'
 *
 * @param private_key_bytes - private key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param public_key_bytes - pointer to null byte array to store public key
 * @param public_key_size - pointer to unsigned integer to store 'public_key_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void ecdsa_export_public_key(const CryptoPP::byte* private_key_bytes, const unsigned int private_key_size, CryptoPP::byte** public_key_bytes, unsigned int* public_key_size);

/**
 * Generate ecdsa key pair for defined elliptic curve
 *
 * @note Caller MUST delete 'private_key_bytes' with helper function 'delete_byte_array'
 * @note Caller MUST delete 'public_key_bytes' with helper function 'delete_byte_array'
 *
 * @param elliptic_curve - known elliptic curve, where 0 is 'secp256k1', 1 is 'secp256r1', 2 is 'secp384r1', 3 is 'secp521r1'
 * @param private_key_bytes - pointer to null byte array to store private key
 * @param private_key_size - pointer to unsigned integer to store 'private_key_bytes' size
 * @param public_key_bytes - pointer to null byte array to store public key
 * @param public_key_size - pointer to unsigned integer to store 'public_key_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void ecdsa_key_pair(const CryptoPP::byte elliptic_curve, CryptoPP::byte** private_key_bytes, unsigned int* private_key_size, CryptoPP::byte** public_key_bytes, unsigned int* public_key_size);

/**
 * Generate signature of data with ecdsa sha1
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to sign
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - private key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store signature data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void ecdsa_sha1_sign(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* private_key_bytes, const unsigned int private_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Verify signature of data with ecdsa sha1
 *
 * @param input_bytes - byte array of data
 * @param input_size - size of 'input_bytes'
 * @param signature_bytes - byte array of signaturet
 * @param signature_size - size of 'signature_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param result - pointer to boolean to store result
 */
extern "C" CRYPTOPP_EXPORT void ecdsa_sha1_verify(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* signature_bytes, const unsigned int signature_size, const CryptoPP::byte* public_key_bytes, const unsigned int public_key_size, bool* result);

/**
 * Generate signature of data with ecdsa sha256
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to sign
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - private key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store signature data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void ecdsa_sha256_sign(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* private_key_bytes, const unsigned int private_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Verify signature of data with ecdsa sha256
 *
 * @param input_bytes - byte array of data
 * @param input_size - size of 'input_bytes'
 * @param signature_bytes - byte array of signaturet
 * @param signature_size - size of 'signature_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param result - pointer to boolean to store result
 */
extern "C" CRYPTOPP_EXPORT void ecdsa_sha256_verify(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* signature_bytes, const unsigned int signature_size, const CryptoPP::byte* public_key_bytes, const unsigned int public_key_size, bool* result);

#pragma endregion

#pragma region ed25519

/**
 * Export public key from private key
 *
 * @note 'private_key_bytes' is expected to be a PKCS8 DER-encoded ed25519 private key
 * @note Caller MUST delete 'public_key_bytes' with helper function 'delete_byte_array'
 *
 * @param private_key_bytes - private key byte array (PKCS8 DER encoded)
 * @param private_key_size - size of 'private_key_bytes'
 * @param public_key_bytes - pointer to null byte array to store public key (X.509 DER encoded)
 * @param public_key_size - pointer to unsigned integer to store 'public_key_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void ed25519_export_public_key(const CryptoPP::byte* private_key_bytes, const unsigned int private_key_size, CryptoPP::byte** public_key_bytes, unsigned int* public_key_size);

/**
 * Generate ed25519 key pair
 *
 * @note Returned keys are PKCS8 / X.509 DER encoded
 * @note Caller MUST delete 'private_key_bytes' with helper function 'delete_byte_array'
 * @note Caller MUST delete 'public_key_bytes' with helper function 'delete_byte_array'
 *
 * @param private_key_bytes - pointer to null byte array to store private key
 * @param private_key_size - pointer to unsigned integer to store 'private_key_bytes' size
 * @param public_key_bytes - pointer to null byte array to store public key
 * @param public_key_size - pointer to unsigned integer to store 'public_key_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void ed25519_key_pair(CryptoPP::byte** private_key_bytes, unsigned int* private_key_size, CryptoPP::byte** public_key_bytes, unsigned int* public_key_size);

/**
 * Generate signature of data with ed25519
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to sign
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - private key byte array (PKCS8 DER encoded)
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store signature data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void ed25519_sign(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* private_key_bytes, const unsigned int private_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Verify signature of data with ed25519
 *
 * @param input_bytes - byte array of data
 * @param input_size - size of 'input_bytes'
 * @param signature_bytes - byte array of signature
 * @param signature_size - size of 'signature_bytes'
 * @param public_key_bytes - public key byte array (X.509 DER encoded)
 * @param public_key_size - size of 'public_key_bytes'
 * @param result - pointer to boolean to store result
 */
extern "C" CRYPTOPP_EXPORT void ed25519_verify(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* signature_bytes, const unsigned int signature_size, const CryptoPP::byte* public_key_bytes, const unsigned int public_key_size, bool* result);

#pragma endregion

#pragma region hash

/**
 * md2 hash of byte array of data
 *
 * @note Caller MUST allocate for 'output_bytes' 16 bytes
 *
 * @param input_bytes - byte array of data
 * @param input_size - size of 'input_bytes'
 * @param output_bytes - pointer to byte array with defined size to store hash
 */
extern "C" CRYPTOPP_EXPORT void md2(const CryptoPP::byte* input_bytes, const unsigned int input_size, CryptoPP::byte** output_bytes);

/**
 * md4 hash of byte array of data
 *
 * @note Caller MUST allocate for 'output_bytes' 16 bytes
 *
 * @param input_bytes - byte array of data
 * @param input_size - size of 'input_bytes'
 * @param output_bytes - pointer to byte array with defined size to store hash
 */
extern "C" CRYPTOPP_EXPORT void md4(const CryptoPP::byte* input_bytes, const unsigned int input_size, CryptoPP::byte** output_bytes);

/**
 * md5 hash of byte array of data
 *
 * @note Caller MUST allocate for 'output_bytes' 16 bytes
 *
 * @param input_bytes - byte array of data
 * @param input_size - size of 'input_bytes'
 * @param output_bytes - pointer to byte array with defined size to store hash
 */
extern "C" CRYPTOPP_EXPORT void md5(const CryptoPP::byte* input_bytes, const unsigned int input_size, CryptoPP::byte** output_bytes);

/**
 * poly1305 (IETF's variant) hash of byte array of data
 *
 * @note Caller MUST allocate for 'key_bytes' 32 bytes
 * @note Caller MUST allocate for 'output_bytes' 16 bytes
 *
 * @param input_bytes - byte array of data
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param output_bytes - pointer to byte array with defined size to store hash
 */
extern "C" CRYPTOPP_EXPORT void poly1305_tls(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* key_bytes, CryptoPP::byte** output_bytes);

#pragma endregion

#pragma region pbkdf2

/**
 * Generate byte array for defined size
 *
 * @note Caller MUST allocate 'output_bytes' with size 'output_size'
 *
 * @param password_bytes - password byte array
 * @param password_size - size of 'password_bytes'
 * @param salt_bytes - salt byte array
 * @param salt_size - size of 'salt_bytes'
 * @param iterations_count - iterations count
 * @param output_bytes - pointer to byte array with defined size
 * @param output_size - size of 'output_bytes'
 */
extern "C" CRYPTOPP_EXPORT void pbkdf2_hmac_sha1(const CryptoPP::byte* password_bytes, const unsigned int password_size, const CryptoPP::byte* salt_bytes, const unsigned int salt_size, const unsigned int iterations_count, CryptoPP::byte** output_bytes, const unsigned int output_size);

/**
 * Generate byte array for defined size
 *
 * @note Caller MUST allocate 'output_bytes' with size 'output_size'
 *
 * @param password_bytes - password byte array
 * @param password_size - size of 'password_bytes'
 * @param salt_bytes - salt byte array
 * @param salt_size - size of 'salt_bytes'
 * @param iterations_count - iterations count
 * @param output_bytes - pointer to byte array with defined size
 * @param output_size - size of 'output_bytes'
 */
extern "C" CRYPTOPP_EXPORT void pbkdf2_hmac_sha256(const CryptoPP::byte* password_bytes, const unsigned int password_size, const CryptoPP::byte* salt_bytes, const unsigned int salt_size, const unsigned int iterations_count, CryptoPP::byte** output_bytes, const unsigned int output_size);

/**
 * Generate byte array for defined size
 *
 * @note Caller MUST allocate 'output_bytes' with size 'output_size'
 *
 * @param password_bytes - password byte array
 * @param password_size - size of 'password_bytes'
 * @param salt_bytes - salt byte array
 * @param salt_size - size of 'salt_bytes'
 * @param iterations_count - iterations count
 * @param output_bytes - pointer to byte array with defined size
 * @param output_size - size of 'output_bytes'
 */
extern "C" CRYPTOPP_EXPORT void pbkdf2_hmac_sha512(const CryptoPP::byte* password_bytes, const unsigned int password_size, const CryptoPP::byte* salt_bytes, const unsigned int salt_size, const unsigned int iterations_count, CryptoPP::byte** output_bytes, const unsigned int output_size);

#pragma endregion

#pragma region rsa

/**
 * Decrypt data with rsa ecb pkcs1 padding
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - private key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store decrypted data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void rsa_ecb_decrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* private_key_bytes, const unsigned int private_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Encrypt data with rsa ecb pkcs1 padding
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param output_bytes - pointer to null byte array to store cipher data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void rsa_ecb_encrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* public_key_bytes, const unsigned int public_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Export public key from private key
 *
 * @note Caller MUST delete 'public_key_bytes' with helper function 'delete_byte_array'
 *
 * @param private_key_bytes - private key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param public_key_bytes - pointer to null byte array to store public key
 * @param public_key_size - pointer to unsigned integer to store 'public_key_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void rsa_export_public_key(const CryptoPP::byte* private_key_bytes, const unsigned int private_key_size, CryptoPP::byte** public_key_bytes, unsigned int* public_key_size);

/**
 * Generate rsa key pair for defined size
 *
 * @note Caller MUST delete 'private_key_bytes' with helper function 'delete_byte_array'
 * @note Caller MUST delete 'public_key_bytes' with helper function 'delete_byte_array'
 *
 * @param key_size - size of the key in bits
 * @param private_key_bytes - pointer to null byte array to store private key
 * @param private_key_size - pointer to unsigned integer to store 'private_key_bytes' size
 * @param public_key_bytes - pointer to null byte array to store public key
 * @param public_key_size - pointer to unsigned integer to store 'public_key_bytes' size
 * @param exponent - define key exponent value, default value = 65537
 */
extern "C" CRYPTOPP_EXPORT void rsa_key_pair(const unsigned int key_size, CryptoPP::byte** private_key_bytes, unsigned int* private_key_size, CryptoPP::byte** public_key_bytes, unsigned int* public_key_size, const unsigned int exponent);

/**
 * Decrypt data with rsa no padding
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - private key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store decrypted data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void rsa_no_padding_decrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* private_key_bytes, const unsigned int private_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Encrypt data with rsa no padding
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param output_bytes - pointer to null byte array to store cipher data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void rsa_no_padding_encrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* public_key_bytes, const unsigned int public_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Decrypt data with rsa oaep md2
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - private key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store decrypted data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void rsa_oaep_md2_decrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* private_key_bytes, const unsigned int private_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Encrypt data with rsa oaep md2
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param output_bytes - pointer to null byte array to store cipher data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void rsa_oaep_md2_encrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* public_key_bytes, const unsigned int public_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Decrypt data with rsa oaep md4
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - private key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store decrypted data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void rsa_oaep_md4_decrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* private_key_bytes, const unsigned int private_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Encrypt data with rsa oaep md4
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param output_bytes - pointer to null byte array to store cipher data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void rsa_oaep_md4_encrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* public_key_bytes, const unsigned int public_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Decrypt data with rsa oaep md5
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - private key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store decrypted data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void rsa_oaep_md5_decrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* private_key_bytes, const unsigned int private_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Encrypt data with rsa oaep md5
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param output_bytes - pointer to null byte array to store cipher data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void rsa_oaep_md5_encrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* public_key_bytes, const unsigned int public_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Decrypt data with rsa oaep sha1
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - private key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store decrypted data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void rsa_oaep_sha1_decrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* private_key_bytes, const unsigned int private_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Encrypt data with rsa oaep sha1
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param output_bytes - pointer to null byte array to store cipher data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void rsa_oaep_sha1_encrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* public_key_bytes, const unsigned int public_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Decrypt data with rsa oaep sha224
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - private key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store decrypted data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void rsa_oaep_sha224_decrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* private_key_bytes, const unsigned int private_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Encrypt data with rsa oaep sha224
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param output_bytes - pointer to null byte array to store cipher data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void rsa_oaep_sha224_encrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* public_key_bytes, const unsigned int public_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Decrypt data with rsa oaep sha256
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - private key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store decrypted data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void rsa_oaep_sha256_decrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* private_key_bytes, const unsigned int private_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Encrypt data with rsa oaep sha256
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param output_bytes - pointer to null byte array to store cipher data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void rsa_oaep_sha256_encrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* public_key_bytes, const unsigned int public_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Decrypt data with rsa oaep sha384
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - private key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store decrypted data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void rsa_oaep_sha384_decrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* private_key_bytes, const unsigned int private_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Encrypt data with rsa oaep sha384
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param output_bytes - pointer to null byte array to store cipher data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void rsa_oaep_sha384_encrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* public_key_bytes, const unsigned int public_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Decrypt data with rsa oaep sha512
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - private key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store decrypted data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void rsa_oaep_sha512_decrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* private_key_bytes, const unsigned int private_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Encrypt data with rsa oaep sha512
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param output_bytes - pointer to null byte array to store cipher data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void rsa_oaep_sha512_encrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* public_key_bytes, const unsigned int public_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Generate signature of data with rsa pss sha1
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to sign
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store signature data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void rsa_pss_sha1_sign(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* private_key_bytes, const unsigned int private_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Verify signature of data with rsa pss sha1
 *
 * @param input_bytes - byte array of data
 * @param input_size - size of 'input_bytes'
 * @param signature_bytes - byte array of signaturet
 * @param signature_size - size of 'signature_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param result - pointer to boolean to store result
 */
extern "C" CRYPTOPP_EXPORT void rsa_pss_sha1_verify(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* signature_bytes, const unsigned int signature_size, const CryptoPP::byte* public_key_bytes, const unsigned int public_key_size, bool* result);

/**
 * Generate signature of data with rsa pss sha224
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to sign
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store signature data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void rsa_pss_sha224_sign(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* private_key_bytes, const unsigned int private_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Verify signature of data with rsa pss sha224
 *
 * @param input_bytes - byte array of data
 * @param input_size - size of 'input_bytes'
 * @param signature_bytes - byte array of signaturet
 * @param signature_size - size of 'signature_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param result - pointer to boolean to store result
 */
extern "C" CRYPTOPP_EXPORT void rsa_pss_sha224_verify(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* signature_bytes, const unsigned int signature_size, const CryptoPP::byte* public_key_bytes, const unsigned int public_key_size, bool* result);

/**
 * Generate signature of data with rsa pss sha256
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to sign
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store signature data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void rsa_pss_sha256_sign(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* private_key_bytes, const unsigned int private_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Verify signature of data with rsa pss sha256
 *
 * @param input_bytes - byte array of data
 * @param input_size - size of 'input_bytes'
 * @param signature_bytes - byte array of signaturet
 * @param signature_size - size of 'signature_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param result - pointer to boolean to store result
 */
extern "C" CRYPTOPP_EXPORT void rsa_pss_sha256_verify(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* signature_bytes, const unsigned int signature_size, const CryptoPP::byte* public_key_bytes, const unsigned int public_key_size, bool* result);

/**
 * Generate signature of data with rsa pss sha384
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to sign
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store signature data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void rsa_pss_sha384_sign(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* private_key_bytes, const unsigned int private_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Verify signature of data with rsa pss sha384
 *
 * @param input_bytes - byte array of data
 * @param input_size - size of 'input_bytes'
 * @param signature_bytes - byte array of signaturet
 * @param signature_size - size of 'signature_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param result - pointer to boolean to store result
 */
extern "C" CRYPTOPP_EXPORT void rsa_pss_sha384_verify(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* signature_bytes, const unsigned int signature_size, const CryptoPP::byte* public_key_bytes, const unsigned int public_key_size, bool* result);

/**
 * Generate signature of data with rsa pss sha512
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to sign
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store signature data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void rsa_pss_sha512_sign(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* private_key_bytes, const unsigned int private_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Verify signature of data with rsa pss sha512
 *
 * @param input_bytes - byte array of data
 * @param input_size - size of 'input_bytes'
 * @param signature_bytes - byte array of signaturet
 * @param signature_size - size of 'signature_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param result - pointer to boolean to store result
 */
extern "C" CRYPTOPP_EXPORT void rsa_pss_sha512_verify(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* signature_bytes, const unsigned int signature_size, const CryptoPP::byte* public_key_bytes, const unsigned int public_key_size, bool* result);


/**
 * Generate signature of data with rsa pkcs v1 md2
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to sign
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - private key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store signature data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void rsa_md2_sign(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* private_key_bytes, const unsigned int private_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Verify signature of data with rsa pkcs v1 md2
 *
 * @param input_bytes - byte array of data
 * @param input_size - size of 'input_bytes'
 * @param signature_bytes - byte array of signaturet
 * @param signature_size - size of 'signature_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param result - pointer to boolean to store result
 */
extern "C" CRYPTOPP_EXPORT void rsa_md2_verify(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* signature_bytes, const unsigned int signature_size, const CryptoPP::byte* public_key_bytes, const unsigned int public_key_size, bool* result);

/**
 * Generate signature of data with rsa pkcs v1 md5
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to sign
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store signature data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void rsa_md5_sign(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* private_key_bytes, const unsigned int private_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Verify signature of data with rsa pkcs v1 md5
 *
 * @param input_bytes - byte array of data
 * @param input_size - size of 'input_bytes'
 * @param signature_bytes - byte array of signaturet
 * @param signature_size - size of 'signature_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param result - pointer to boolean to store result
 */
extern "C" CRYPTOPP_EXPORT void rsa_md5_verify(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* signature_bytes, const unsigned int signature_size, const CryptoPP::byte* public_key_bytes, const unsigned int public_key_size, bool* result);

/**
 * Generate signature of data with rsa pkcs v1 sha1
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to sign
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store signature data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void rsa_sha1_sign(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* private_key_bytes, const unsigned int private_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Verify signature of data with rsa pkcs v1 sha1
 *
 * @param input_bytes - byte array of data
 * @param input_size - size of 'input_bytes'
 * @param signature_bytes - byte array of signaturet
 * @param signature_size - size of 'signature_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param result - pointer to boolean to store result
 */
extern "C" CRYPTOPP_EXPORT void rsa_sha1_verify(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* signature_bytes, const unsigned int signature_size, const CryptoPP::byte* public_key_bytes, const unsigned int public_key_size, bool* result);

/**
 * Generate signature of data with rsa pkcs v1 sha224
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to sign
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store signature data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void rsa_sha224_sign(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* private_key_bytes, const unsigned int private_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Verify signature of data with rsa pkcs v1 sha224
 *
 * @param input_bytes - byte array of data
 * @param input_size - size of 'input_bytes'
 * @param signature_bytes - byte array of signaturet
 * @param signature_size - size of 'signature_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param result - pointer to boolean to store result
 */
extern "C" CRYPTOPP_EXPORT void rsa_sha224_verify(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* signature_bytes, const unsigned int signature_size, const CryptoPP::byte* public_key_bytes, const unsigned int public_key_size, bool* result);

/**
 * Generate signature of data with rsa pkcs v1 sha256
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to sign
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store signature data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void rsa_sha256_sign(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* private_key_bytes, const unsigned int private_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Verify signature of data with rsa pkcs v1 sha256
 *
 * @param input_bytes - byte array of data
 * @param input_size - size of 'input_bytes'
 * @param signature_bytes - byte array of signaturet
 * @param signature_size - size of 'signature_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param result - pointer to boolean to store result
 */
extern "C" CRYPTOPP_EXPORT void rsa_sha256_verify(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* signature_bytes, const unsigned int signature_size, const CryptoPP::byte* public_key_bytes, const unsigned int public_key_size, bool* result);

/**
 * Generate signature of data with rsa pkcs v1 sha384
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to sign
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store signature data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void rsa_sha384_sign(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* private_key_bytes, const unsigned int private_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Verify signature of data with rsa pkcs v1 sha384
 *
 * @param input_bytes - byte array of data
 * @param input_size - size of 'input_bytes'
 * @param signature_bytes - byte array of signaturet
 * @param signature_size - size of 'signature_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param result - pointer to boolean to store result
 */
extern "C" CRYPTOPP_EXPORT void rsa_sha384_verify(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* signature_bytes, const unsigned int signature_size, const CryptoPP::byte* public_key_bytes, const unsigned int public_key_size, bool* result);

/**
 * Generate signature of data with rsa pkcs v1 sha512
 *
 * @note Caller MUST delete 'output_bytes' with helper function 'delete_byte_array'
 *
 * @param input_bytes - byte array of data to sign
 * @param input_size - size of 'input_bytes'
 * @param private_key_bytes - key byte array
 * @param private_key_size - size of 'private_key_bytes'
 * @param output_bytes - pointer to null byte array to store signature data
 * @param output_size - pointer to unsigned integer to store 'output_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void rsa_sha512_sign(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* private_key_bytes, const unsigned int private_key_size, CryptoPP::byte** output_bytes, unsigned int* output_size);

/**
 * Verify signature of data with rsa pkcs v1 sha512
 *
 * @param input_bytes - byte array of data
 * @param input_size - size of 'input_bytes'
 * @param signature_bytes - byte array of signaturet
 * @param signature_size - size of 'signature_bytes'
 * @param public_key_bytes - public key byte array
 * @param public_key_size - size of 'public_key_bytes'
 * @param result - pointer to boolean to store result
 */
extern "C" CRYPTOPP_EXPORT void rsa_sha512_verify(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* signature_bytes, const unsigned int signature_size, const CryptoPP::byte* public_key_bytes, const unsigned int public_key_size, bool* result);

#pragma endregion

#pragma region salsa20

/**
 * Decrypt data with salsa20
 *
 * @note Caller MUST allocate for 'key_bytes' 16 or 32 bytes
 * @note Caller MUST allocate for 'iv_bytes' 8 bytes
 * @note Caller MUST allocate 'output_bytes' with size 'input_size'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param key_size - size of 'key_bytes'
 * @param iv_bytes - initialization vector byte array
 * @param output_bytes - pointer to byte array with defined size to store decrypted data
 */
extern "C" CRYPTOPP_EXPORT void salsa20_decrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* key_bytes, const unsigned int key_size, const CryptoPP::byte* iv_bytes, CryptoPP::byte** output_bytes);

/**
 * Encrypt data with salsa20
 *
 * @note Caller MUST allocate for 'key_bytes' 16 or 32 bytes
 * @note Caller MUST allocate for 'iv_bytes' 8 bytes
 * @note Caller MUST allocate 'output_bytes' with size 'input_size'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param key_size - size of 'key_bytes'
 * @param iv_bytes - initialization vector byte array
 * @param output_bytes - pointer to byte array with defined size to store cipher data
 */
extern "C" CRYPTOPP_EXPORT void salsa20_encrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* key_bytes, const unsigned int key_size, const CryptoPP::byte* iv_bytes, CryptoPP::byte** output_bytes);

#pragma endregion

#pragma region x25519

/**
 * Generate public and private keys
 *
 * @note Caller MUST delete 'private_key_bytes' with helper function 'delete_byte_array'
 * @note Caller MUST delete 'public_key_bytes' with helper function 'delete_byte_array'
 *
 * @param private_key_bytes - pointer to null byte array to store private key
 * @param private_key_size - pointer to unsigned integer to store 'private_key_bytes' size
 * @param public_key_bytes - pointer to null byte array to store public key
 * @param public_key_size - pointer to unsigned integer to store 'public_key_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void x25519_key_pair(CryptoPP::byte** private_key_bytes, unsigned int* private_key_size, CryptoPP::byte** public_key_bytes, unsigned int* public_key_size);

/**
 * Generate shared key
 *
 * @note Caller MUST delete 'shared_key_bytes' with helper function 'delete_byte_array'
 *
 * @param private_key_bytes - private key byte array
 * @param other_public_key_bytes - other public key byte array
 * @param shared_key_bytes - pointer to null byte array to store shared key
 * @param shared_key_size - pointer to unsigned integer to store 'shared_key_bytes' size
 */
extern "C" CRYPTOPP_EXPORT void x25519_shared_key(const CryptoPP::byte* private_key_bytes, const CryptoPP::byte* other_public_key_bytes, CryptoPP::byte** shared_key_bytes, unsigned int* shared_key_size);

#pragma endregion

#pragma region xsalsa20

/**
 * Decrypt data with xsalsa20
 *
 * @note Caller MUST allocate for 'key_bytes' 32 bytes
 * @note Caller MUST allocate for 'iv_bytes' 24 bytes
 * @note Caller MUST allocate 'output_bytes' with size 'input_size'
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param iv_bytes - initialization vector byte array
 * @param output_bytes - pointer to byte array with defined size to store decrypted data
 */
extern "C" CRYPTOPP_EXPORT void xsalsa20_decrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* key_bytes, const CryptoPP::byte* iv_bytes, CryptoPP::byte** output_bytes);

/**
 * Encrypt data with xsalsa20
 *
 * @note Caller MUST allocate for 'key_bytes' 32 bytes
 * @note Caller MUST allocate for 'iv_bytes' 24 bytes
 * @note Caller MUST allocate 'output_bytes' with size 'input_size'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param iv_bytes - initialization vector byte array
 * @param output_bytes - pointer to byte array with defined size to store cipher data
 */
extern "C" CRYPTOPP_EXPORT void xsalsa20_encrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* key_bytes, const CryptoPP::byte* iv_bytes, CryptoPP::byte** output_bytes);

/**
 * Decrypt data with xsalsa20 and verify poly1305 (IETF's variant) hash
 *
 * @note Caller MUST allocate for 'key_bytes' 32 bytes
 * @note Caller MUST allocate for 'iv_bytes' 24 bytes
 * @note Caller MUST allocate 'output_bytes' with size 'input_size - 16'
 * @note If verification fails, 'output_bytes' is zero-filled and 'verified' is set to false;
 *       callers MUST check 'verified' rather than assuming decryption succeeded
 * @note MAC comparison is performed in constant time
 *
 * @param input_bytes - byte array of cipher data
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param iv_bytes - initialization vector byte array
 * @param output_bytes - pointer to byte array with defined size to store decrypted data
 * @param verified - pointer to boolean to store whether the poly1305 hash matched (always true when 'verify' is false)
 * @param verify - define verification for poly1305 hash, default value = true
 */
extern "C" CRYPTOPP_EXPORT void xsalsa20_poly1305_tls_decrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* key_bytes, const CryptoPP::byte* iv_bytes, CryptoPP::byte** output_bytes, bool* verified, const bool verify);

/**
 * Encrypt data with xsalsa20 and calculate poly1305 (IETF's variant) hash
 *
 * @note Caller MUST allocate for 'key_bytes' 32 bytes
 * @note Caller MUST allocate for 'iv_bytes' 24 bytes
 * @note Caller MUST allocate 'output_bytes' with size 'input_size + 16'
 *
 * @param input_bytes - byte array of data to encrypt
 * @param input_size - size of 'input_bytes'
 * @param key_bytes - key byte array
 * @param iv_bytes - initialization vector byte array
 * @param output_bytes - pointer to byte array with defined size to store cipher data
 */
extern "C" CRYPTOPP_EXPORT void xsalsa20_poly1305_tls_encrypt(const CryptoPP::byte* input_bytes, const unsigned int input_size, const CryptoPP::byte* key_bytes, const CryptoPP::byte* iv_bytes, CryptoPP::byte** output_bytes);

#pragma endregion
