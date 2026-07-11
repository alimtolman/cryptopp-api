#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#pragma warning(disable: 6386)
#pragma warning(push, 0) 
#include "aes.h"
#include "blowfish.h"
#include "camellia.h"
#include "chacha.h"
#include "dh.h"
#include "ecp.h"
#include "eccrypto.h"
#include "filters.h"
#include "gcm.h"
#include "md2.h"
#include "md4.h"
#include "md5.h"
#include "modes.h"
#include "oids.h"
#include "osrng.h"
#include "poly1305.h"
#include "pwdbased.h"
#include "pssr.h"
#include "rsa.h"
#include "salsa.h"
#include "sha.h"
#include "xed25519.h"
#pragma warning(pop)

#include "main.h"

using namespace CryptoPP;

#pragma region helpers

void delete_byte_array(const byte* bytes) {
    delete[] bytes;
}

#pragma endregion

#pragma region aes

void aes_cbc_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, const unsigned int key_size, const byte* iv_bytes, byte** output_bytes, unsigned int* output_size, const bool zeros_padding = false) {
    std::string output_str = "";
    const BlockPaddingSchemeDef::BlockPaddingScheme padding = zeros_padding ? BlockPaddingSchemeDef::ZEROS_PADDING : BlockPaddingSchemeDef::PKCS_PADDING;

    CBC_Mode<AES>::Decryption engine(key_bytes, key_size, iv_bytes);
    StreamTransformationFilter stream(engine, new StringSink(output_str), padding);
    stream.Put(input_bytes, input_size);
    stream.MessageEnd();

    *output_size = static_cast<unsigned int>(output_str.size());
    *output_bytes = new byte[output_str.size()];

    for (unsigned int i = 0; i < output_str.size(); ++i)
        (*output_bytes)[i] = static_cast<byte>(output_str.at(i));
}

void aes_cbc_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, const unsigned int key_size, const byte* iv_bytes, byte** output_bytes, unsigned int* output_size, const bool zeros_padding = false) {
    std::string output_str = "";
    const BlockPaddingSchemeDef::BlockPaddingScheme padding = zeros_padding ? BlockPaddingSchemeDef::ZEROS_PADDING : BlockPaddingSchemeDef::PKCS_PADDING;

    CBC_Mode<AES>::Encryption engine(key_bytes, key_size, iv_bytes);
    StreamTransformationFilter stream(engine, new StringSink(output_str), padding);
    stream.Put(input_bytes, input_size);
    stream.MessageEnd();

    *output_size = static_cast<unsigned int>(output_str.size());
    *output_bytes = new byte[output_str.size()];

    for (unsigned int i = 0; i < output_str.size(); ++i)
        (*output_bytes)[i] = static_cast<byte>(output_str.at(i));
}

void aes_cfb_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, const unsigned int key_size, const byte* iv_bytes, byte** output_bytes) {
    std::string output_str = "";

    CFB_Mode<AES>::Decryption engine(key_bytes, key_size, iv_bytes);
    StreamTransformationFilter stream(engine, new StringSink(output_str), BlockPaddingSchemeDef::ZEROS_PADDING);
    stream.Put(input_bytes, input_size);
    stream.MessageEnd();

    for (unsigned int i = 0; i < output_str.size(); ++i)
        (*output_bytes)[i] = static_cast<byte>(output_str.at(i));
}

void aes_cfb_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, const unsigned int key_size, const byte* iv_bytes, byte** output_bytes) {
    std::string output_str = "";

    CFB_Mode<AES>::Encryption engine(key_bytes, key_size, iv_bytes);
    StreamTransformationFilter stream(engine, new StringSink(output_str), BlockPaddingSchemeDef::ZEROS_PADDING);
    stream.Put(input_bytes, input_size);
    stream.MessageEnd();

    for (unsigned int i = 0; i < output_str.size(); ++i)
        (*output_bytes)[i] = static_cast<byte>(output_str.at(i));
}

void aes_ctr_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, const unsigned int key_size, const byte* iv_bytes, byte** output_bytes) {
    std::string output_str = "";

    CTR_Mode<AES>::Decryption engine(key_bytes, key_size, iv_bytes);
    StreamTransformationFilter stream(engine, new StringSink(output_str));
    stream.Put(input_bytes, input_size);
    stream.MessageEnd();

    for (unsigned int i = 0; i < output_str.size(); ++i)
        (*output_bytes)[i] = static_cast<byte>(output_str.at(i));
}

void aes_ctr_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, const unsigned int key_size, const byte* iv_bytes, byte** output_bytes) {
    std::string output_str = "";

    CTR_Mode<AES>::Encryption engine(key_bytes, key_size, iv_bytes);
    StreamTransformationFilter stream(engine, new StringSink(output_str));
    stream.Put(input_bytes, input_size);
    stream.MessageEnd();

    for (unsigned int i = 0; i < output_str.size(); ++i)
        (*output_bytes)[i] = static_cast<byte>(output_str.at(i));
}

void aes_ecb_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, const unsigned int key_size, byte** output_bytes, unsigned int* output_size, const bool zeros_padding = false) {
    std::string output_str = "";
    const BlockPaddingSchemeDef::BlockPaddingScheme padding = zeros_padding ? BlockPaddingSchemeDef::ZEROS_PADDING : BlockPaddingSchemeDef::PKCS_PADDING;

    ECB_Mode<AES>::Decryption engine(key_bytes, key_size);
    StreamTransformationFilter stream(engine, new StringSink(output_str), padding);
    stream.Put(input_bytes, input_size);
    stream.MessageEnd();

    *output_size = static_cast<unsigned int>(output_str.size());
    *output_bytes = new byte[output_str.size()];

    for (unsigned int i = 0; i < output_str.size(); ++i)
        (*output_bytes)[i] = static_cast<byte>(output_str.at(i));
}

void aes_ecb_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, const unsigned int key_size, byte** output_bytes, unsigned int* output_size, const bool zeros_padding = false) {
    std::string output_str = "";
    const BlockPaddingSchemeDef::BlockPaddingScheme padding = zeros_padding ? BlockPaddingSchemeDef::ZEROS_PADDING : BlockPaddingSchemeDef::PKCS_PADDING;

    ECB_Mode<AES>::Encryption engine(key_bytes, key_size);
    StreamTransformationFilter stream(engine, new StringSink(output_str), padding);
    stream.Put(input_bytes, input_size);
    stream.MessageEnd();

    *output_size = static_cast<unsigned int>(output_str.size());
    *output_bytes = new byte[output_str.size()];

    for (unsigned int i = 0; i < output_str.size(); ++i)
        (*output_bytes)[i] = static_cast<byte>(output_str.at(i));
}

void aes_gcm_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, const unsigned int key_size, const byte* iv_bytes, const unsigned int iv_size, byte** output_bytes, unsigned int* output_size) {
    std::string output_str = "";
    int tag_size = 16;

    GCM<AES>::Decryption engine;
    engine.SetKeyWithIV(key_bytes, key_size, iv_bytes, iv_size);
    AuthenticatedEncryptionFilter stream(engine, new StringSink(output_str), false, tag_size);
    stream.ChannelPut("", input_bytes, input_size);
    stream.ChannelMessageEnd("");

    *output_size = static_cast<unsigned int>(output_str.size());
    *output_bytes = new byte[output_str.size()];

    for (unsigned int i = 0; i < output_str.size(); ++i)
        (*output_bytes)[i] = static_cast<byte>(output_str.at(i));
}

void aes_gcm_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, const unsigned int key_size, const byte* iv_bytes, const unsigned int iv_size, byte** output_bytes, unsigned int* output_size) {
    std::string output_str = "";
    int tag_size = 16;

    GCM<AES>::Encryption engine;
    engine.SetKeyWithIV(key_bytes, key_size, iv_bytes, iv_size);
    AuthenticatedEncryptionFilter stream(engine, new StringSink(output_str), false, tag_size);
    stream.ChannelPut("", input_bytes, input_size);
    stream.ChannelMessageEnd("");

    *output_size = static_cast<unsigned int>(output_str.size());
    *output_bytes = new byte[output_str.size()];

    for (unsigned int i = 0; i < output_str.size(); ++i)
        (*output_bytes)[i] = static_cast<byte>(output_str.at(i));
}

#pragma endregion

#pragma region big integer

void big_integer_add(const char* value_1_hex, const char* value_2_hex, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    Integer value_1(value_1_hex);
    Integer value_2(value_2_hex);
    Integer result = value_1 + value_2;

    result.Encode(buffer, result.ByteCount());

    *output_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *output_bytes = new byte[*output_size];

    buffer.Get(*output_bytes, *output_size);
}

void big_integer_mod(const char* value_1_hex, const char* value_2_hex, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    Integer value_1(value_1_hex);
    Integer value_2(value_2_hex);
    Integer result = value_1 % value_2;

    result.Encode(buffer, result.ByteCount());

    *output_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *output_bytes = new byte[*output_size];

    buffer.Get(*output_bytes, *output_size);
}

void big_integer_mod_pow(const char* value_hex, const char* exponent_hex, const char* modulus_hex, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    Integer value(value_hex);
    Integer exponent(exponent_hex);
    Integer modulus(modulus_hex);
    Integer result(1);

    value %= modulus;

    while (exponent > 0) {
        if ((exponent & 1) == 1)
            result = (result * value) % modulus;

        value = (value * value) % modulus;
        exponent >>= 1;
    }

    result.Encode(buffer, result.ByteCount());

    *output_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *output_bytes = new byte[*output_size];

    buffer.Get(*output_bytes, *output_size);
}

void big_integer_multiply(const char* value_1_hex, const char* value_2_hex, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    Integer value_1(value_1_hex);
    Integer value_2(value_2_hex);
    Integer result = value_1 * value_2;

    result.Encode(buffer, result.ByteCount());

    *output_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *output_bytes = new byte[*output_size];

    buffer.Get(*output_bytes, *output_size);
}

void big_integer_subtract(const char* value_1_hex, const char* value_2_hex, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    Integer value_1(value_1_hex);
    Integer value_2(value_2_hex);
    Integer result = value_1 - value_2;

    result.Encode(buffer, result.ByteCount());

    *output_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *output_bytes = new byte[*output_size];

    buffer.Get(*output_bytes, *output_size);
}

#pragma endregion

#pragma region blowfish

void blowfish_cbc_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, const unsigned int key_size, const byte* iv_bytes, byte** output_bytes, unsigned int* output_size) {
    std::string output_str = "";
    CBC_Mode<Blowfish>::Decryption engine(key_bytes, key_size, iv_bytes);
    StreamTransformationFilter stream(engine, new StringSink(output_str));
    stream.Put(input_bytes, input_size);
    stream.MessageEnd();

    *output_size = static_cast<unsigned int>(output_str.size());
    *output_bytes = new byte[output_str.size()];

    for (unsigned int i = 0; i < output_str.size(); ++i)
        (*output_bytes)[i] = static_cast<byte>(output_str.at(i));
}

void blowfish_cbc_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, const unsigned int key_size, const byte* iv_bytes, byte** output_bytes, unsigned int* output_size) {
    std::string output_str = "";
    CBC_Mode<Blowfish>::Encryption engine(key_bytes, key_size, iv_bytes);
    StreamTransformationFilter stream(engine, new StringSink(output_str));
    stream.Put(input_bytes, input_size);
    stream.MessageEnd();

    *output_size = static_cast<unsigned int>(output_str.size());
    *output_bytes = new byte[output_str.size()];

    for (unsigned int i = 0; i < output_str.size(); ++i)
        (*output_bytes)[i] = static_cast<byte>(output_str.at(i));
}

#pragma endregion

#pragma region camellia

void camellia_cbc_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, const unsigned int key_size, const byte* iv_bytes, byte** output_bytes, unsigned int* output_size) {
    std::string output_str = "";
    CBC_Mode<Camellia>::Decryption engine(key_bytes, key_size, iv_bytes);
    StreamTransformationFilter stream(engine, new StringSink(output_str));
    stream.Put(input_bytes, input_size);
    stream.MessageEnd();

    *output_size = static_cast<unsigned int>(output_str.size());
    *output_bytes = new byte[output_str.size()];

    for (unsigned int i = 0; i < output_str.size(); ++i)
        (*output_bytes)[i] = static_cast<byte>(output_str.at(i));
}

void camellia_cbc_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, const unsigned int key_size, const byte* iv_bytes, byte** output_bytes, unsigned int* output_size) {
    std::string output_str = "";
    CBC_Mode<Camellia>::Encryption engine(key_bytes, key_size, iv_bytes);
    StreamTransformationFilter stream(engine, new StringSink(output_str));
    stream.Put(input_bytes, input_size);
    stream.MessageEnd();

    *output_size = static_cast<unsigned int>(output_str.size());
    *output_bytes = new byte[output_str.size()];

    for (unsigned int i = 0; i < output_str.size(); ++i)
        (*output_bytes)[i] = static_cast<byte>(output_str.at(i));
}

#pragma endregion

#pragma region chacha20

void chacha20_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, const unsigned int key_size, const byte* iv_bytes, byte** output_bytes) {
    ChaCha::Decryption engine;

    engine.SetKeyWithIV(key_bytes, key_size, iv_bytes, ChaCha::IV_LENGTH);
    engine.ProcessData(*output_bytes, input_bytes, input_size);
}

void chacha20_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, const unsigned int key_size, const byte* iv_bytes, byte** output_bytes) {
    ChaCha::Encryption engine;

    engine.SetKeyWithIV(key_bytes, key_size, iv_bytes, ChaCha::IV_LENGTH);
    engine.ProcessData(*output_bytes, input_bytes, input_size);
}

#pragma endregion

#pragma region diffie-hellman

void dh_key_pair(const char* p_hex, const char* g_hex, byte** private_key_bytes, unsigned int* private_key_size, byte** public_key_bytes, unsigned int* public_key_size) {
    DH dh;
    AutoSeededRandomPool rng;
    Integer p(p_hex);
    Integer g(g_hex);

    dh.AccessGroupParameters().Initialize(p, g);

    *private_key_size = dh.PrivateKeyLength();
    *public_key_size = dh.PublicKeyLength();
    *private_key_bytes = new byte[*private_key_size];
    *public_key_bytes = new byte[*public_key_size];

    dh.GenerateKeyPair(rng, *private_key_bytes, *public_key_bytes);
}

void dh_shared_key(const char* p_hex, const char* g_hex, const byte* private_key_bytes, const byte* other_public_key_bytes, byte** shared_key_bytes, unsigned int* shared_key_size) {
    DH dh;
    Integer p(p_hex);
    Integer g(g_hex);

    dh.AccessGroupParameters().Initialize(p, g);

    *shared_key_size = dh.AgreedValueLength();
    *shared_key_bytes = new byte[*shared_key_size];

    dh.Agree(*shared_key_bytes, private_key_bytes, other_public_key_bytes);
}

#pragma endregion

#pragma region ecdh

void ecdh_key_pair(const byte elliptic_curve, byte** private_key_bytes, unsigned int* private_key_size, byte** public_key_bytes, unsigned int* public_key_size) {
    AutoSeededRandomPool rng;
    OID oid;

    switch (elliptic_curve) {
    case 1:
        oid = ASN1::secp256r1();
        break;
    case 2:
        oid = ASN1::secp384r1();
        break;
    case 3:
        oid = ASN1::secp521r1();
        break;
    default:
        oid = ASN1::secp256k1();
        break;
    }

    ECDH<ECP>::Domain ecdh(oid);

    *private_key_size = ecdh.PrivateKeyLength();
    *public_key_size = ecdh.PublicKeyLength();
    *private_key_bytes = new byte[*private_key_size];
    *public_key_bytes = new byte[*public_key_size];

    ecdh.GenerateKeyPair(rng, *private_key_bytes, *public_key_bytes);
}

void ecdh_shared_key(const byte elliptic_curve, const byte* private_key_bytes, const byte* other_public_key_bytes, byte** shared_key_bytes, unsigned int* shared_key_size) {
    AutoSeededRandomPool rng;
    OID oid;

    switch (elliptic_curve) {
    case 1:
        oid = ASN1::secp256r1();
        break;
    case 2:
        oid = ASN1::secp384r1();
        break;
    case 3:
        oid = ASN1::secp521r1();
        break;
    default:
        oid = ASN1::secp256k1();
        break;
    }

    ECDH<ECP>::Domain ecdh(oid);

    *shared_key_size = ecdh.AgreedValueLength();
    *shared_key_bytes = new byte[*shared_key_size];

    ecdh.Agree(*shared_key_bytes, private_key_bytes, other_public_key_bytes);
}

#pragma endregion

#pragma region ecdsa

void ecdsa_export_public_key(const byte* private_key_bytes, const unsigned int private_key_size, byte** public_key_bytes, unsigned int* public_key_size) {
    ByteQueue buffer;
    ECDSA<ECP, SHA256>::PrivateKey private_key;
    ECDSA<ECP, SHA256>::PublicKey public_key;

    buffer.Put(private_key_bytes, private_key_size);

    private_key.Load(buffer);
    private_key.MakePublicKey(public_key);

    buffer.Clear();
    public_key.Save(buffer);

    *public_key_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *public_key_bytes = new byte[*public_key_size];

    buffer.Get(*public_key_bytes, *public_key_size);
}

void ecdsa_key_pair(const byte elliptic_curve, byte** private_key_bytes, unsigned int* private_key_size, byte** public_key_bytes, unsigned int* public_key_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    ECDSA<ECP, SHA256>::PrivateKey private_key;
    ECDSA<ECP, SHA256>::PublicKey public_key;
    OID oid;

    switch (elliptic_curve) {
    case 1:
        oid = ASN1::secp256r1();
        break;
    case 2:
        oid = ASN1::secp384r1();
        break;
    case 3:
        oid = ASN1::secp521r1();
        break;
    default:
        oid = ASN1::secp256k1();
        break;
    }

    private_key.Initialize(rng, oid);
    private_key.MakePublicKey(public_key);
    private_key.Save(buffer);

    *private_key_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *private_key_bytes = new byte[*private_key_size];

    buffer.Get(*private_key_bytes, *private_key_size);

    buffer.Clear();
    public_key.Save(buffer);

    *public_key_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *public_key_bytes = new byte[*public_key_size];

    buffer.Get(*public_key_bytes, *public_key_size);
}

void ecdsa_sha1_sign(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    ECDSA<ECP, SHA1>::Signer signer;

    buffer.Put(private_key_bytes, private_key_size);
    signer.AccessKey().Load(buffer);

    *output_bytes = new byte[signer.MaxSignatureLength()];
    *output_size = static_cast<unsigned int>(signer.SignMessage(rng, input_bytes, input_size, *output_bytes));
}

void ecdsa_sha1_verify(const byte* input_bytes, const unsigned int input_size, const byte* signature_bytes, const unsigned int signature_size, const byte* public_key_bytes, const unsigned int public_key_size, bool* result) {
    ByteQueue buffer;
    ECDSA<ECP, SHA1>::Verifier verifier;

    buffer.Put(public_key_bytes, public_key_size);
    verifier.AccessKey().Load(buffer);

    *result = verifier.VerifyMessage(input_bytes, input_size, signature_bytes, signature_size);
}

void ecdsa_sha256_sign(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    ECDSA<ECP, SHA256>::Signer signer;

    buffer.Put(private_key_bytes, private_key_size);
    signer.AccessKey().Load(buffer);

    *output_bytes = new byte[signer.MaxSignatureLength()];
    *output_size = static_cast<unsigned int>(signer.SignMessage(rng, input_bytes, input_size, *output_bytes));
}

void ecdsa_sha256_verify(const byte* input_bytes, const unsigned int input_size, const byte* signature_bytes, const unsigned int signature_size, const byte* public_key_bytes, const unsigned int public_key_size, bool* result) {
    ByteQueue buffer;
    ECDSA<ECP, SHA256>::Verifier verifier;

    buffer.Put(public_key_bytes, public_key_size);
    verifier.AccessKey().Load(buffer);

    *result = verifier.VerifyMessage(input_bytes, input_size, signature_bytes, signature_size);
}

#pragma endregion

#pragma region ed25519

void ed25519_export_public_key(const byte* private_key_bytes, const unsigned int private_key_size, byte** public_key_bytes, unsigned int* public_key_size) {
    ByteQueue buffer;
    ed25519::Signer signer;

    buffer.Put(private_key_bytes, private_key_size);
    signer.AccessPrivateKey().Load(buffer);

    ed25519::Verifier verifier(signer);

    buffer.Clear();
    verifier.GetPublicKey().Save(buffer);

    *public_key_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *public_key_bytes = new byte[*public_key_size];

    buffer.Get(*public_key_bytes, *public_key_size);
}

void ed25519_key_pair(byte** private_key_bytes, unsigned int* private_key_size, byte** public_key_bytes, unsigned int* public_key_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    ed25519::Signer signer;

    signer.AccessPrivateKey().GenerateRandom(rng);
    signer.GetPrivateKey().Save(buffer);

    *private_key_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *private_key_bytes = new byte[*private_key_size];

    buffer.Get(*private_key_bytes, *private_key_size);

    ed25519::Verifier verifier(signer);

    buffer.Clear();
    verifier.GetPublicKey().Save(buffer);

    *public_key_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *public_key_bytes = new byte[*public_key_size];

    buffer.Get(*public_key_bytes, *public_key_size);
}

void ed25519_sign(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    ed25519::Signer signer;

    buffer.Put(private_key_bytes, private_key_size);
    signer.AccessPrivateKey().Load(buffer);

    *output_bytes = new byte[signer.MaxSignatureLength()];
    *output_size = static_cast<unsigned int>(signer.SignMessage(rng, input_bytes, input_size, *output_bytes));
}

void ed25519_verify(const byte* input_bytes, const unsigned int input_size, const byte* signature_bytes, const unsigned int signature_size, const byte* public_key_bytes, const unsigned int public_key_size, bool* result) {
    ByteQueue buffer;
    ed25519::Verifier verifier;

    buffer.Put(public_key_bytes, public_key_size);
    verifier.AccessPublicKey().Load(buffer);

    *result = verifier.VerifyMessage(input_bytes, input_size, signature_bytes, signature_size);
}

#pragma endregion

#pragma region hash

void md2(const byte* input_bytes, const unsigned int input_size, byte** output_bytes) {
    Weak::MD2().CalculateDigest(*output_bytes, input_bytes, input_size);
}

void md4(const byte* input_bytes, const unsigned int input_size, byte** output_bytes) {
    Weak::MD4().CalculateDigest(*output_bytes, input_bytes, input_size);
}

void md5(const byte* input_bytes, const unsigned int input_size, byte** output_bytes) {
    Weak::MD5().CalculateDigest(*output_bytes, input_bytes, input_size);
}

void poly1305_tls(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, byte** output_bytes) {
    Poly1305TLS mac;

    mac.SetKey(key_bytes, Poly1305TLS::KEYLENGTH);
    mac.Update(input_bytes, input_size);
    mac.Final(*output_bytes);
}

#pragma endregion

#pragma region pbkdf2

void pbkdf2_hmac_sha1(const byte* password_bytes, const unsigned int password_size, const byte* salt_bytes, const unsigned int salt_size, const unsigned int iterations_count, byte** output_bytes, const unsigned int output_size) {
    PKCS5_PBKDF2_HMAC<SHA1> pbkdf2;

    pbkdf2.DeriveKey(*output_bytes, output_size, 0, password_bytes, password_size, salt_bytes, salt_size, iterations_count);
}

void pbkdf2_hmac_sha256(const byte* password_bytes, const unsigned int password_size, const byte* salt_bytes, const unsigned int salt_size, const unsigned int iterations_count, byte** output_bytes, const unsigned int output_size) {
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf2;

    pbkdf2.DeriveKey(*output_bytes, output_size, 0, password_bytes, password_size, salt_bytes, salt_size, iterations_count);
}

void pbkdf2_hmac_sha512(const byte* password_bytes, const unsigned int password_size, const byte* salt_bytes, const unsigned int salt_size, const unsigned int iterations_count, byte** output_bytes, const unsigned int output_size) {
    PKCS5_PBKDF2_HMAC<SHA512> pbkdf2;

    pbkdf2.DeriveKey(*output_bytes, output_size, 0, password_bytes, password_size, salt_bytes, salt_size, iterations_count);
}

#pragma endregion

#pragma region rsa

void rsa_ecb_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSAES<PKCS1v15>::Decryptor decryptor;

    buffer.Put(private_key_bytes, private_key_size);
    decryptor.AccessKey().Load(buffer);
    buffer.Clear();

    unsigned int block_size = static_cast<unsigned int>(decryptor.FixedCiphertextLength());

    for (unsigned int i = 0; i < input_size; i += block_size) {
        unsigned int input_length = i + block_size > input_size ? input_size - i : block_size;
        unsigned int output_length = static_cast<unsigned int>(decryptor.MaxPlaintextLength(input_length));
        byte* output_block = new byte[output_length];
        output_length = static_cast<unsigned int>(decryptor.Decrypt(rng, &input_bytes[i], input_length, output_block).messageLength);

        buffer.Put(output_block, output_length);

        delete[] output_block;
    }

    *output_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *output_bytes = new byte[*output_size];

    buffer.Get(*output_bytes, *output_size);
}

void rsa_ecb_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* public_key_bytes, const unsigned int public_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSAES<PKCS1v15>::Encryptor encryptor;

    buffer.Put(public_key_bytes, public_key_size);
    encryptor.AccessKey().Load(buffer);
    buffer.Clear();

    unsigned int block_size = static_cast<unsigned int>(encryptor.FixedMaxPlaintextLength());
    unsigned int i = 0;
    
    // Empty plaintext is valid: still emit one padded ciphertext block.
    do {
        unsigned int input_length = i + block_size > input_size ? input_size - i : block_size;
        unsigned int output_length = static_cast<unsigned int>(encryptor.CiphertextLength(input_length));
        byte* output_block = new byte[output_length];

        encryptor.Encrypt(rng, input_length ? &input_bytes[i] : input_bytes, input_length, output_block);
        buffer.Put(output_block, output_length);

        delete[] output_block;

        if (input_size == 0)
            break;
        i += block_size;
    } while (i < input_size);

    *output_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *output_bytes = new byte[*output_size];

    buffer.Get(*output_bytes, *output_size);
}

void rsa_export_public_key(const byte* private_key_bytes, const unsigned int private_key_size, byte** public_key_bytes, unsigned int* public_key_size) {
    ByteQueue buffer;
    RSA::PrivateKey private_key;
    RSA::PublicKey public_key;

    buffer.Put(private_key_bytes, private_key_size);

    private_key.Load(buffer);
    public_key.Initialize(private_key.GetModulus(), private_key.GetPublicExponent());

    buffer.Clear();
    public_key.Save(buffer);

    *public_key_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *public_key_bytes = new byte[*public_key_size];

    buffer.Get(*public_key_bytes, *public_key_size);
}

void rsa_key_pair(const unsigned int key_size, byte** private_key_bytes, unsigned int* private_key_size, byte** public_key_bytes, unsigned int* public_key_size, const unsigned int exponent = 65537) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSA::PrivateKey private_key;
    RSA::PublicKey public_key;
    AlgorithmParameters params = MakeParameters(Name::KeySize(), (int)key_size)(Name::PublicExponent(), (int)exponent);

    private_key.GenerateRandom(rng, params);
    public_key.Initialize(private_key.GetModulus(), private_key.GetPublicExponent());
    private_key.Save(buffer);

    *private_key_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *private_key_bytes = new byte[*private_key_size];

    buffer.Get(*private_key_bytes, *private_key_size);

    buffer.Clear();
    public_key.Save(buffer);

    *public_key_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *public_key_bytes = new byte[*public_key_size];

    buffer.Get(*public_key_bytes, *public_key_size);
}

void rsa_no_padding_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSA::PrivateKey private_key;

    buffer.Put(private_key_bytes, private_key_size);
    private_key.Load(buffer);
    buffer.Clear();

    Integer decrypted = private_key.CalculateInverse(rng, Integer(input_bytes, input_size));

    decrypted.Encode(buffer, decrypted.ByteCount());

    *output_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *output_bytes = new byte[*output_size];

    buffer.Get(*output_bytes, *output_size);
}

void rsa_no_padding_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* public_key_bytes, const unsigned int public_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    RSA::PublicKey public_key;

    buffer.Put(public_key_bytes, public_key_size);
    public_key.Load(buffer);
    buffer.Clear();
    
    Integer plaintext = input_size ? Integer(input_bytes, input_size) : Integer(0);
    Integer encrypted = public_key.ApplyFunction(plaintext);

    encrypted.Encode(buffer, encrypted.ByteCount());

    *output_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *output_bytes = new byte[*output_size];

    buffer.Get(*output_bytes, *output_size);
}

void rsa_oaep_md2_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSAES<OAEP<Weak::MD2>>::Decryptor decryptor;

    buffer.Put(private_key_bytes, private_key_size);
    decryptor.AccessKey().Load(buffer);
    buffer.Clear();

    unsigned int block_size = static_cast<unsigned int>(decryptor.FixedCiphertextLength());

    for (unsigned int i = 0; i < input_size; i += block_size) {
        unsigned int input_length = i + block_size > input_size ? input_size - i : block_size;
        unsigned int output_length = static_cast<unsigned int>(decryptor.MaxPlaintextLength(input_length));
        byte* output_block = new byte[output_length];
        output_length = static_cast<unsigned int>(decryptor.Decrypt(rng, &input_bytes[i], input_length, output_block).messageLength);

        buffer.Put(output_block, output_length);

        delete[] output_block;
    }

    *output_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *output_bytes = new byte[*output_size];

    buffer.Get(*output_bytes, *output_size);
}

void rsa_oaep_md2_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* public_key_bytes, const unsigned int public_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSAES<OAEP<Weak::MD2>>::Encryptor encryptor;

    buffer.Put(public_key_bytes, public_key_size);
    encryptor.AccessKey().Load(buffer);
    buffer.Clear();

    unsigned int block_size = static_cast<unsigned int>(encryptor.FixedMaxPlaintextLength());
    unsigned int i = 0;
    
    // Empty plaintext is valid: still emit one padded ciphertext block.
    do {
        unsigned int input_length = i + block_size > input_size ? input_size - i : block_size;
        unsigned int output_length = static_cast<unsigned int>(encryptor.CiphertextLength(input_length));
        byte* output_block = new byte[output_length];

        encryptor.Encrypt(rng, input_length ? &input_bytes[i] : input_bytes, input_length, output_block);
        buffer.Put(output_block, output_length);

        delete[] output_block;

        if (input_size == 0)
            break;
        i += block_size;
    } while (i < input_size);

    *output_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *output_bytes = new byte[*output_size];

    buffer.Get(*output_bytes, *output_size);
}

void rsa_oaep_md4_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSAES<OAEP<Weak::MD4>>::Decryptor decryptor;

    buffer.Put(private_key_bytes, private_key_size);
    decryptor.AccessKey().Load(buffer);
    buffer.Clear();

    unsigned int block_size = static_cast<unsigned int>(decryptor.FixedCiphertextLength());

    for (unsigned int i = 0; i < input_size; i += block_size) {
        unsigned int input_length = i + block_size > input_size ? input_size - i : block_size;
        unsigned int output_length = static_cast<unsigned int>(decryptor.MaxPlaintextLength(input_length));
        byte* output_block = new byte[output_length];
        output_length = static_cast<unsigned int>(decryptor.Decrypt(rng, &input_bytes[i], input_length, output_block).messageLength);

        buffer.Put(output_block, output_length);

        delete[] output_block;
    }

    *output_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *output_bytes = new byte[*output_size];

    buffer.Get(*output_bytes, *output_size);
}

void rsa_oaep_md4_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* public_key_bytes, const unsigned int public_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSAES<OAEP<Weak::MD4>>::Encryptor encryptor;

    buffer.Put(public_key_bytes, public_key_size);
    encryptor.AccessKey().Load(buffer);
    buffer.Clear();

    unsigned int block_size = static_cast<unsigned int>(encryptor.FixedMaxPlaintextLength());
    unsigned int i = 0;
    
    // Empty plaintext is valid: still emit one padded ciphertext block.
    do {
        unsigned int input_length = i + block_size > input_size ? input_size - i : block_size;
        unsigned int output_length = static_cast<unsigned int>(encryptor.CiphertextLength(input_length));
        byte* output_block = new byte[output_length];

        encryptor.Encrypt(rng, input_length ? &input_bytes[i] : input_bytes, input_length, output_block);
        buffer.Put(output_block, output_length);

        delete[] output_block;

        if (input_size == 0)
            break;
        i += block_size;
    } while (i < input_size);

    *output_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *output_bytes = new byte[*output_size];

    buffer.Get(*output_bytes, *output_size);
}

void rsa_oaep_md5_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSAES<OAEP<Weak::MD5>>::Decryptor decryptor;

    buffer.Put(private_key_bytes, private_key_size);
    decryptor.AccessKey().Load(buffer);
    buffer.Clear();

    unsigned int block_size = static_cast<unsigned int>(decryptor.FixedCiphertextLength());

    for (unsigned int i = 0; i < input_size; i += block_size) {
        unsigned int input_length = i + block_size > input_size ? input_size - i : block_size;
        unsigned int output_length = static_cast<unsigned int>(decryptor.MaxPlaintextLength(input_length));
        byte* output_block = new byte[output_length];
        output_length = static_cast<unsigned int>(decryptor.Decrypt(rng, &input_bytes[i], input_length, output_block).messageLength);

        buffer.Put(output_block, output_length);

        delete[] output_block;
    }

    *output_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *output_bytes = new byte[*output_size];

    buffer.Get(*output_bytes, *output_size);
}

void rsa_oaep_md5_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* public_key_bytes, const unsigned int public_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSAES<OAEP<Weak::MD5>>::Encryptor encryptor;

    buffer.Put(public_key_bytes, public_key_size);
    encryptor.AccessKey().Load(buffer);
    buffer.Clear();

    unsigned int block_size = static_cast<unsigned int>(encryptor.FixedMaxPlaintextLength());
    unsigned int i = 0;
    
    // Empty plaintext is valid: still emit one padded ciphertext block.
    do {
        unsigned int input_length = i + block_size > input_size ? input_size - i : block_size;
        unsigned int output_length = static_cast<unsigned int>(encryptor.CiphertextLength(input_length));
        byte* output_block = new byte[output_length];

        encryptor.Encrypt(rng, input_length ? &input_bytes[i] : input_bytes, input_length, output_block);
        buffer.Put(output_block, output_length);

        delete[] output_block;

        if (input_size == 0)
            break;
        i += block_size;
    } while (i < input_size);

    *output_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *output_bytes = new byte[*output_size];

    buffer.Get(*output_bytes, *output_size);
}

void rsa_oaep_sha1_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSAES<OAEP<SHA1>>::Decryptor decryptor;

    buffer.Put(private_key_bytes, private_key_size);
    decryptor.AccessKey().Load(buffer);
    buffer.Clear();

    unsigned int block_size = static_cast<unsigned int>(decryptor.FixedCiphertextLength());

    for (unsigned int i = 0; i < input_size; i += block_size) {
        unsigned int input_length = i + block_size > input_size ? input_size - i : block_size;
        unsigned int output_length = static_cast<unsigned int>(decryptor.MaxPlaintextLength(input_length));
        byte* output_block = new byte[output_length];
        output_length = static_cast<unsigned int>(decryptor.Decrypt(rng, &input_bytes[i], input_length, output_block).messageLength);

        buffer.Put(output_block, output_length);

        delete[] output_block;
    }

    *output_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *output_bytes = new byte[*output_size];

    buffer.Get(*output_bytes, *output_size);
}

void rsa_oaep_sha1_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* public_key_bytes, const unsigned int public_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSAES<OAEP<SHA1>>::Encryptor encryptor;

    buffer.Put(public_key_bytes, public_key_size);
    encryptor.AccessKey().Load(buffer);
    buffer.Clear();

    unsigned int block_size = static_cast<unsigned int>(encryptor.FixedMaxPlaintextLength());
    unsigned int i = 0;
    
    // Empty plaintext is valid: still emit one padded ciphertext block.
    do {
        unsigned int input_length = i + block_size > input_size ? input_size - i : block_size;
        unsigned int output_length = static_cast<unsigned int>(encryptor.CiphertextLength(input_length));
        byte* output_block = new byte[output_length];

        encryptor.Encrypt(rng, input_length ? &input_bytes[i] : input_bytes, input_length, output_block);
        buffer.Put(output_block, output_length);

        delete[] output_block;

        if (input_size == 0)
            break;
        i += block_size;
    } while (i < input_size);

    *output_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *output_bytes = new byte[*output_size];

    buffer.Get(*output_bytes, *output_size);
}

void rsa_oaep_sha224_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSAES<OAEP<SHA224>>::Decryptor decryptor;

    buffer.Put(private_key_bytes, private_key_size);
    decryptor.AccessKey().Load(buffer);
    buffer.Clear();

    unsigned int block_size = static_cast<unsigned int>(decryptor.FixedCiphertextLength());

    for (unsigned int i = 0; i < input_size; i += block_size) {
        unsigned int input_length = i + block_size > input_size ? input_size - i : block_size;
        unsigned int output_length = static_cast<unsigned int>(decryptor.MaxPlaintextLength(input_length));
        byte* output_block = new byte[output_length];
        output_length = static_cast<unsigned int>(decryptor.Decrypt(rng, &input_bytes[i], input_length, output_block).messageLength);

        buffer.Put(output_block, output_length);

        delete[] output_block;
    }

    *output_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *output_bytes = new byte[*output_size];

    buffer.Get(*output_bytes, *output_size);
}

void rsa_oaep_sha224_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* public_key_bytes, const unsigned int public_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSAES<OAEP<SHA224>>::Encryptor encryptor;

    buffer.Put(public_key_bytes, public_key_size);
    encryptor.AccessKey().Load(buffer);
    buffer.Clear();

    unsigned int block_size = static_cast<unsigned int>(encryptor.FixedMaxPlaintextLength());
    unsigned int i = 0;
    
    // Empty plaintext is valid: still emit one padded ciphertext block.
    do {
        unsigned int input_length = i + block_size > input_size ? input_size - i : block_size;
        unsigned int output_length = static_cast<unsigned int>(encryptor.CiphertextLength(input_length));
        byte* output_block = new byte[output_length];

        encryptor.Encrypt(rng, input_length ? &input_bytes[i] : input_bytes, input_length, output_block);
        buffer.Put(output_block, output_length);

        delete[] output_block;

        if (input_size == 0)
            break;
        i += block_size;
    } while (i < input_size);

    *output_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *output_bytes = new byte[*output_size];

    buffer.Get(*output_bytes, *output_size);
}

void rsa_oaep_sha256_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSAES<OAEP<SHA256>>::Decryptor decryptor;

    buffer.Put(private_key_bytes, private_key_size);
    decryptor.AccessKey().Load(buffer);
    buffer.Clear();

    unsigned int block_size = static_cast<unsigned int>(decryptor.FixedCiphertextLength());

    for (unsigned int i = 0; i < input_size; i += block_size) {
        unsigned int input_length = i + block_size > input_size ? input_size - i : block_size;
        unsigned int output_length = static_cast<unsigned int>(decryptor.MaxPlaintextLength(input_length));
        byte* output_block = new byte[output_length];
        output_length = static_cast<unsigned int>(decryptor.Decrypt(rng, &input_bytes[i], input_length, output_block).messageLength);

        buffer.Put(output_block, output_length);

        delete[] output_block;
    }

    *output_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *output_bytes = new byte[*output_size];

    buffer.Get(*output_bytes, *output_size);
}

void rsa_oaep_sha256_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* public_key_bytes, const unsigned int public_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSAES<OAEP<SHA256>>::Encryptor encryptor;

    buffer.Put(public_key_bytes, public_key_size);
    encryptor.AccessKey().Load(buffer);
    buffer.Clear();

    unsigned int block_size = static_cast<unsigned int>(encryptor.FixedMaxPlaintextLength());
    unsigned int i = 0;
    
    // Empty plaintext is valid: still emit one padded ciphertext block.
    do {
        unsigned int input_length = i + block_size > input_size ? input_size - i : block_size;
        unsigned int output_length = static_cast<unsigned int>(encryptor.CiphertextLength(input_length));
        byte* output_block = new byte[output_length];

        encryptor.Encrypt(rng, input_length ? &input_bytes[i] : input_bytes, input_length, output_block);
        buffer.Put(output_block, output_length);

        delete[] output_block;

        if (input_size == 0)
            break;
        i += block_size;
    } while (i < input_size);

    *output_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *output_bytes = new byte[*output_size];

    buffer.Get(*output_bytes, *output_size);
}

void rsa_oaep_sha384_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSAES<OAEP<SHA384>>::Decryptor decryptor;

    buffer.Put(private_key_bytes, private_key_size);
    decryptor.AccessKey().Load(buffer);
    buffer.Clear();

    unsigned int block_size = static_cast<unsigned int>(decryptor.FixedCiphertextLength());

    for (unsigned int i = 0; i < input_size; i += block_size) {
        unsigned int input_length = i + block_size > input_size ? input_size - i : block_size;
        unsigned int output_length = static_cast<unsigned int>(decryptor.MaxPlaintextLength(input_length));
        byte* output_block = new byte[output_length];
        output_length = static_cast<unsigned int>(decryptor.Decrypt(rng, &input_bytes[i], input_length, output_block).messageLength);

        buffer.Put(output_block, output_length);

        delete[] output_block;
    }

    *output_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *output_bytes = new byte[*output_size];

    buffer.Get(*output_bytes, *output_size);
}

void rsa_oaep_sha384_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* public_key_bytes, const unsigned int public_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSAES<OAEP<SHA384>>::Encryptor encryptor;

    buffer.Put(public_key_bytes, public_key_size);
    encryptor.AccessKey().Load(buffer);
    buffer.Clear();

    unsigned int block_size = static_cast<unsigned int>(encryptor.FixedMaxPlaintextLength());
    unsigned int i = 0;
    
    // Empty plaintext is valid: still emit one padded ciphertext block.
    do {
        unsigned int input_length = i + block_size > input_size ? input_size - i : block_size;
        unsigned int output_length = static_cast<unsigned int>(encryptor.CiphertextLength(input_length));
        byte* output_block = new byte[output_length];

        encryptor.Encrypt(rng, input_length ? &input_bytes[i] : input_bytes, input_length, output_block);
        buffer.Put(output_block, output_length);

        delete[] output_block;

        if (input_size == 0)
            break;
        i += block_size;
    } while (i < input_size);

    *output_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *output_bytes = new byte[*output_size];

    buffer.Get(*output_bytes, *output_size);
}

void rsa_oaep_sha512_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSAES<OAEP<SHA512>>::Decryptor decryptor;

    buffer.Put(private_key_bytes, private_key_size);
    decryptor.AccessKey().Load(buffer);
    buffer.Clear();

    unsigned int block_size = static_cast<unsigned int>(decryptor.FixedCiphertextLength());

    for (unsigned int i = 0; i < input_size; i += block_size) {
        unsigned int input_length = i + block_size > input_size ? input_size - i : block_size;
        unsigned int output_length = static_cast<unsigned int>(decryptor.MaxPlaintextLength(input_length));
        byte* output_block = new byte[output_length];
        output_length = static_cast<unsigned int>(decryptor.Decrypt(rng, &input_bytes[i], input_length, output_block).messageLength);

        buffer.Put(output_block, output_length);

        delete[] output_block;
    }

    *output_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *output_bytes = new byte[*output_size];

    buffer.Get(*output_bytes, *output_size);
}

void rsa_oaep_sha512_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* public_key_bytes, const unsigned int public_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSAES<OAEP<SHA512>>::Encryptor encryptor;

    buffer.Put(public_key_bytes, public_key_size);
    encryptor.AccessKey().Load(buffer);
    buffer.Clear();

    unsigned int block_size = static_cast<unsigned int>(encryptor.FixedMaxPlaintextLength());
    unsigned int i = 0;
    
    // Empty plaintext is valid: still emit one padded ciphertext block.
    do {
        unsigned int input_length = i + block_size > input_size ? input_size - i : block_size;
        unsigned int output_length = static_cast<unsigned int>(encryptor.CiphertextLength(input_length));
        byte* output_block = new byte[output_length];

        encryptor.Encrypt(rng, input_length ? &input_bytes[i] : input_bytes, input_length, output_block);
        buffer.Put(output_block, output_length);

        delete[] output_block;

        if (input_size == 0)
            break;
        i += block_size;
    } while (i < input_size);

    *output_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *output_bytes = new byte[*output_size];

    buffer.Get(*output_bytes, *output_size);
}

void rsa_pss_sha1_sign(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSASS<PSS, SHA1>::Signer signer;

    buffer.Put(private_key_bytes, private_key_size);
    signer.AccessKey().Load(buffer);

    *output_bytes = new byte[signer.MaxSignatureLength()];
    *output_size = static_cast<unsigned int>(signer.SignMessage(rng, input_bytes, input_size, *output_bytes));
}

void rsa_pss_sha1_verify(const byte* input_bytes, const unsigned int input_size, const byte* signature_bytes, const unsigned int signature_size, const byte* public_key_bytes, const unsigned int public_key_size, bool* result) {
    ByteQueue buffer;
    RSASS<PSS, SHA1>::Verifier verifier;

    buffer.Put(public_key_bytes, public_key_size);
    verifier.AccessKey().Load(buffer);

    *result = verifier.VerifyMessage(input_bytes, input_size, signature_bytes, signature_size);
}

void rsa_pss_sha224_sign(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSASS<PSS, SHA224>::Signer signer;

    buffer.Put(private_key_bytes, private_key_size);
    signer.AccessKey().Load(buffer);

    *output_bytes = new byte[signer.MaxSignatureLength()];
    *output_size = static_cast<unsigned int>(signer.SignMessage(rng, input_bytes, input_size, *output_bytes));
}

void rsa_pss_sha224_verify(const byte* input_bytes, const unsigned int input_size, const byte* signature_bytes, const unsigned int signature_size, const byte* public_key_bytes, const unsigned int public_key_size, bool* result) {
    ByteQueue buffer;
    RSASS<PSS, SHA224>::Verifier verifier;

    buffer.Put(public_key_bytes, public_key_size);
    verifier.AccessKey().Load(buffer);

    *result = verifier.VerifyMessage(input_bytes, input_size, signature_bytes, signature_size);
}

void rsa_pss_sha256_sign(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSASS<PSS, SHA256>::Signer signer;

    buffer.Put(private_key_bytes, private_key_size);
    signer.AccessKey().Load(buffer);

    *output_bytes = new byte[signer.MaxSignatureLength()];
    *output_size = static_cast<unsigned int>(signer.SignMessage(rng, input_bytes, input_size, *output_bytes));
}

void rsa_pss_sha256_verify(const byte* input_bytes, const unsigned int input_size, const byte* signature_bytes, const unsigned int signature_size, const byte* public_key_bytes, const unsigned int public_key_size, bool* result) {
    ByteQueue buffer;
    RSASS<PSS, SHA256>::Verifier verifier;

    buffer.Put(public_key_bytes, public_key_size);
    verifier.AccessKey().Load(buffer);

    *result = verifier.VerifyMessage(input_bytes, input_size, signature_bytes, signature_size);
}

void rsa_pss_sha384_sign(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSASS<PSS, SHA384>::Signer signer;

    buffer.Put(private_key_bytes, private_key_size);
    signer.AccessKey().Load(buffer);

    *output_bytes = new byte[signer.MaxSignatureLength()];
    *output_size = static_cast<unsigned int>(signer.SignMessage(rng, input_bytes, input_size, *output_bytes));
}

void rsa_pss_sha384_verify(const byte* input_bytes, const unsigned int input_size, const byte* signature_bytes, const unsigned int signature_size, const byte* public_key_bytes, const unsigned int public_key_size, bool* result) {
    ByteQueue buffer;
    RSASS<PSS, SHA384>::Verifier verifier;

    buffer.Put(public_key_bytes, public_key_size);
    verifier.AccessKey().Load(buffer);

    *result = verifier.VerifyMessage(input_bytes, input_size, signature_bytes, signature_size);
}

void rsa_pss_sha512_sign(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSASS<PSS, SHA512>::Signer signer;

    buffer.Put(private_key_bytes, private_key_size);
    signer.AccessKey().Load(buffer);

    *output_bytes = new byte[signer.MaxSignatureLength()];
    *output_size = static_cast<unsigned int>(signer.SignMessage(rng, input_bytes, input_size, *output_bytes));
}

void rsa_pss_sha512_verify(const byte* input_bytes, const unsigned int input_size, const byte* signature_bytes, const unsigned int signature_size, const byte* public_key_bytes, const unsigned int public_key_size, bool* result) {
    ByteQueue buffer;
    RSASS<PSS, SHA512>::Verifier verifier;

    buffer.Put(public_key_bytes, public_key_size);
    verifier.AccessKey().Load(buffer);

    *result = verifier.VerifyMessage(input_bytes, input_size, signature_bytes, signature_size);
}

void rsa_md2_sign(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSASS<PKCS1v15, Weak::MD2>::Signer signer;

    buffer.Put(private_key_bytes, private_key_size);
    signer.AccessKey().Load(buffer);

    *output_bytes = new byte[signer.MaxSignatureLength()];
    *output_size = static_cast<unsigned int>(signer.SignMessage(rng, input_bytes, input_size, *output_bytes));
}

void rsa_md2_verify(const byte* input_bytes, const unsigned int input_size, const byte* signature_bytes, const unsigned int signature_size, const byte* public_key_bytes, const unsigned int public_key_size, bool* result) {
    ByteQueue buffer;
    RSASS<PKCS1v15, Weak::MD2>::Verifier verifier;

    buffer.Put(public_key_bytes, public_key_size);
    verifier.AccessKey().Load(buffer);

    *result = verifier.VerifyMessage(input_bytes, input_size, signature_bytes, signature_size);
}

void rsa_md5_sign(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSASS<PKCS1v15, Weak::MD5>::Signer signer;

    buffer.Put(private_key_bytes, private_key_size);
    signer.AccessKey().Load(buffer);

    *output_bytes = new byte[signer.MaxSignatureLength()];
    *output_size = static_cast<unsigned int>(signer.SignMessage(rng, input_bytes, input_size, *output_bytes));
}

void rsa_md5_verify(const byte* input_bytes, const unsigned int input_size, const byte* signature_bytes, const unsigned int signature_size, const byte* public_key_bytes, const unsigned int public_key_size, bool* result) {
    ByteQueue buffer;
    RSASS<PKCS1v15, Weak::MD5>::Verifier verifier;

    buffer.Put(public_key_bytes, public_key_size);
    verifier.AccessKey().Load(buffer);

    *result = verifier.VerifyMessage(input_bytes, input_size, signature_bytes, signature_size);
}

void rsa_sha1_sign(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSASS<PKCS1v15, SHA1>::Signer signer;

    buffer.Put(private_key_bytes, private_key_size);
    signer.AccessKey().Load(buffer);

    *output_bytes = new byte[signer.MaxSignatureLength()];
    *output_size = static_cast<unsigned int>(signer.SignMessage(rng, input_bytes, input_size, *output_bytes));
}

void rsa_sha1_verify(const byte* input_bytes, const unsigned int input_size, const byte* signature_bytes, const unsigned int signature_size, const byte* public_key_bytes, const unsigned int public_key_size, bool* result) {
    ByteQueue buffer;
    RSASS<PKCS1v15, SHA1>::Verifier verifier;

    buffer.Put(public_key_bytes, public_key_size);
    verifier.AccessKey().Load(buffer);

    *result = verifier.VerifyMessage(input_bytes, input_size, signature_bytes, signature_size);
}

void rsa_sha224_sign(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSASS<PKCS1v15, SHA224>::Signer signer;

    buffer.Put(private_key_bytes, private_key_size);
    signer.AccessKey().Load(buffer);

    *output_bytes = new byte[signer.MaxSignatureLength()];
    *output_size = static_cast<unsigned int>(signer.SignMessage(rng, input_bytes, input_size, *output_bytes));
}

void rsa_sha224_verify(const byte* input_bytes, const unsigned int input_size, const byte* signature_bytes, const unsigned int signature_size, const byte* public_key_bytes, const unsigned int public_key_size, bool* result) {
    ByteQueue buffer;
    RSASS<PKCS1v15, SHA224>::Verifier verifier;

    buffer.Put(public_key_bytes, public_key_size);
    verifier.AccessKey().Load(buffer);

    *result = verifier.VerifyMessage(input_bytes, input_size, signature_bytes, signature_size);
}

void rsa_sha256_sign(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSASS<PKCS1v15, SHA256>::Signer signer;

    buffer.Put(private_key_bytes, private_key_size);
    signer.AccessKey().Load(buffer);

    *output_bytes = new byte[signer.MaxSignatureLength()];
    *output_size = static_cast<unsigned int>(signer.SignMessage(rng, input_bytes, input_size, *output_bytes));
}

void rsa_sha256_verify(const byte* input_bytes, const unsigned int input_size, const byte* signature_bytes, const unsigned int signature_size, const byte* public_key_bytes, const unsigned int public_key_size, bool* result) {
    ByteQueue buffer;
    RSASS<PKCS1v15, SHA256>::Verifier verifier;

    buffer.Put(public_key_bytes, public_key_size);
    verifier.AccessKey().Load(buffer);

    *result = verifier.VerifyMessage(input_bytes, input_size, signature_bytes, signature_size);
}

void rsa_sha384_sign(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSASS<PKCS1v15, SHA384>::Signer signer;

    buffer.Put(private_key_bytes, private_key_size);
    signer.AccessKey().Load(buffer);

    *output_bytes = new byte[signer.MaxSignatureLength()];
    *output_size = static_cast<unsigned int>(signer.SignMessage(rng, input_bytes, input_size, *output_bytes));
}

void rsa_sha384_verify(const byte* input_bytes, const unsigned int input_size, const byte* signature_bytes, const unsigned int signature_size, const byte* public_key_bytes, const unsigned int public_key_size, bool* result) {
    ByteQueue buffer;
    RSASS<PKCS1v15, SHA384>::Verifier verifier;

    buffer.Put(public_key_bytes, public_key_size);
    verifier.AccessKey().Load(buffer);

    *result = verifier.VerifyMessage(input_bytes, input_size, signature_bytes, signature_size);
}

void rsa_sha512_sign(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSASS<PKCS1v15, SHA512>::Signer signer;

    buffer.Put(private_key_bytes, private_key_size);
    signer.AccessKey().Load(buffer);

    *output_bytes = new byte[signer.MaxSignatureLength()];
    *output_size = static_cast<unsigned int>(signer.SignMessage(rng, input_bytes, input_size, *output_bytes));
}

void rsa_sha512_verify(const byte* input_bytes, const unsigned int input_size, const byte* signature_bytes, const unsigned int signature_size, const byte* public_key_bytes, const unsigned int public_key_size, bool* result) {
    ByteQueue buffer;
    RSASS<PKCS1v15, SHA512>::Verifier verifier;

    buffer.Put(public_key_bytes, public_key_size);
    verifier.AccessKey().Load(buffer);

    *result = verifier.VerifyMessage(input_bytes, input_size, signature_bytes, signature_size);
}

#pragma endregion

#pragma region salsa20

void salsa20_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, const unsigned int key_size, const byte* iv_bytes, byte** output_bytes) {
    Salsa20::Decryption engine;

    engine.SetKeyWithIV(key_bytes, key_size, iv_bytes, Salsa20::IV_LENGTH);
    engine.ProcessData(*output_bytes, input_bytes, input_size);
}

void salsa20_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, const unsigned int key_size, const byte* iv_bytes, byte** output_bytes) {
    Salsa20::Encryption engine;

    engine.SetKeyWithIV(key_bytes, key_size, iv_bytes, Salsa20::IV_LENGTH);
    engine.ProcessData(*output_bytes, input_bytes, input_size);
}

#pragma endregion

#pragma region x25519

void x25519_key_pair(byte** private_key_bytes, unsigned int* private_key_size, byte** public_key_bytes, unsigned int* public_key_size) {
    AutoSeededRandomPool rng;
    x25519 kex;

    *private_key_size = x25519::SECRET_KEYLENGTH;
    *public_key_size = x25519::PUBLIC_KEYLENGTH;
    *private_key_bytes = new byte[*private_key_size];
    *public_key_bytes = new byte[*public_key_size];

    kex.GeneratePrivateKey(rng, *private_key_bytes);
    kex.GeneratePublicKey(rng, *private_key_bytes, *public_key_bytes);
}

void x25519_shared_key(const byte* private_key_bytes, const byte* other_public_key_bytes, byte** shared_key_bytes, unsigned int* shared_key_size) {
    x25519 kex;

    *shared_key_size = x25519::SHARED_KEYLENGTH;
    *shared_key_bytes = new byte[*shared_key_size];

    if (!kex.Agree(*shared_key_bytes, private_key_bytes, other_public_key_bytes))
        memset(*shared_key_bytes, 0, *shared_key_size);
}

#pragma endregion

#pragma region xsalsa20

void xsalsa20_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, const byte* iv_bytes, byte** output_bytes) {
    XSalsa20::Decryption engine;

    engine.SetKeyWithIV(key_bytes, XSalsa20::KEYLENGTH, iv_bytes, XSalsa20::IV_LENGTH);
    engine.ProcessData(*output_bytes, input_bytes, input_size);
}

void xsalsa20_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, const byte* iv_bytes, byte** output_bytes) {
    XSalsa20::Encryption engine;

    engine.SetKeyWithIV(key_bytes, XSalsa20::KEYLENGTH, iv_bytes, XSalsa20::IV_LENGTH);
    engine.ProcessData(*output_bytes, input_bytes, input_size);
}

void xsalsa20_poly1305_tls_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, const byte* iv_bytes, byte** output_bytes, bool* verified, const bool verify = true) {
    const unsigned int encrypted_size = input_size - Poly1305TLS::DIGESTSIZE;
    byte* encrypted_bytes = new byte[encrypted_size];
    byte* main_hash_bytes = new byte[Poly1305TLS::DIGESTSIZE];
    byte* other_hash_bytes = new byte[Poly1305TLS::DIGESTSIZE];
    byte sub_key_bytes[Poly1305TLS::KEYLENGTH] = {};

    memcpy(encrypted_bytes, input_bytes + Poly1305TLS::DIGESTSIZE, encrypted_size);
    memcpy(other_hash_bytes, input_bytes, Poly1305TLS::DIGESTSIZE);

    XSalsa20::Decryption engine;

    engine.SetKeyWithIV(key_bytes, XSalsa20::KEYLENGTH, iv_bytes, XSalsa20::IV_LENGTH);
    engine.ProcessData(sub_key_bytes, sub_key_bytes, Poly1305TLS::KEYLENGTH);

    *verified = true;

    if (verify) {
        poly1305_tls(encrypted_bytes, encrypted_size, sub_key_bytes, &main_hash_bytes);
        // Constant-time comparison to avoid leaking MAC-matching progress via timing.
        *verified = VerifyBufsEqual(main_hash_bytes, other_hash_bytes, Poly1305TLS::DIGESTSIZE);
    }

    if (*verified)
        engine.ProcessData(*output_bytes, encrypted_bytes, encrypted_size);
    else
        memset(*output_bytes, 0, encrypted_size);

    delete[] encrypted_bytes;
    delete[] main_hash_bytes;
    delete[] other_hash_bytes;
}

void xsalsa20_poly1305_tls_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, const byte* iv_bytes, byte** output_bytes) {
    byte* encrypted_bytes = new byte[input_size];
    byte* hash_bytes = new byte[Poly1305TLS::DIGESTSIZE];
    byte sub_key_bytes[Poly1305TLS::KEYLENGTH] = {};

    XSalsa20::Encryption engine;

    engine.SetKeyWithIV(key_bytes, XSalsa20::KEYLENGTH, iv_bytes, XSalsa20::IV_LENGTH);
    engine.ProcessData(sub_key_bytes, sub_key_bytes, Poly1305TLS::KEYLENGTH);
    engine.ProcessData(encrypted_bytes, input_bytes, input_size);

    poly1305_tls(encrypted_bytes, input_size, sub_key_bytes, &hash_bytes);

    memcpy(*output_bytes, hash_bytes, Poly1305TLS::DIGESTSIZE);
    memcpy(*output_bytes + Poly1305TLS::DIGESTSIZE, encrypted_bytes, input_size);

    delete[] encrypted_bytes;
    delete[] hash_bytes;
}

#pragma endregion
