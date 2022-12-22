#include <ed25519-viper/ed25519.hpp>
#include <test/testing.hpp>

using namespace ed25519;

auto testKeyGen() -> void
{
    // Create a standard Ed25519 private key.
    auto key = PrivateKey::generate();
    TEST_ASSERT_THROW(key.isValid());
}

auto testExtendedKeyGen() -> void
{
    // Create an extended Ed25519 private key.
    auto ext_key = ExtendedPrivateKey::generate();
    TEST_ASSERT_THROW(ext_key.isValid());
}

auto testPublicKeyGen() -> void
{
    constexpr auto ext_prv_key_bytes =
        std::array<uint8_t, ED25519_EXTENDED_KEY_SIZE>{
            0x48, 0x4c, 0xc9, 0x24, 0x24, 0x16, 0x82, 0xbd, 0xc9, 0x8a, 0x7b,
            0x0b, 0xc4, 0x6f, 0xb9, 0x9c, 0x29, 0xc2, 0xca, 0xb7, 0x6f, 0xa6,
            0xc1, 0x37, 0x49, 0xab, 0x76, 0x0d, 0xfc, 0xfb, 0x63, 0x54, 0x8d,
            0xb8, 0x5e, 0xe5, 0xd4, 0x65, 0x38, 0x5c, 0xe6, 0x71, 0xe9, 0xc3,
            0xaa, 0x4e, 0x39, 0xf3, 0x18, 0x7a, 0xc2, 0x19, 0x94, 0x4d, 0xb1,
            0xeb, 0x75, 0xab, 0x0c, 0xc0, 0xdf, 0xb0, 0x3c, 0x77};
    constexpr auto ext_pub_key_bytes = std::array<uint8_t, ED25519_KEY_SIZE>{
        0xaf, 0x65, 0x50, 0xa2, 0x0d, 0x46, 0x89, 0xd5, 0x02, 0xb9, 0x42,
        0xb2, 0x5c, 0xad, 0xf4, 0xe9, 0xa9, 0xa4, 0x4c, 0xc5, 0xf4, 0xca,
        0x0d, 0xdf, 0x05, 0xf1, 0xf5, 0xb6, 0x24, 0x39, 0xd7, 0x69};

    const auto ext_prv_key = ExtendedPrivateKey(ext_prv_key_bytes);
    TEST_ASSERT_THROW(ext_prv_key.isValid());
    TEST_ASSERT_THROW(ext_prv_key.publicKey().bytes() == ext_pub_key_bytes);

    constexpr auto prv_key_bytes = std::array<uint8_t, ED25519_KEY_SIZE>{
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a,
        0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32,
        0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60};
    constexpr auto pub_key_bytes = std::array<uint8_t, ED25519_KEY_SIZE>{
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe,
        0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6,
        0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a};

    const auto prv_key = PrivateKey(prv_key_bytes);
    TEST_ASSERT_THROW(prv_key.isValid());
    TEST_ASSERT_THROW(prv_key.publicKey().bytes() == pub_key_bytes);
}

auto main() -> int
{
    testKeyGen();
    testExtendedKeyGen();
    testPublicKeyGen();
    return 0;
}