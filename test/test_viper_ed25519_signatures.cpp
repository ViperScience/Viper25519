#include <ed25519-viper/ed25519.hpp>
#include <test/testing.hpp>

using namespace ed25519;

auto testBasic() -> void
{
    constexpr auto prv_key_bytes = std::array<uint8_t, ED25519_KEY_SIZE>{
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a,
        0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32,
        0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60};
    constexpr auto sig_bytes = std::array<uint8_t, ED25519_SIGNATURE_SIZE>{
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2,
        0xcc, 0x80, 0x6e, 0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5,
        0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55, 0x5f,
        0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70,
        0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe,
        0x24, 0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b};

    const auto prv_key = PrivateKey(prv_key_bytes);
    TEST_ASSERT_THROW(prv_key.isValid())

    // Test signing an empty message
    auto msg = std::vector<uint8_t>{};
    auto sig = prv_key.sign(msg);
    TEST_ASSERT_THROW(sig == sig_bytes)
}

auto testAdvanced() -> void { TEST_ASSERT_THROW(true) }

auto main() -> int
{
    testBasic();
    testAdvanced();
    return 0;
}