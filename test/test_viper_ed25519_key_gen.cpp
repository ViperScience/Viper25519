#include <ed25519-viper/ed25519.hpp>
#include <test/testing.hpp>

auto testKeyGen() -> void
{
    // Create a standard Ed25519 private key.
    auto key = ed25519::PrivateKey::generate();
    TEST_ASSERT_THROW(key.isValid());
}

auto testExtendedKeyGen() -> void
{
    // Create an extended Ed25519 private key.
    auto ext_key = ed25519::ExtendedPrivateKey::generate();
    TEST_ASSERT_THROW(ext_key.isValid());
}

auto main() -> int
{
    testKeyGen();
    testExtendedKeyGen();
}