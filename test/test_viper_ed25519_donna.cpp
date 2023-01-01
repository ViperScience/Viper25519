// Repeat tests defined at
// https://github.com/floodyberry/ed25519-donna/blob/master/test.c

#include <ed25519-viper/curve25519.hpp>
#include <ed25519-viper/ed25519.hpp>
#include <test/testing.hpp>

auto testBasepoint() -> void
{
    // result of the curve25519 scalarmult ((|255| * basepoint) * basepoint)...
    // 1024 times
    static constexpr auto curved25519_expected = std::array<uint8_t, 32>{
        0xac, 0xce, 0x24, 0xb1, 0xd4, 0xa2, 0x36, 0x21, 0x15, 0xe2, 0x3e,
        0x84, 0x3c, 0x23, 0x2b, 0x5f, 0x95, 0x6c, 0xc0, 0x7b, 0x95, 0x82,
        0xd7, 0x93, 0xd5, 0x19, 0xb6, 0xf1, 0xfb, 0x96, 0xd6, 0x04};

    auto csk = std::array<std::array<uint8_t, 32>, 2>{{{255}}};

    for (uint32_t i = 0; i < 1024; i++)
        csk[(i & 1) ^ 1] = curve25519::scalarmult_basepoint(csk[i & 1]);

    TEST_ASSERT_THROW(csk[0] == curved25519_expected)
}

auto testAdvanced() -> void
{
    // test data
    typedef struct test_data_t
    {
        unsigned char sk[32], pk[32], sig[64];
        const char *m;
    } test_data;
    test_data dataset[] = {
#include "regression_data.txt"
    };

    for (auto i = 0UL; i < 1024; i++)
    {
        auto sk = ed25519::PrivateKey({dataset[i].sk, 32});
        auto pk = sk.publicKey();

        // Not all the keys in the regression tests are valid according to this
        // library since they do not enforce the cleared bit,
        // i.e., keyhash[31] & 0b00100000 == 0.
        if (!sk.isValid()) continue;
        // Only 470 of the 1024 pass the validity check :/

        // Check that the same public key was derived.
        auto pk_bytes = pk.bytes();
        for (auto j = 0UL; j < 32; j++)
            TEST_ASSERT_THROW(pk_bytes[j] == dataset[i].pk[j])

        // Sign the message
        auto msg = std::span<const uint8_t>{
            reinterpret_cast<const uint8_t *>(dataset[i].m), i};
        auto sig = sk.sign(msg);

        // Verify the message signature
        TEST_ASSERT_THROW(pk.verifySignature(msg, sig));
        for (auto j = 0UL; j < 64; j++)
            TEST_ASSERT_THROW(sig[j] == dataset[i].sig[j])
    }
}

auto main() -> int
{
    testBasepoint();
    testAdvanced();
    return 0;
}