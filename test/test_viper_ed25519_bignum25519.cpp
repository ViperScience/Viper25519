#include <ed25519-viper/curve25519.hpp>
#include "testing.hpp"

// We need to test private code so we include the source file instead of linking during build.
#include "src/curve25519.cpp"

auto test_contract256_window4_modm()
{
    constexpr auto bytes_donna = std::array<int8_t, 64>{
        -1, +1, -6, +7, -2, -1, +0, +7, 
        +1, +5, -5, -5, -3, -1, +0, +5, 
        +4, -5, -8, -2, -3, -8, +3, +2,
        -5, +6, +1, +1, +3, -1, +7, +4,
        +4, +4, -7, +5, +5, -4, -6, +7,
        -5, -8, +3, +3, -7, +7, -7, +2,
        +0, +7, -5, +4, -4, -5, +4, +0,
        -4, +2, -2, -5, +0, -8, +1, +0,
    };

    constexpr auto in = curve25519::bignum25519{
        0x00ecab516fee6a0f, 0x00115b227cd7b44f, 0x007b69c5494446f3, 
        0x0003ac3b70196932, 0x00000000007fae1c};
    constexpr auto res = contract256_window4_modm(in);

    TEST_ASSERT_THROW( res == bytes_donna )
}

auto test_expand256_modm() -> void
{
    auto k = std::array<uint8_t, 32>{
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
        0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
        0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60};
    
    auto a = curve25519::bignum25519::expand256_modm(k);
    auto a_donna = curve25519::bignum25519{
        0x00ecab516fee6a0f, 0x00115b227cd7b44f, 0x007b69c5494446f3, 
        0x0003ac3b70196932, 0x00000000007fae1c};
    
    TEST_ASSERT_THROW( a == a_donna )
}

auto main() -> int
{
    test_contract256_window4_modm();
    test_expand256_modm();
    return 0;
}