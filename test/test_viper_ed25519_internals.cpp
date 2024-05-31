// Repeat the tests defined at
// https://github.com/floodyberry/ed25519-donna/blob/master/test-internals.c

#include <viper25519/curve25519.hpp>

#include "testing.hpp"

static auto test_adds() -> void
{
    // largest result for each limb from a mult or square: all elements except
    // r1 reduced, r1 overflowed as far as possible
    static constexpr auto max_bignum = curve25519::bignum25519{
        0x7ffffffffffff, 0x8000000001230, 0x7ffffffffffff, 0x7ffffffffffff,
        0x7ffffffffffff
    };

    // (max_bignum + max_bignum)^2
    static constexpr auto max_bignum2_squared_raw = std::array<uint8_t, 32>{
        0x10, 0x05, 0x00, 0x00, 0x00, 0x00, 0x80, 0xdc, 0x51, 0x00, 0x00,
        0x00, 0x00, 0x61, 0xed, 0x4a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    // ((max_bignum + max_bignum) + max_bignum)^2
    static constexpr auto max_bignum3_squared_raw = std::array<uint8_t, 32>{
        0x64, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x20, 0x30, 0xb8, 0x00, 0x00,
        0x00, 0x40, 0x1a, 0x96, 0xe8, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    // a = (max_bignum + max_bignum)
    static constexpr auto a = max_bignum + max_bignum;

    // b = ((max_bignum + max_bignum) * (max_bignum + max_bignum))
    TEST_ASSERT_THROW(
        curve25519::bignum25519::contract(a * a) == max_bignum2_squared_raw
    )
    TEST_ASSERT_THROW(
        curve25519::bignum25519::contract(a.square()) == max_bignum2_squared_raw
    )

    // b = (max_bignum + max_bignum + max_bignum)
    static constexpr auto b = a + max_bignum;

    // a = ((max_bignum + max_bignum + max_bignum) * (max_bignum + max_bignum +
    // max_bignum)) */
    TEST_ASSERT_THROW(
        curve25519::bignum25519::contract(b * b) == max_bignum3_squared_raw
    )
    TEST_ASSERT_THROW(
        curve25519::bignum25519::contract(b.square()) == max_bignum3_squared_raw
    )
}

static auto test_subs() -> void
{
    // largest result for each limb from a mult or square: all elements except
    // r1 reduced, r1 overflowed as far as possible */
    static constexpr auto max_bignum = curve25519::bignum25519{
        0x7ffffffffffff, 0x8000000001230, 0x7ffffffffffff, 0x7ffffffffffff,
        0x7ffffffffffff
    };

    static constexpr auto zero =
        curve25519::bignum25519{0ULL, 0ULL, 0ULL, 0ULL, 0ULL};

    // what max_bignum should fully reduce to
    static constexpr auto max_bignum_raw =
        std::array<uint8_t, 32>{0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x91,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    // (max_bignum * max_bignum)
    static constexpr auto max_bignum_squared_raw =
        std::array<uint8_t, 32>{0x44, 0x01, 0x00, 0x00, 0x00, 0x00, 0x20, 0x77,
                                0x14, 0x00, 0x00, 0x00, 0x40, 0x58, 0xbb, 0x52,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    // a = max_bignum - 0, which expands to 2p + max_bignum - 0
    auto a = max_bignum - zero;
    TEST_ASSERT_THROW(curve25519::bignum25519::contract(a) == max_bignum_raw)

    // b = (max_bignum * max_bignum)
    auto b = a * a;
    TEST_ASSERT_THROW(
        curve25519::bignum25519::contract(b) == max_bignum_squared_raw
    )
    TEST_ASSERT_THROW(
        curve25519::bignum25519::contract(a.square()) == max_bignum_squared_raw
    )

    // b = ((a - 0) - 0)
    b = a - zero;
    TEST_ASSERT_THROW(curve25519::bignum25519::contract(b) == max_bignum_raw)

    // a = (max_bignum * max_bignum)
    a = b * b;
    TEST_ASSERT_THROW(
        curve25519::bignum25519::contract(a) == max_bignum_squared_raw
    )
    TEST_ASSERT_THROW(
        curve25519::bignum25519::contract(b.square()) == max_bignum_squared_raw
    )
}

auto main() -> int
{
    test_adds();
    test_subs();
}