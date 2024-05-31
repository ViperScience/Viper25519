#include <viper25519/curve25519.hpp>

#include "testing.hpp"

// We need to test private code so we include the source file instead of linking
// during build.
#include "curve25519.cpp"

auto test_contract256_modm() -> void
{
    constexpr auto bytes_donna =
        std::array<uint8_t, 32>{0x0f, 0x6a, 0xee, 0x6f, 0x51, 0xab, 0xec, 0x4f,
                                0xb4, 0xd7, 0x7c, 0x22, 0x5b, 0x11, 0xf3, 0x46,
                                0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
                                0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x00};
    constexpr auto in = curve25519::bignum25519{
        0x00ecab516fee6a0f, 0x00115b227cd7b44f, 0x007b69c5494446f3,
        0x0003ac3b70196932, 0x00000000007fae1c
    };
    auto bytes = bignum25519::contract256_modm(in);
    TEST_ASSERT_THROW(bytes == bytes_donna)
}

auto test_contract256_window4_modm() -> void
{
    constexpr auto bytes_donna = std::array<int8_t, 64>{
        -1, +1, -6, +7, -2, -1, +0, +7, +1, +5, -5, -5, -3, -1, +0, +5,
        +4, -5, -8, -2, -3, -8, +3, +2, -5, +6, +1, +1, +3, -1, +7, +4,
        +4, +4, -7, +5, +5, -4, -6, +7, -5, -8, +3, +3, -7, +7, -7, +2,
        +0, +7, -5, +4, -4, -5, +4, +0, -4, +2, -2, -5, +0, -8, +1, +0,
    };

    constexpr auto in = curve25519::bignum25519{
        0x00ecab516fee6a0f, 0x00115b227cd7b44f, 0x007b69c5494446f3,
        0x0003ac3b70196932, 0x00000000007fae1c
    };
    constexpr auto res = contract256_window4_modm(in);

    TEST_ASSERT_THROW(res == bytes_donna)
}

auto test_contract256_slidingwindow_modm() -> void
{
    constexpr auto bytes_donna = std::array<int8_t, 256>{
        +15, +0,  +0, +0,  +0, +0, +0,  +0,  +0,  -11, +0, +0,  +0,  +0,  +0,
        -3,  +0,  +0, +0,  +0, -1, +0,  +0,  +0,  +0,  +0, +0,  +0,  -9,  +0,
        +0,  +0,  +0, +9,  +0, +0, +0,  +0,  +13, +0,  +0, +0,  +0,  -11, +0,
        +0,  +0,  +0, +13, +0, +0, +0,  +0,  -1,  +0,  +0, +0,  +0,  +0,  +0,
        +5,  +0,  +0, +0,  +0, +0, +13, +0,  +0,  +0,  +0, +15, +0,  +0,  +0,
        +0,  +13, +0, +0,  +0, +0, +0,  -1,  +0,  +0,  +0, +0,  +5,  +0,  +0,
        +0,  +0,  +0, -7,  +0, +0, +0,  +0,  -9,  +0,  +0, +0,  +0,  +3,  +0,
        +0,  +0,  +0, -15, +0, +0, +0,  +0,  +0,  -3,  +0, +0,  +0,  +0,  +0,
        +7,  +0,  +0, +0,  +0, +0, -15, +0,  +0,  +0,  +0, +9,  +0,  +0,  +0,
        +0,  +9,  +0, +0,  +0, +0, +0,  -11, +0,  +0,  +0, +0,  -7,  +0,  +0,
        +0,  +0,  +0, -11, +0, +0, +0,  +0,  +0,  -9,  +0, +0,  +0,  +0,  +0,
        +0,  +0,  +5, +0,  +0, +0, +0,  -13, +0,  +0,  +0, +0,  -11, +0,  +0,
        +0,  +0,  +0, -13, +0, +0, +0,  +0,  +0,  +1,  +0, +0,  +0,  +0,  +0,
        +0,  -9,  +0, +0,  +0, +0, +0,  +15, +0,  +0,  +0, +0,  +0,  +0,  +0,
        +11, +0,  +0, +0,  +0, +7, +0,  +0,  +0,  +0,  +0, +0,  +0,  +0,  +0,
        +0,  +7,  +0, +0,  +0, +0, +0,  +0,  -9,  +0,  +0, +0,  +0,  -1,  +0,
        +0,  +0,  +0, +0,  +0, +0, +0,  +1,  +0,  +0,  +0, +0,  +0,  +0,  +0,
        +0,
    };

    constexpr auto in = curve25519::bignum25519{
        0x00ecab516fee6a0f, 0x00115b227cd7b44f, 0x007b69c5494446f3,
        0x0003ac3b70196932, 0x00000000007fae1c
    };
    constexpr auto res = contract256_slidingwindow_modm(in, 5);

    TEST_ASSERT_THROW(res == bytes_donna)
}

auto test_expand256_modm() -> void
{
    constexpr auto k =
        std::array<uint8_t, 32>{0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
                                0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
                                0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
                                0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60};

    const auto a = curve25519::bignum25519::expand256_modm(k);
    constexpr auto a_donna = curve25519::bignum25519{
        0x00ecab516fee6a0f, 0x00115b227cd7b44f, 0x007b69c5494446f3,
        0x0003ac3b70196932, 0x00000000007fae1c
    };

    TEST_ASSERT_THROW(a == a_donna)
}

auto test_bignum25519_expand() -> void
{
    constexpr auto table = std::array<uint8_t, 96>{
        0x3e, 0x91, 0x40, 0xd7, 0x05, 0x39, 0x10, 0x9d, 0xb3, 0xbe, 0x40, 0xd1,
        0x05, 0x9f, 0x39, 0xfd, 0x09, 0x8a, 0x8f, 0x68, 0x34, 0x84, 0xc1, 0xa5,
        0x67, 0x12, 0xf8, 0x98, 0x92, 0x2f, 0xfd, 0x44, 0x85, 0x3b, 0x8c, 0xf5,
        0xc6, 0x93, 0xbc, 0x2f, 0x19, 0x0e, 0x8c, 0xfb, 0xc6, 0x2d, 0x93, 0xcf,
        0xc2, 0x42, 0x3d, 0x64, 0x98, 0x48, 0x0b, 0x27, 0x65, 0xba, 0xd4, 0x33,
        0x3a, 0x9d, 0xcf, 0x07, 0x59, 0xbb, 0x6f, 0x4b, 0x67, 0x15, 0xbd, 0xdb,
        0xea, 0xa5, 0xa2, 0xee, 0x00, 0x3f, 0xe1, 0x41, 0xfa, 0xc6, 0x57, 0xc9,
        0x1c, 0x9d, 0xd4, 0xcd, 0xca, 0xec, 0x16, 0xaf, 0x1f, 0xbe, 0x0e, 0x4f
    };

    const auto ysubx = bignum25519::expand({table.data() + 0, 32});
    const auto xaddy = bignum25519::expand({table.data() + 32, 32});
    const auto t2d = bignum25519::expand({table.data() + 64, 32});

    constexpr auto ysubx_donna = curve25519::bignum25519{
        0x00003905d740913e, 0x0000ba2817d673a2, 0x00023e2827f4e67c,
        0x000133d2e0c21a34, 0x00044fd2f9298f81
    };
    constexpr auto xaddy_donna = curve25519::bignum25519{
        0x000493c6f58c3b85, 0x0000df7181c325f7, 0x0000f50b0b3e4cb7,
        0x0005329385a44c32, 0x00007cf9d3a33d4b
    };
    constexpr auto t2d_donna = curve25519::bignum25519{
        0x000515674b6fbb59, 0x00001dd454bd5b77, 0x00055f1be90784fc,
        0x00066566ea4e8e64, 0x0004f0ebe1faf16e
    };

    TEST_ASSERT_THROW(ysubx == ysubx_donna)
    TEST_ASSERT_THROW(xaddy == xaddy_donna)
    TEST_ASSERT_THROW(t2d == t2d_donna)
}

// Not a public function
auto test_bignum25519_swap_conditional() -> void
{
    constexpr auto a_const = curve25519::bignum25519{
        0x00ecab516fee6a0f, 0x00115b227cd7b44f, 0x007b69c5494446f3,
        0x0003ac3b70196932, 0x00000000007fae1c
    };
    constexpr auto b_const = curve25519::bignum25519{
        0x00003905d740913e, 0x0000ba2817d673a2, 0x00023e2827f4e67c,
        0x000133d2e0c21a34, 0x00044fd2f9298f81
    };

    auto a = curve25519::bignum25519{
        0x00ecab516fee6a0f, 0x00115b227cd7b44f, 0x007b69c5494446f3,
        0x0003ac3b70196932, 0x00000000007fae1c
    };
    auto b = curve25519::bignum25519{
        0x00003905d740913e, 0x0000ba2817d673a2, 0x00023e2827f4e67c,
        0x000133d2e0c21a34, 0x00044fd2f9298f81
    };

    swap_conditional(a, b, 0);
    TEST_ASSERT_THROW(a == a_const)
    TEST_ASSERT_THROW(b == b_const)

    swap_conditional(a, b, 1);
    TEST_ASSERT_THROW(b == a_const)
    TEST_ASSERT_THROW(a == b_const)
}

auto test_bignum25519_neg() -> void
{
    constexpr auto in = curve25519::bignum25519{
        0x00ecab516fee6a0f, 0x00115b227cd7b44f, 0x007b69c5494446f3,
        0x0003ac3b70196932, 0x00000000007fae1c
    };
    constexpr auto neg_donna = curve25519::bignum25519{
        0x000354ae901195de, 0x0006a4dd83286b93, 0x0004963ab6bbd90a,
        0x000453c48fe6b6be, 0x0007ffffff8051e3
    };
    TEST_ASSERT_THROW(in.neg() == neg_donna)
}

auto test_bignum25519_addReduce() -> void
{
    constexpr auto in = curve25519::bignum25519{
        0x00ecab516fee6a0f, 0x00115b227cd7b44f, 0x007b69c5494446f3,
        0x0003ac3b70196932, 0x00000000007fae1c
    };
    constexpr auto res_donna = curve25519::bignum25519{
        0x000156a2dfdcd41e, 0x0002b644f9af68d9, 0x0006d38a92888dea,
        0x00075876e032d282, 0x0000000000ff5c38
    };
    TEST_ASSERT_THROW(in.addReduce(in) == res_donna)
}

auto test_bignum25519_squareTimes() -> void
{
    constexpr auto in = curve25519::bignum25519{
        0x00ecab516fee6a0f, 0x00115b227cd7b44f, 0x007b69c5494446f3,
        0x0003ac3b70196932, 0x00000000007fae1c
    };
    constexpr auto res_donna = curve25519::bignum25519{
        0x000359048f567c22, 0x000647e2c934680e, 0x00014bf662215d18,
        0x0005b33c440e32a7, 0x0005fc478404ae75
    };

    TEST_ASSERT_THROW(in.squareTimes(5) == res_donna)
}

auto test_bignum25519_pow_two5mtwo0_two250mtwo0() -> void
{
    constexpr auto in = curve25519::bignum25519{
        0x00ecab516fee6a0f, 0x00115b227cd7b44f, 0x007b69c5494446f3,
        0x0003ac3b70196932, 0x00000000007fae1c
    };
    constexpr auto res_donna = curve25519::bignum25519{
        0x00055297e3a7c6fc, 0x0002c33b3e396b71, 0x00043ed13ab9b454,
        0x0000a229671d85b3, 0x00008b1c5f6bac99
    };
    TEST_ASSERT_THROW(in.pow_two5mtwo0_two250mtwo0() == res_donna)
}

auto test_bignum25519_recip() -> void
{
    constexpr auto in = curve25519::bignum25519{
        0x00ecab516fee6a0f, 0x00115b227cd7b44f, 0x007b69c5494446f3,
        0x0003ac3b70196932, 0x00000000007fae1c
    };
    constexpr auto res_donna = curve25519::bignum25519{
        0x000264340ecb3c4e, 0x000073c1b0856a3c, 0x00053c3f1d78c007,
        0x000116305d643f7d, 0x000027dfa1fdc373
    };
    TEST_ASSERT_THROW(in.recip() == res_donna)
}

auto test_bignum25519_add256_modm() -> void
{
    constexpr auto x = curve25519::bignum25519{
        0x00ecab516fee6a0f, 0x00115b227cd7b44f, 0x007b69c5494446f3,
        0x0003ac3b70196932, 0x00000000007fae1c
    };
    constexpr auto y = curve25519::bignum25519{
        0x00003905d740913e, 0x0000ba2817d673a2, 0x00023e2827f4e67c,
        0x000133d2e0c21a34, 0x00044fd2f9298f81
    };
    constexpr auto r = curve25519::bignum25519{
        0x00da813cea392760, 0x001836a79d115199, 0x007da7ed71391890,
        0x0004e00e50db8366, 0x00044fd2e9a93d9d
    };

    TEST_ASSERT_THROW(curve25519::bignum25519::add256_modm(x, y) == r)
}

auto test_bignum25519_mul256_modm() -> void
{
    constexpr auto x = curve25519::bignum25519{
        0x00ecab516fee6a0f, 0x00115b227cd7b44f, 0x007b69c5494446f3,
        0x0003ac3b70196932, 0x00000000007fae1c
    };
    constexpr auto y = curve25519::bignum25519{
        0x00003905d740913e, 0x0000ba2817d673a2, 0x00023e2827f4e67c,
        0x000133d2e0c21a34, 0x00044fd2f9298f81
    };
    constexpr auto r = curve25519::bignum25519{
        0x00b2f1b400f3561c, 0x004b4f2b65106226, 0x00ec9086adfadc93,
        0x0091f1638f8bce32, 0x000000079e7d6a70
    };

    TEST_ASSERT_THROW(curve25519::bignum25519::mul256_modm(x, y) == r)
}

auto test_bignum25519_pow_two252m3() -> void
{
    // bignum25519::pow_two252m3
    constexpr auto in = curve25519::bignum25519{
        0x00ecab516fee6a0f, 0x00115b227cd7b44f, 0x007b69c5494446f3,
        0x0003ac3b70196932, 0x00000000007fae1c
    };
    constexpr auto res_donna = curve25519::bignum25519{
        0x000682d9e2b111e1, 0x00007e8974ac1d3f, 0x0000797621ab59db,
        0x0002854d06b63c40, 0x0003e9d41c005987
    };
    TEST_ASSERT_THROW(in.pow_two252m3() == res_donna)
}

auto main() -> int
{
    test_contract256_modm();
    test_contract256_window4_modm();
    test_contract256_slidingwindow_modm();
    test_expand256_modm();
    test_bignum25519_expand();
    test_bignum25519_swap_conditional();
    test_bignum25519_neg();
    test_bignum25519_addReduce();
    test_bignum25519_squareTimes();
    test_bignum25519_pow_two5mtwo0_two250mtwo0();
    test_bignum25519_recip();
    test_bignum25519_add256_modm();
    test_bignum25519_mul256_modm();
    test_bignum25519_pow_two252m3();
    return 0;
}