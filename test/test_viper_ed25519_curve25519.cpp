
#include <viper25519/curve25519.hpp>

#include "testing.hpp"

// We need to test private code so we include the source file instead of linking
// during build.
#include "src/curve25519.cpp"

// Not a public function
auto test_curve25519_move_conditional_bytes() -> void
{
    auto packed = std::array<uint8_t, 96>{};
    packed[0] = 1;
    packed[32] = 1;

    auto table = std::array<uint8_t, 96>{
        0x3e, 0x91, 0x40, 0xd7, 0x05, 0x39, 0x10, 0x9d, 0xb3, 0xbe, 0x40, 0xd1,
        0x05, 0x9f, 0x39, 0xfd, 0x09, 0x8a, 0x8f, 0x68, 0x34, 0x84, 0xc1, 0xa5,
        0x67, 0x12, 0xf8, 0x98, 0x92, 0x2f, 0xfd, 0x44, 0x85, 0x3b, 0x8c, 0xf5,
        0xc6, 0x93, 0xbc, 0x2f, 0x19, 0x0e, 0x8c, 0xfb, 0xc6, 0x2d, 0x93, 0xcf,
        0xc2, 0x42, 0x3d, 0x64, 0x98, 0x48, 0x0b, 0x27, 0x65, 0xba, 0xd4, 0x33,
        0x3a, 0x9d, 0xcf, 0x07, 0x59, 0xbb, 0x6f, 0x4b, 0x67, 0x15, 0xbd, 0xdb,
        0xea, 0xa5, 0xa2, 0xee, 0x00, 0x3f, 0xe1, 0x41, 0xfa, 0xc6, 0x57, 0xc9,
        0x1c, 0x9d, 0xd4, 0xcd, 0xca, 0xec, 0x16, 0xaf, 0x1f, 0xbe, 0x0e, 0x4f};

    move_conditional_bytes(packed.data(), table.data(), 1);

    TEST_ASSERT_THROW(packed == table)
}

// Not a public function
auto test_curve25519_scalarmult_base_choose_niels() -> void
{
    uint32_t pos = 0;
    int8_t b = -1;

    auto t = scalarmult_base_choose_niels(pos, b);

    constexpr auto ysubx_donna = curve25519::bignum25519{
        0x000493c6f58c3b85, 0x0000df7181c325f7, 0x0000f50b0b3e4cb7,
        0x0005329385a44c32, 0x00007cf9d3a33d4b};
    constexpr auto xaddy_donna = curve25519::bignum25519{
        0x00003905d740913e, 0x0000ba2817d673a2, 0x00023e2827f4e67c,
        0x000133d2e0c21a34, 0x00044fd2f9298f81};
    constexpr auto t2d_donna = curve25519::bignum25519{
        0x0002ea98b4904494, 0x0007e22bab42a488, 0x0002a0e416f87b03,
        0x00019a9915b1719b, 0x00030f141e050e91};

    TEST_ASSERT_THROW(t.ysubx() == ysubx_donna)
    TEST_ASSERT_THROW(t.xaddy() == xaddy_donna)
    TEST_ASSERT_THROW(t.t2d() == t2d_donna)
}

auto test_ExtendedPoint_doubleExtended() -> void
{
    constexpr auto x_donna = curve25519::bignum25519{
        0x000318cace8906c8, 0x0005414882e10cb5, 0x0004ed26b6cfff4f, 
        0x0000ce366e1a07b3, 0x000582439920a9a7};
    constexpr auto y_donna = curve25519::bignum25519{
        0x00067f02c4dff024, 0x000677a7c8ca27d9, 0x00030f4244ca478f,
        0x0001a7804a15806b, 0x00063a0a76af14da};
    constexpr auto z_donna = curve25519::bignum25519{
        0x0002157313a73e74, 0x0002a34762b17c39, 0x00012efcdae5c421,
        0x0001577155674345, 0x0003b84ca2c70517};
    constexpr auto t_donna = curve25519::bignum25519{
        0x00029d3ac5aaf4d7, 0x000044b758b5ab6e, 0x00067ef498d67449,
        0x00006a3f7280a458, 0x0006fd594c8e9ff6};
    
    const auto p0 = curve25519::ExtendedPoint{std::array<bignum25519, 4>{
        bignum25519{0x000079428889ba1f, 0x0001b59cf07b69db, 0x0004bc277cebb0ae, 0x0005eb6eb40fb94f, 0x0002a2f1f65d462c},
        bignum25519{0x0002b18201985ad7, 0x00013a7fc97ab6e1, 0x0005cb8438e81d93, 0x0001579291d36d79, 0x0001a5107f7681a0},
        bignum25519{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
        bignum25519{0x00074d45e08fe9a9, 0x0007f486703777e3, 0x00042ed987ec26ad, 0x0000ceb9dc0fc102, 0x0003ada767a7a585}
    }};

    auto p = p0.doubleExtended();

    TEST_ASSERT_THROW(p.x() == x_donna)
    TEST_ASSERT_THROW(p.y() == y_donna)
    TEST_ASSERT_THROW(p.z() == z_donna)
    TEST_ASSERT_THROW(p.t() == t_donna)
}

auto test_ExtendedPoint_addPrecomp_v1() -> void
{
    constexpr auto xaddy_donna = curve25519::bignum25519{0x00065f364da3dc0f, 0x0006e3c12eacd23c, 0x0007f1a3ee691b7d, 0x0009d6dae0be207b, 0x0006f1383f3efa04};
    constexpr auto ysubx_donna = curve25519::bignum25519{0x000d98dfd95ba55d, 0x000cd97d17a46c90, 0x0010886e37e920ff, 0x001365276fede2dd, 0x000adf1b7639acca};
    constexpr auto z_donna = curve25519::bignum25519{0x000055cc4e9cf9e3, 0x00028d1d8ac5f0e5, 0x0004bbf36b971085, 0x00055dc5559d0d14, 0x0006e1328b1c145c};
    constexpr auto t2d_donna = curve25519::bignum25519{0x0004a7564745c7a5, 0x0007c299703a529a, 0x0000b815848b1652, 0x0006745899671f09, 0x0000edcc8e006dd0};

    const auto p = curve25519::ExtendedPoint{std::array<bignum25519, 4>{
        bignum25519{0x000079428889ba1f, 0x0001b59cf07b69db, 0x0004bc277cebb0ae, 0x0005eb6eb40fb94f, 0x0002a2f1f65d462c},
        bignum25519{0x0002b18201985ad7, 0x00013a7fc97ab6e1, 0x0005cb8438e81d93, 0x0001579291d36d79, 0x0001a5107f7681a0},
        bignum25519{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
        bignum25519{0x00074d45e08fe9a9, 0x0007f486703777e3, 0x00042ed987ec26ad, 0x0000ceb9dc0fc102, 0x0003ada767a7a585}
    }};

    const auto q = curve25519::ExtendedPrecomputedPoint{std::array<bignum25519, 4>{
        bignum25519{0x00032ac48a2214f6, 0x0002f01cb9f620bc, 0x000a87abb5d3ce41, 0x0007430145e326c8, 0x0004480275d3c7cc},
        bignum25519{0x0012383f790ea092, 0x000f84e2d8ff4d04, 0x00110f5cbbfc6ce3, 0x000b6c23ddc3b428, 0x000f021e89193b72},
        bignum25519{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
        bignum25519{0x000658330b54124e, 0x000123331fdcf281, 0x0003e2557c028372, 0x00066f3e5156223f, 0x00033f1759186581}
    }};

    auto r = p.add(q);

    TEST_ASSERT_THROW(r.xaddy() == xaddy_donna)
    TEST_ASSERT_THROW(r.ysubx() == ysubx_donna)
    TEST_ASSERT_THROW(r.z() == z_donna)
    TEST_ASSERT_THROW(r.t2d() == t2d_donna)
}

auto test_ExtendedPoint_addPrecomp_v2() -> void
{
    const auto p = curve25519::ExtendedPoint{std::array<bignum25519, 4>{
        bignum25519{0x000079428889ba1f, 0x0001b59cf07b69db, 0x0004bc277cebb0ae, 0x0005eb6eb40fb94f, 0x0002a2f1f65d462c},
        bignum25519{0x0002b18201985ad7, 0x00013a7fc97ab6e1, 0x0005cb8438e81d93, 0x0001579291d36d79, 0x0001a5107f7681a0},
        bignum25519{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
        bignum25519{0x00074d45e08fe9a9, 0x0007f486703777e3, 0x00042ed987ec26ad, 0x0000ceb9dc0fc102, 0x0003ada767a7a585}
    }};

    const auto q = curve25519::ExtendedPrecomputedPoint{std::array<bignum25519, 4>{
        bignum25519{0x00032ac48a2214f6, 0x0002f01cb9f620bc, 0x000a87abb5d3ce41, 0x0007430145e326c8, 0x0004480275d3c7cc},
        bignum25519{0x0012383f790ea092, 0x000f84e2d8ff4d04, 0x00110f5cbbfc6ce3, 0x000b6c23ddc3b428, 0x000f021e89193b72},
        bignum25519{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
        bignum25519{0x000658330b54124e, 0x000123331fdcf281, 0x0003e2557c028372, 0x00066f3e5156223f, 0x00033f1759186581}
    }};

    auto r = p.add(q, 0);

    constexpr auto x_donna0 = curve25519::bignum25519{0x00153517823fa6a4, 0x000fd219c0dddf8d, 0x0010bb661fb09ab6, 0x000b3ae7703f0408, 0x000eb69d9e9e9613};
    constexpr auto y_donna0 = curve25519::bignum25519{0x0009a2e6b4ccdf76, 0x000bb0da2c66ded5, 0x000b0994fe404272, 0x000a9030362616ac, 0x00061ed2c9c34d09};
    constexpr auto z_donna0 = curve25519::bignum25519{0x000132e58b08f3cd, 0x000772d56da744f0, 0x0001ac3bc835e980, 0x00063705375c9643, 0x0001a48242cea9ba};
    constexpr auto t_donna0 = curve25519::bignum25519{0x000ecd1a74f70c11, 0x00088d2a9258bb0e, 0x000e53c437ca167e, 0x0009c8fac8a369bb, 0x000e5b7dbd315644};

    TEST_ASSERT_THROW(r.x() == x_donna0)
    TEST_ASSERT_THROW(r.y() == y_donna0)
    TEST_ASSERT_THROW(r.z() == z_donna0)
    TEST_ASSERT_THROW(r.t() == t_donna0)

    r = p.add(q, 1);

    constexpr auto x_donna1 = curve25519::bignum25519{0x000fffffffffffda, 0x000ffffffffffffe, 0x000ffffffffffffe, 0x000ffffffffffffe, 0x000ffffffffffffe};
    constexpr auto y_donna1 = curve25519::bignum25519{0x000132e58b08f3ba, 0x000772d56da744f0, 0x0009ac3bc835e980, 0x00063705375c9642, 0x0009a48242cea9ba};
    constexpr auto z_donna1 = curve25519::bignum25519{0x000ecd1a74f70c11, 0x00088d2a9258bb0e, 0x000e53c437ca167e, 0x0009c8fac8a369bb, 0x000e5b7dbd315644};
    constexpr auto t_donna1 = curve25519::bignum25519{0x000132e58b08f3cd, 0x000772d56da744f0, 0x0001ac3bc835e980, 0x00063705375c9643, 0x0001a48242cea9ba};

    TEST_ASSERT_THROW(r.x() == x_donna1)
    TEST_ASSERT_THROW(r.y() == y_donna1)
    TEST_ASSERT_THROW(r.z() == z_donna1)
    TEST_ASSERT_THROW(r.t() == t_donna1)

}

auto test_ExtendedPoint_addPrecomp_v3() -> void
{
    const auto p = curve25519::ExtendedPoint{std::array<bignum25519, 4>{
        bignum25519{0x000079428889ba1f, 0x0001b59cf07b69db, 0x0004bc277cebb0ae, 0x0005eb6eb40fb94f, 0x0002a2f1f65d462c},
        bignum25519{0x0002b18201985ad7, 0x00013a7fc97ab6e1, 0x0005cb8438e81d93, 0x0001579291d36d79, 0x0001a5107f7681a0},
        bignum25519{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
        bignum25519{0x00074d45e08fe9a9, 0x0007f486703777e3, 0x00042ed987ec26ad, 0x0000ceb9dc0fc102, 0x0003ada767a7a585}
    }};

    const auto q = curve25519::PrecomputedPoint{std::array<bignum25519, 3>{
        bignum25519{0x00032ac48a2214f6, 0x0002f01cb9f620bc, 0x000a87abb5d3ce41, 0x0007430145e326c8, 0x0004480275d3c7cc},
        bignum25519{0x0012383f790ea092, 0x000f84e2d8ff4d04, 0x00110f5cbbfc6ce3, 0x000b6c23ddc3b428, 0x000f021e89193b72},
        bignum25519{0x000658330b54124e, 0x000123331fdcf281, 0x0003e2557c028372, 0x00066f3e5156223f, 0x00033f1759186581}
    }};

    auto r = p.add(q, 0);

    constexpr auto x_donna0 = curve25519::bignum25519{0x00153517823fa6a4, 0x000fd219c0dddf8d, 0x0010bb661fb09ab6, 0x000b3ae7703f0408, 0x000eb69d9e9e9613};
    constexpr auto y_donna0 = curve25519::bignum25519{0x0009a2e6b4ccdf76, 0x000bb0da2c66ded5, 0x000b0994fe404272, 0x000a9030362616ac, 0x00061ed2c9c34d09};
    constexpr auto z_donna0 = curve25519::bignum25519{0x000132e58b08f3cd, 0x000772d56da744f0, 0x0001ac3bc835e980, 0x00063705375c9643, 0x0001a48242cea9ba};
    constexpr auto t_donna0 = curve25519::bignum25519{0x000ecd1a74f70c11, 0x00088d2a9258bb0e, 0x000e53c437ca167e, 0x0009c8fac8a369bb, 0x000e5b7dbd315644};

    TEST_ASSERT_THROW(r.x() == x_donna0)
    TEST_ASSERT_THROW(r.y() == y_donna0)
    TEST_ASSERT_THROW(r.z() == z_donna0)
    TEST_ASSERT_THROW(r.t() == t_donna0)

    r = p.add(q, 1);

    constexpr auto x_donna1 = curve25519::bignum25519{0x000fffffffffffda, 0x000ffffffffffffe, 0x000ffffffffffffe, 0x000ffffffffffffe, 0x000ffffffffffffe};
    constexpr auto y_donna1 = curve25519::bignum25519{0x000132e58b08f3ba, 0x000772d56da744f0, 0x0009ac3bc835e980, 0x00063705375c9642, 0x0009a48242cea9ba};
    constexpr auto z_donna1 = curve25519::bignum25519{0x000ecd1a74f70c11, 0x00088d2a9258bb0e, 0x000e53c437ca167e, 0x0009c8fac8a369bb, 0x000e5b7dbd315644};
    constexpr auto t_donna1 = curve25519::bignum25519{0x000132e58b08f3cd, 0x000772d56da744f0, 0x0001ac3bc835e980, 0x00063705375c9643, 0x0001a48242cea9ba};

    TEST_ASSERT_THROW(r.x() == x_donna1)
    TEST_ASSERT_THROW(r.y() == y_donna1)
    TEST_ASSERT_THROW(r.z() == z_donna1)
    TEST_ASSERT_THROW(r.t() == t_donna1)
}

auto test_ExtendedPoint_toPrecomputedExtendedPoint()
{
    constexpr auto xaddy_donna = curve25519::bignum25519{
        0x00032ac48a2214f6, 0x0002f01cb9f620bc, 0x000a87abb5d3ce41, 0x0007430145e326c8, 0x0004480275d3c7cc};
    constexpr auto ysubx_donna = curve25519::bignum25519{
        0x0012383f790ea092, 0x000f84e2d8ff4d04, 0x00110f5cbbfc6ce3, 0x000b6c23ddc3b428, 0x000f021e89193b72};
    constexpr auto z_donna = curve25519::bignum25519{
        0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000};
    constexpr auto t2d_donna = curve25519::bignum25519{
        0x000658330b54124e, 0x000123331fdcf281, 0x0003e2557c028372, 0x00066f3e5156223f, 0x00033f1759186581};

    const auto p0 = curve25519::ExtendedPoint{std::array<bignum25519, 4>{
        bignum25519{0x000079428889ba1f, 0x0001b59cf07b69db, 0x0004bc277cebb0ae, 0x0005eb6eb40fb94f, 0x0002a2f1f65d462c},
        bignum25519{0x0002b18201985ad7, 0x00013a7fc97ab6e1, 0x0005cb8438e81d93, 0x0001579291d36d79, 0x0001a5107f7681a0},
        bignum25519{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
        bignum25519{0x00074d45e08fe9a9, 0x0007f486703777e3, 0x00042ed987ec26ad, 0x0000ceb9dc0fc102, 0x0003ada767a7a585}
    }};

    auto p = p0.toPrecomputedExtendedPoint();

    TEST_ASSERT_THROW(p.xaddy() == xaddy_donna)
    TEST_ASSERT_THROW(p.ysubx() == ysubx_donna)
    TEST_ASSERT_THROW(p.z() == z_donna)
    TEST_ASSERT_THROW(p.t2d() == t2d_donna)
}

auto test_ExtendedPoint_multiplyBasepointByScalar() -> void
{
    constexpr auto a1 = curve25519::bignum25519{
        0x00ecab516fee6a0f, 0x00115b227cd7b44f, 0x007b69c5494446f3,
        0x0003ac3b70196932, 0x00000000007fae1c};
    const auto ab1 = curve25519::ExtendedPoint::multiplyBasepointByScalar(a1);

    constexpr auto x1_donna = curve25519::bignum25519{
        0x00023678d01e8e19, 0x00021dbcbb3e0bb7, 0x0005f3557b15865f,
        0x0005b8dddd751446, 0x000528d4f03cef61};
    constexpr auto y1_donna = curve25519::bignum25519{
        0x0003340895964e1e, 0x00046bb12587eb7f, 0x0000e22bae9cb108,
        0x000126b93825d981, 0x000788d8f0e568cf};
    constexpr auto z1_donna = curve25519::bignum25519{
        0x000762eec9076327, 0x00066f82733b414f, 0x00050604b0b05ff6,
        0x000275d49c4e1e01, 0x00036453b2bdc3ac};
    constexpr auto t1_donna = curve25519::bignum25519{
        0x0002073e57365b41, 0x0003ad3de19ad394, 0x0000912409ab19a2,
        0x00049cadac0c24f3, 0x00057d89e2280699};

    TEST_ASSERT_THROW(ab1.x() == x1_donna)
    TEST_ASSERT_THROW(ab1.y() == y1_donna)
    TEST_ASSERT_THROW(ab1.z() == z1_donna)
    TEST_ASSERT_THROW(ab1.t() == t1_donna)

    constexpr auto a2 = curve25519::bignum25519{
        0x008c40a0a7bc33e0, 0x00b57421cae8bade, 0x00787db7ad72c176,
        0x00548639116c68a5, 0x00000000414fa297};
    const auto ab2 = curve25519::ExtendedPoint::multiplyBasepointByScalar(a2);

    constexpr auto x2_donna = curve25519::bignum25519{
        0x00062b0f24758d96, 0x00056e645fa9b99f, 0x00065ca9e986a331, 0x0006445717934f96, 0x00037bb64b57bfd2};
    constexpr auto y2_donna = curve25519::bignum25519{
        0x0006772d7403b6f4, 0x0002218c2a0d3b90, 0x000667845a512eab, 0x0003aff484fe5c0f, 0x000709cded587b35 };
    constexpr auto z2_donna = curve25519::bignum25519{
        0x0004b3ae0f1c61a5, 0x0003b699a6e095cf, 0x0000330f68d32796, 0x000033c15acb23e5, 0x000366e5d53ab739};
    constexpr auto t2_donna = curve25519::bignum25519{
        0x0000e1cc01561ef1, 0x00079dc021400c9e, 0x00004b5a2fe0468d, 0x00073714d4c82967, 0x0000e093f956af9f};

    TEST_ASSERT_THROW(ab2.x() == x2_donna)
    TEST_ASSERT_THROW(ab2.y() == y2_donna)
    TEST_ASSERT_THROW(ab2.z() == z2_donna)
    TEST_ASSERT_THROW(ab2.t() == t2_donna)
}

auto test_ExtendedPoint_unpack() -> void
{
    constexpr auto x_donna = curve25519::bignum25519{
        0x000079428889ba1f, 0x0001b59cf07b69db, 0x0004bc277cebb0ae, 
        0x0005eb6eb40fb94f, 0x0002a2f1f65d462c};
    constexpr auto y_donna = curve25519::bignum25519{
        0x0002b18201985ad7, 0x00013a7fc97ab6e1, 0x0005cb8438e81d93,
        0x0001579291d36d79, 0x0001a5107f7681a0};
    constexpr auto z_donna = curve25519::bignum25519{
        0x0000000000000001, 0x0000000000000000, 0x0000000000000000,
        0x0000000000000000, 0x0000000000000000};
    constexpr auto t_donna = curve25519::bignum25519{
        0x00074d45e08fe9a9, 0x0007f486703777e3, 0x00042ed987ec26ad,
        0x0000ceb9dc0fc102, 0x0003ada767a7a585};

    constexpr auto bytes = std::array<uint8_t, 32>{
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe,
            0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6,
            0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a};
    auto p = ExtendedPoint::unpack(bytes);

    TEST_ASSERT_THROW(p.x() == x_donna)
    TEST_ASSERT_THROW(p.y() == y_donna)
    TEST_ASSERT_THROW(p.z() == z_donna)
    TEST_ASSERT_THROW(p.t() == t_donna)
}

auto test_ExtendedPoint_doubleScalarMultiple() -> void
{
    constexpr auto x_donna = curve25519::bignum25519{
        0x00054b919ad90ff8, 0x0006d4293f7b422c, 0x00057566212466bb, 0x00070d430077bf93, 0x0001ced251a2fef4};
    constexpr auto y_donna = curve25519::bignum25519{
        0x0004eaa0223caeee, 0x00022366f2efbe7e, 0x00064e49018e6ce3, 0x00072353fe7a0c02, 0x0002f43ba9331d20};
    constexpr auto z_donna = curve25519::bignum25519{
        0x0002710d204750ac, 0x0004bcfafe29176a, 0x0002ee2c637a123d, 0x0007f9892131fd37, 0x0000590929c555fd};
    constexpr auto t_donna = curve25519::bignum25519{
        0x0007329797d37fd2, 0x0005b0865d9df5d9, 0x0001920661844503, 0x00042decac580cd8, 0x0007d8caaaf04880};

    constexpr auto s1 = curve25519::bignum25519{0x00ecab516fee6a0f, 0x00115b227cd7b44f, 0x007b69c5494446f3, 0x0003ac3b70196932, 0x00000000007fae1c};
    constexpr auto s2 = curve25519::bignum25519{0x00003905d740913e, 0x0000ba2817d673a2, 0x00023e2827f4e67c, 0x000133d2e0c21a34, 0x00044fd2f9298f81};
    const auto p1 = curve25519::ExtendedPoint{std::array<bignum25519, 4>{
        bignum25519{0x000079428889ba1f, 0x0001b59cf07b69db, 0x0004bc277cebb0ae, 0x0005eb6eb40fb94f, 0x0002a2f1f65d462c},
        bignum25519{0x0002b18201985ad7, 0x00013a7fc97ab6e1, 0x0005cb8438e81d93, 0x0001579291d36d79, 0x0001a5107f7681a0},
        bignum25519{0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
        bignum25519{0x00074d45e08fe9a9, 0x0007f486703777e3, 0x00042ed987ec26ad, 0x0000ceb9dc0fc102, 0x0003ada767a7a585}
    }};

    auto d1 = p1.doubleScalarMultiple(s1, s2);

    TEST_ASSERT_THROW(d1.x() == x_donna)
    TEST_ASSERT_THROW(d1.y() == y_donna)
    TEST_ASSERT_THROW(d1.z() == z_donna)
    TEST_ASSERT_THROW(d1.t() == t_donna)
}

auto test_CompletedPoint_toExtended() -> void
{
    const auto p1 = curve25519::CompletedPoint{std::array<bignum25519, 4>{
        bignum25519{0x0021a8bc11fd35f1, 0x001e90ce06eefc79, 0x001ddb30fd84d5bc, 0x0021d73b81f8204d, 0x001db4ecf4f4b09f},
        bignum25519{0x00051735a666fc0f, 0x000586d16336f6b1, 0x00084ca7f202139b, 0x00048181b130b56a, 0x0008f6964e1a6852},
        bignum25519{0x0011972c58479e55, 0x001396ab6d3a277f, 0x000d61de41af4c05, 0x0011b829bae4b218, 0x0015241216754dd4},
        bignum25519{0x001668d3a7b8616c, 0x0014695492c5d87c, 0x001a9e21be50b3f6, 0x001647d6451b4de3, 0x0012dbede98ab227}
    }};

    const auto r1 = curve25519::ExtendedPoint{std::array<bignum25519, 4>{
        bignum25519{0x0000cace8906d510, 0x00014882e10cb563, 0x000526b6cfff4fa8, 0x0006366e1a07b39d, 0x0002439920a9a719},
        bignum25519{0x000702c4dff032c5, 0x0007a7c8ca27d9cf, 0x00074244ca478fce, 0x0007804a15806b61, 0x00020a76af14da34},
        bignum25519{0x00057313a73e7cd5, 0x00034762b17c3942, 0x0006fcdae5c42154, 0x0007715567434525, 0x00004ca2c705172a},
        bignum25519{0x00053ac5aaf4e78d, 0x0004b758b5ab6e53, 0x0006f498d6744908, 0x00023f7280a458cf, 0x0005594c8e9ff60d}
    }};

    auto r = p1.toExtended();

    TEST_ASSERT_THROW(r.x() == r1.x())
    TEST_ASSERT_THROW(r.y() == r1.y())
    TEST_ASSERT_THROW(r.z() == r1.z())
    TEST_ASSERT_THROW(r.t() == r1.t())
}

auto main() -> int
{
    test_curve25519_move_conditional_bytes();
    test_curve25519_scalarmult_base_choose_niels();

    test_ExtendedPoint_doubleExtended();
    test_ExtendedPoint_toPrecomputedExtendedPoint();
    test_ExtendedPoint_addPrecomp_v1();
    test_ExtendedPoint_addPrecomp_v2();
    test_ExtendedPoint_addPrecomp_v3();
    test_ExtendedPoint_multiplyBasepointByScalar();
    test_ExtendedPoint_unpack();
    test_ExtendedPoint_doubleScalarMultiple();

    test_CompletedPoint_toExtended();

    return 0;
}