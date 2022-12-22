
#include <ed25519-viper/curve25519.hpp>

#include "testing.hpp"

// We need to test private code so we include the source file instead of linking
// during build.
#include "src/curve25519.cpp"

// Not a public function
auto test_move_conditional_bytes() -> void
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
auto test_scalarmult_base_choose_niels() -> void
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

auto test_multiplyBasepointByScalar() -> void
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

auto main() -> int
{
    test_move_conditional_bytes();
    test_scalarmult_base_choose_niels();
    test_multiplyBasepointByScalar();
    return 0;
}