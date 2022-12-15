
#include <ed25519-viper/curve25519.hpp>
#include "testing.hpp"

// We need to test private code so we include the source file instead of linking during build.
#include "src/curve25519.cpp"

auto test_multiplyBasepointByScalar() -> void
{
    constexpr auto a = curve25519::bignum25519{
        0x00ecab516fee6a0f, 0x00115b227cd7b44f, 0x007b69c5494446f3, 
        0x0003ac3b70196932, 0x00000000007fae1c};
    const auto ab = curve25519::ExtendedPoint::multiplyBasepointByScalar(a);

    constexpr auto x_donna = curve25519::bignum25519{0x00023678d01e8e19, 0x00021dbcbb3e0bb7, 0x0005f3557b15865f, 0x0005b8dddd751446, 0x000528d4f03cef61};
    constexpr auto y_donna = curve25519::bignum25519{0x0003340895964e1e, 0x00046bb12587eb7f, 0x0000e22bae9cb108, 0x000126b93825d981, 0x000788d8f0e568cf};
    constexpr auto z_donna = curve25519::bignum25519{0x000762eec9076327, 0x00066f82733b414f, 0x00050604b0b05ff6, 0x000275d49c4e1e01, 0x00036453b2bdc3ac};
    constexpr auto t_donna = curve25519::bignum25519{0x0002073e57365b41, 0x0003ad3de19ad394, 0x0000912409ab19a2, 0x00049cadac0c24f3, 0x00057d89e2280699};

    print_bignum(ab.x());
    print_bignum(ab.y());
    print_bignum(ab.z());
    print_bignum(ab.t());

    TEST_ASSERT_THROW( ab.x() == x_donna )
    TEST_ASSERT_THROW( ab.y() == y_donna )
    TEST_ASSERT_THROW( ab.z() == z_donna )
    TEST_ASSERT_THROW( ab.t() == t_donna )
}

auto main() -> int
{
    //test_multiplyBasepointByScalar();
    return 0;
}