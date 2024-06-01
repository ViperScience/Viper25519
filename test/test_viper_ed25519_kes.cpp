#include <catch2/catch_test_macros.hpp>
#include <viper25519/kes25519.hpp>
#include <viper25519/secmem.hpp>

using namespace ed25519;

TEST_CASE("test_viper_ed25519_kes")
{
    SECTION("SumKesKey_Depth0")
    {
        auto [skey, pkey] = SumKesPrivateKey<0>::generate();
        REQUIRE(skey.period() == 0);
        REQUIRE_THROWS(skey.update());
    }

    SECTION("CompactSumKesKey_")
    {
        // auto key = ed25519::Sum0CompactKesPrivateKey::generate();
        // CHECK(key.period() == 0);
        // CHECK_THROWS(key.update());
    }

    SECTION("SumKesKey_Depth1")
    {
        auto [skey, pkey] = SumKesPrivateKey<1>::generate();

        constexpr auto dummy_message = "tilin";
        // sign
        // verify

        // Key can be updated 2^4 - 1 times
        REQUIRE(skey.period() == 0);
        REQUIRE_NOTHROW(skey.update());
        REQUIRE(skey.period() == 1);
        REQUIRE_THROWS(skey.update());

        // Verify the key is zeroed by the drop operation.
        skey.drop();
        auto z = std::array<uint8_t, SumKesPrivateKey<1>::size + 4>{};
        REQUIRE(skey.bytes() == z);
    }

    SECTION("SumKesKey_Depth4")
    {
        auto [skey, pkey] = SumKesPrivateKey<4>::generate();

        constexpr auto dummy_message = "tilin";
        // sign
        // verify

        // Key can be updated 2^4 - 1 times
        for (int i = 0; i < 15; i++)
        {
            REQUIRE_NOTHROW(skey.update());
        }
        REQUIRE(skey.period() == 15);

        // sign
        // verify
    }
}