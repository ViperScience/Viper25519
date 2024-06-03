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

        constexpr auto dummy_message = "tilin";
        auto sigma = skey.sign(dummy_message);

        REQUIRE(sigma.verify(0, pkey, dummy_message));
    }

    SECTION("CompactSumKesKey_Depth0")
    {
        // auto key = ed25519::Sum0CompactKesPrivateKey::generate();
        // CHECK(key.period() == 0);
        // CHECK_THROWS(key.update());
    }

    SECTION("SumKesKey_Depth1")
    {
        auto [skey, pkey] = SumKesPrivateKey<1>::generate();

        constexpr auto dummy_message = "tilin";
        auto sigma = skey.sign(dummy_message);
        REQUIRE(sigma.verify(0, pkey, dummy_message));

        // Key can be updated 2^1 - 1 times
        REQUIRE(skey.period() == 0);
        REQUIRE_NOTHROW(skey.update());
        REQUIRE(skey.period() == 1);
        REQUIRE_THROWS(skey.update());

        // Verify the key is zeroed by the drop operation.
        skey.drop();
        auto z = std::array<uint8_t, SumKesPrivateKey<1>::size + 4>{};
        REQUIRE(skey.bytes() == z);
    }

    SECTION("CompactSumKesKey_Depth1") {}

    SECTION("SumKesKey_Depth4")
    {
        auto [skey, pkey] = SumKesPrivateKey<4>::generate();

        constexpr auto dummy_message = "tilin";
        auto sigma = skey.sign(dummy_message);
        REQUIRE(sigma.verify(0, pkey, dummy_message));

        // Key can be updated 2^4 - 1 times
        for (int i = 0; i < 15; i++)
        {
            REQUIRE_NOTHROW(skey.update());
        }
        REQUIRE(skey.period() == 15);

        REQUIRE(skey.sign(dummy_message).verify(15, pkey, dummy_message));
    }

    SECTION("CompactSumKesKey_Depth4") {}

    SECTION("KesKey_to_PublicKey")
    {
        auto [skey, pkey] = SumKesPrivateKey<4>::generate();
        REQUIRE(pkey.bytes() == skey.publicKey().bytes());
    }
}