#include <catch2/catch_test_macros.hpp>
#include <viper25519/kes25519.hpp>
#include <viper25519/secmem.hpp>

using namespace ed25519;

TEST_CASE("test_viper_ed25519_kes")
{
    SECTION("Sum0KesPrivateKey")
    {
        // auto key = SumKesPrivateKey<0>::generate();
        // CHECK(key.period() == 0);
        // CHECK_THROWS(key.update());
    }

    SECTION("Sum0CompactKesPrivateKey")
    {
        // auto key = ed25519::Sum0CompactKesPrivateKey::generate();
        // CHECK(key.period() == 0);
        // CHECK_THROWS(key.update());
    }

    SECTION("buff_single")
    {
        auto skey_buffer =
            SecureByteArray<uint8_t, SumKesPrivateKey<1>::size + 4>{};
        auto seed_buffer = SecureByteArray<uint8_t, KesSeed::size>{};

        auto [skey, pkey] =
            SumKesPrivateKey<1>::keygen(skey_buffer, seed_buffer);

        constexpr auto dummy_message = "tilin";

        // auto sig = skey.sign(dummy_message);

        // auto skey = ed25519::SumKesSigningKey<1>::generate();

        // auto sskey = ed25519::SumKesPrivateKey<0>();
        // CHECK(sskey.size == ed25519::SumKesPrivateKey<0>::size);
        // CHECK(sskey.size != ed25519::SumKesPrivateKey<1>::size);
        // CHECK(key.period() == 0);
        // CHECK_THROWS(key.update());

        auto z = std::array<uint8_t, SumKesPrivateKey<1>::size + 4>{};

        CHECK(skey.bytes() == skey_buffer);
    }

    //         fn buff_single() {
    //         let mut skey_buffer = [0u8; Sum1Kes::SIZE + 4];
    //         let mut seed = [0u8; Seed::SIZE];
    //         let (mut skey, pkey) = Sum1Kes::keygen(&mut skey_buffer, &mut
    //         seed); let dummy_message = b"tilin"; let sigma =
    //         skey.sign(dummy_message);
    //
    //         assert_eq!(skey.get_period(), 0);
    //
    //         assert!(sigma.verify(0, &pkey, dummy_message).is_ok());
    //
    //         // Key can be updated once
    //         assert!(skey.update().is_ok());
    //     }
    //
    //     SumKesSigningKey
}