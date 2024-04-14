#include <algorithm>
#include <charconv>
#include <iomanip>
#include <iostream>
#include <map>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <viper25519/vrf25519.hpp>

#include "testing.hpp"

using namespace ed25519;

typedef struct TestData_
{
    const char seed[2 * 32 + 1];
    const char pubk[2 * 32 + 1];
    const char proof[2 * 80 + 1];
    const char hash[2 * 64 + 1];
} TestData;

// /// Test data taken from
// /// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-13#appendix-A.4
// /// which contains the seeds and expected values.
// static const TestData test_data[] = {
//     {
//         "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
//         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
//         "7d9c633ffeee27349264cf5c667579fc583b4bda63ab71d001f89c10003ab46f14adf9a3cd8b8412d9038531e865c341cafa73589b023d14311c331a9ad15ff2fb37831e00f0acaa6d73bc9997b06501",
//         "9d574bf9b8302ec0fc1e21c3ec5368269527b87b462ce36dab2d14ccf80c53cccf6758f058c5b1c856b116388152bbe509ee3b9ecfe63d93c3b4346c1fbc6c54"
//     },
//     {
//         "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
//         "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
//         "47b327393ff2dd81336f8a2ef10339112401253b3c714eeda879f12c509072ef055b48372bb82efbdce8e10c8cb9a2f9d60e93908f93df1623ad78a86a028d6bc064dbfc75a6a57379ef855dc6733801",
//         "38561d6b77b71d30eb97a062168ae12b667ce5c28caccdf76bc88e093e4635987cd96814ce55b4689b3dd2947f80e59aac7b7675f8083865b46c89b2ce9cc735"
//     },
//     {
//         "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
//         "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
//         "926e895d308f5e328e7aa159c06eddbe56d06846abf5d98c2512235eaa57fdce35b46edfc655bc828d44ad09d1150f31374e7ef73027e14760d42e77341fe05467bb286cc2c9d7fde29120a0b2320d04",
//         "121b7f9b9aaaa29099fc04a94ba52784d44eac976dd1a3cca458733be5cd090a7b5fbd148444f17f8daf1fb55cb04b1ae85a626e30a54b4b0f8abf4a43314a58"
//     }
// };

/// Test data taken from
/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-03#appendix-A.4
/// which contains the seeds and expected values.
static const TestData test_data[] = {
    {"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "b6b4699f87d56126c9117a7da55bd0085246f4c56dbc95d20172612e9d38e8d7ca65e573a"
     "126ed88d4e30a46f80a666854d675cf3ba81de0de043c3774f061560f55edc256a787afe7"
     "01677c0f602900",
     "5b49b554d05c0cd5a5325376b3387de59d924fd1e13ded44648ab33c21349a603f25b84ec"
     "5ed887995b33da5e3bfcb87cd2f64521c4c62cf825cffabbe5d31cc"},
    {"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "ae5b66bdf04b4c010bfe32b2fc126ead2107b697634f6f7337b9bff8785ee111200095ece"
     "87dde4dbe87343f6df3b107d91798c8a7eb1245d3bb9c5aafb093358c13e6ae1111a55717"
     "e895fd15f99f07",
     "94f4487e1b2fec954309ef1289ecb2e15043a2461ecc7b2ae7d4470607ef82eb1cfa97d84"
     "991fe4a7bfdfd715606bc27e2967a6c557cfb5875879b671740b7d8"},
    {"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     "dfa2cba34b611cc8c833a6ea83b8eb1bb5e2ef2dd1b0c481bc42ff36ae7847f6ab52b976c"
     "fd5def172fa412defde270c8b8bdfbaae1c7ece17d9833b1bcf31064fff78ef493f820055"
     "b561ece45e1009",
     "2031837f582cd17a9af9e0c7ef5a6540e3453ed894b62c293686ca3c1e319dde9d0aa489a"
     "4b59a9594fc2328bc3deff3c8a0929a369a72b1180a596e016b5ded"}
};

static const unsigned char messages[3][2] = {{0x00}, {0x72}, {0xaf, 0x82}};

static auto hex2bytes(std::string_view hex) -> std::vector<uint8_t>
{
    // Ensure an even number of characters in the string
    if (hex.size() % 2 != 0)
        throw std::invalid_argument("Not a valid hexadecimal string.");
    // Verify only hexadecimal characters
    if (hex.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
        throw std::invalid_argument("Not a valid hexadecimal string.");
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    uint8_t byte;
    auto hex_ptr = hex.data();
    for (size_t i = 0; i < hex.size(); i += 2)
    {
        auto res = std::from_chars(hex_ptr, hex_ptr + 2, byte, 16);
        if (res.ec != std::errc())
            throw std::invalid_argument("Invalid hex character found.");
        bytes.push_back(byte);
        hex_ptr += 2;
    }
    return bytes;
}  // hex2bytes

template <std::size_t Size>
static auto hexToByteArray(std::string_view hex) -> std::array<uint8_t, Size>
{
    auto bytes = hex2bytes(hex);
    if (bytes.size() < Size) throw std::invalid_argument("Invalid hex string.");
    auto byte_array = std::array<uint8_t, Size>{};
    std::copy_n(bytes.begin(), Size, byte_array.begin());
    return byte_array;
}

auto testBasic() -> void
{
    auto vrf_key =
        VRFSecretKey::fromSeed(hexToByteArray<32>(test_data[0].seed));
    auto proof = vrf_key.constructProof(messages[0]);
    auto vrf_pkey = vrf_key.publicKey();
    TEST_ASSERT_THROW(vrf_pkey.verifyProof(messages[0], proof));
    TEST_ASSERT_THROW(vrf_key.hash(messages[0]) == vrf_key.proofToHash(proof));
}

// This test is based on the test included in the Cardano fork of libsodium.
auto testAdvanced() -> void
{
    for (size_t i = 0U; i < (sizeof test_data) / (sizeof test_data[0]); i++)
    {
        // Create the key pair from the seed.
        auto vrf_skey =
            VRFSecretKey::fromSeed(hexToByteArray<32>(test_data[i].seed));

        auto vrf_pkey = vrf_skey.publicKey();
        TEST_ASSERT_THROW(
            vrf_pkey.bytes() == hexToByteArray<32>(test_data[i].pubk)
        );

        // Create the proof.
        auto proof = vrf_skey.constructProof({messages[i], i});
        TEST_ASSERT_THROW(proof == hexToByteArray<80>(test_data[i].proof));

        // Verify the proof.
        TEST_ASSERT_THROW(vrf_pkey.verifyProof({messages[i], i}, proof));

        // Check the proof hash.
        auto hash = vrf_skey.hash({messages[i], i});
        TEST_ASSERT_THROW(hash == hexToByteArray<64>(test_data[i].hash));

        // Verify the proof does not work when the proof is modified.

        proof[0] ^= 0x01;  // bad gamma
        TEST_ASSERT_THROW(!vrf_pkey.verifyProof({messages[i], i}, proof));
        proof[0] ^= 0x01;

        proof[32] ^= 0x01;  // bad c value
        TEST_ASSERT_THROW(!vrf_pkey.verifyProof({messages[i], i}, proof));
        proof[32] ^= 0x01;

        proof[48] ^= 0x01;  // bad s value
        TEST_ASSERT_THROW(!vrf_pkey.verifyProof({messages[i], i}, proof));
        proof[48] ^= 0x01;

        proof[79] ^= 0x80;  // bad s value (high-order-bit flipped)
        TEST_ASSERT_THROW(!vrf_pkey.verifyProof({messages[i], i}, proof));
        proof[79] ^= 0x80;

        if (i > 0)
        {
            // Verify should fail with truncated message.
            TEST_ASSERT_THROW(!vrf_pkey.verifyProof({messages[i], i - 1}, proof)
            );
        }
    }
}

auto main() -> int
{
    testBasic();
    testAdvanced();
    return 0;
}