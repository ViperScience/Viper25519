// Repeat tests defined at
// https://github.com/floodyberry/ed25519-donna/blob/master/test.c

#include <ed25519-viper/curve25519.hpp>
#include <test/testing.hpp>

#include <iomanip>
#include <iostream>
#include <span>

static void print_bytes(std::span<const uint8_t> data, size_t line_width = 16)
{
    size_t counter = 0;
    for (auto v : data)
    {
        std::cout << "0x" << std::hex << std::setfill('0') << std::setw(2)
                  << (int)v << " ";
        counter++;
        if (counter > line_width - 1)
        {
            std::cout << std::endl;
            counter = 0;
        }
    }
    std::cout << std::endl;
}

auto testBasepoint() -> void
{
    // result of the curve25519 scalarmult ((|255| * basepoint) * basepoint)...
    // 1024 times
    static constexpr auto curved25519_expected = std::array<uint8_t, 32>{
        0xac, 0xce, 0x24, 0xb1, 0xd4, 0xa2, 0x36, 0x21, 0x15, 0xe2, 0x3e,
        0x84, 0x3c, 0x23, 0x2b, 0x5f, 0x95, 0x6c, 0xc0, 0x7b, 0x95, 0x82,
        0xd7, 0x93, 0xd5, 0x19, 0xb6, 0xf1, 0xfb, 0x96, 0xd6, 0x04};

    auto csk = std::array<std::array<uint8_t, 32>, 2>{{{255}}};
    //for (auto &a : csk) a.fill(255);

    for (uint32_t i = 0; i < 1024; i++)
        csk[(i & 1) ^ 1] = curve25519::scalarmult_basepoint(csk[i & 1]);

    print_bytes(csk[0]);
    print_bytes(csk[1]);
    print_bytes(curved25519_expected);

    TEST_ASSERT_THROW(csk[0] == curved25519_expected)
}

auto testAdvanced() -> void { TEST_ASSERT_THROW(true) }

auto main() -> int
{
    testBasepoint();
    testAdvanced();
    return 0;
}