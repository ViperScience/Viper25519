# MIT License
#
# Copyright (c) 2022-2024 Viper Staking
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(VIPER25519_LINK_LIBS
    botan::botan
    Threads::Threads
    OpenSSL::SSL
    sodium::sodium
)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

Include(FetchContent)

FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.5.4
)

FetchContent_MakeAvailable(Catch2)

# #######################################################################
# Test the Ed25519 API
# #######################################################################
set(TEST_VIPER_ED25519_API_SOURCES
    test_viper_ed25519_api.cpp
    ${CMAKE_SOURCE_DIR}/src/ed25519.cpp
    ${CMAKE_SOURCE_DIR}/src/curve25519.cpp
)
add_executable(test_api ${TEST_VIPER_ED25519_API_SOURCES})
target_link_libraries(test_api PRIVATE ${VIPER25519_LINK_LIBS})
ADD_TEST("Viper25519 Ed25519 API" test_api)

# #######################################################################
# Test the VRF API
# #######################################################################
set(TEST_VIPER_ED25519_VRF_SOURCES
    test_viper_ed25519_vrf.cpp
    ${CMAKE_SOURCE_DIR}/src/vrf25519.cpp
    ${CMAKE_SOURCE_DIR}/src/ed25519.cpp
    ${CMAKE_SOURCE_DIR}/src/curve25519.cpp
)
add_executable(test_vrf ${TEST_VIPER_ED25519_VRF_SOURCES})
target_link_libraries(test_vrf PRIVATE ${VIPER25519_LINK_LIBS} sodium::sodium)
ADD_TEST("VRF Tests" test_vrf)

# #######################################################################
# Test the KES API
# #######################################################################
add_executable(test_kes
    test_viper_ed25519_kes.cpp
    ${CMAKE_SOURCE_DIR}/src/kes25519.cpp
    ${CMAKE_SOURCE_DIR}/src/ed25519.cpp
    ${CMAKE_SOURCE_DIR}/src/curve25519.cpp
)
target_link_libraries(test_kes PRIVATE ${VIPER25519_LINK_LIBS} Catch2::Catch2WithMain)
ADD_TEST("KES Tests" test_kes)

# #######################################################################
# Run all individual tests for debugging scenarios
# #######################################################################
if(RUN_ALL_TESTS)
    # #######################################################################
    # Test the key generation capabilities
    # #######################################################################
    set(TEST_VIPER_ED25519_KEY_GEN_SOURCES
        test_viper_ed25519_key_gen.cpp
        ${CMAKE_SOURCE_DIR}/src/ed25519.cpp
        ${CMAKE_SOURCE_DIR}/src/curve25519.cpp
    )
    add_executable(test_key_gen ${TEST_VIPER_ED25519_KEY_GEN_SOURCES})
    target_link_libraries(test_key_gen PRIVATE
        botan::botan
        Threads::Threads
        OpenSSL::SSL
    )
    ADD_TEST("Key Generation" test_key_gen)

    # #######################################################################
    # Test basic signature capabilities
    # #######################################################################
    set(TEST_VIPER_ED25519_SIGNATURES_SOURCES
        test_viper_ed25519_signatures.cpp
        ${CMAKE_SOURCE_DIR}/src/ed25519.cpp
        ${CMAKE_SOURCE_DIR}/src/curve25519.cpp
    )
    add_executable(test_signatures ${TEST_VIPER_ED25519_SIGNATURES_SOURCES})
    target_link_libraries(test_signatures PRIVATE
        botan::botan
        Threads::Threads
        OpenSSL::SSL
    )
    ADD_TEST(Signatures test_signatures)

    # #######################################################################
    # Test the Curve25519 internals
    # #######################################################################
    set(TEST_VIPER_ED25519_INTERNALS_SOURCES
        test_viper_ed25519_internals.cpp
        ${CMAKE_SOURCE_DIR}/src/ed25519.cpp
        ${CMAKE_SOURCE_DIR}/src/curve25519.cpp
    )
    add_executable(test_internals ${TEST_VIPER_ED25519_INTERNALS_SOURCES})
    target_link_libraries(test_internals PRIVATE
        botan::botan
        Threads::Threads
        OpenSSL::SSL
    )
    ADD_TEST(Internals test_internals)

    # #######################################################################
    # Test the Bignum25519 primitives
    # #######################################################################
    add_executable(test_bignum25519 test_viper_ed25519_bignum25519.cpp)
    target_link_libraries(test_bignum25519 PRIVATE
        botan::botan
        Threads::Threads
        OpenSSL::SSL
    )
    ADD_TEST(Bignum25519 test_bignum25519)

    # #######################################################################
    # Test the Curve25519 primitives
    # #######################################################################
    add_executable(test_curve25519 test_viper_ed25519_curve25519.cpp)
    target_link_libraries(test_curve25519 PRIVATE
        botan::botan
        Threads::Threads
        OpenSSL::SSL
    )
    ADD_TEST(Curve25519 test_curve25519)

    # #######################################################################
    # Recreate tests from the original ed25519-donna code.
    # #######################################################################
    set(TEST_VIPER_ED25519_DONNA_SOURCES
        test_viper_ed25519_donna.cpp
        ${CMAKE_SOURCE_DIR}/src/ed25519.cpp
        ${CMAKE_SOURCE_DIR}/src/curve25519.cpp
    )
    add_executable(test_donna ${TEST_VIPER_ED25519_DONNA_SOURCES})
    target_link_libraries(test_donna PRIVATE
        botan::botan
        Threads::Threads
        OpenSSL::SSL
    )
    ADD_TEST("Ed25519 Donna Tests" test_donna)

    # #######################################################################
endif()