########################################################################
# Test the Viper Ed25519 API
########################################################################

set(TEST_VIPER_ED25519_API_SOURCES 
    test_viper_ed25519_api.cpp
    ${CMAKE_SOURCE_DIR}/src/ed25519.cpp
    ${CMAKE_SOURCE_DIR}/src/curve25519.cpp
)
add_executable(test_api ${TEST_VIPER_ED25519_API_SOURCES})
target_link_libraries(test_api PRIVATE
    botan::botan
    Threads::Threads
    OpenSSL::SSL
)
ADD_TEST("Viper25519 Ed25519 API" test_api)

########################################################################
# Run all individual tests for debugging scenarios
########################################################################
if(RUN_ALL_TESTS)

########################################################################
# Test the key generation capabilities
########################################################################

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

########################################################################
# Test basic signature capabilities
########################################################################

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

########################################################################
# Test the Curve25519 internals
########################################################################

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

########################################################################
# Test the Bignum25519 primitives
########################################################################

add_executable(test_bignum25519 test_viper_ed25519_bignum25519.cpp)
target_link_libraries(test_bignum25519 PRIVATE
    botan::botan
    Threads::Threads
    OpenSSL::SSL
)
ADD_TEST(Bignum25519 test_bignum25519)

########################################################################
# Test the Curve25519 primitives
########################################################################

add_executable(test_curve25519 test_viper_ed25519_curve25519.cpp)
target_link_libraries(test_curve25519 PRIVATE
    botan::botan
    Threads::Threads
    OpenSSL::SSL
)
ADD_TEST(Curve25519 test_curve25519)

########################################################################
# Recreate tests from the original ed25519-donna code.
########################################################################

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

########################################################################
# Test VRF Capabilities.
########################################################################

set(TEST_VIPER_ED25519_VRF_SOURCES
    test_viper_ed25519_vrf.cpp
    ${CMAKE_SOURCE_DIR}/src/vrf25519.cpp
    ${CMAKE_SOURCE_DIR}/src/ed25519.cpp
    ${CMAKE_SOURCE_DIR}/src/curve25519.cpp
)
add_executable(test_vrf ${TEST_VIPER_ED25519_VRF_SOURCES})
target_link_libraries(test_vrf PRIVATE
    botan::botan
    Threads::Threads
    OpenSSL::SSL
    sodium::sodium
)
ADD_TEST("VRF Tests" test_vrf)

########################################################################
endif()