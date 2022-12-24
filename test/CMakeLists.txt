########################################################################
# Test the key generation capabilities
########################################################################

set(TEST_VIPER_ED25519_KEY_GEN_SOURCES 
    test_viper_ed25519_key_gen.cpp
    ${CMAKE_SOURCE_DIR}/src/ed25519.cpp
    ${CMAKE_SOURCE_DIR}/src/curve25519.cpp
)
ADD_EXECUTABLE(test_key_gen ${TEST_VIPER_ED25519_KEY_GEN_SOURCES})
target_link_libraries(test_key_gen PRIVATE
    botan::botan
    Threads::Threads
)
ADD_TEST(Key_Generation test_key_gen)

########################################################################
# Test basic signature capabilities
########################################################################

set(TEST_VIPER_ED25519_SIGNATURES_SOURCES 
    test_viper_ed25519_signatures.cpp
    ${CMAKE_SOURCE_DIR}/src/ed25519.cpp
    ${CMAKE_SOURCE_DIR}/src/curve25519.cpp
)
ADD_EXECUTABLE(test_signatures ${TEST_VIPER_ED25519_SIGNATURES_SOURCES})
target_link_libraries(test_signatures PRIVATE
    botan::botan
    Threads::Threads
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
ADD_EXECUTABLE(test_internals ${TEST_VIPER_ED25519_INTERNALS_SOURCES})
target_link_libraries(test_internals PRIVATE
    botan::botan
    Threads::Threads
)
ADD_TEST(Internals test_internals)

########################################################################
# Test the Bignum25519 primitives
########################################################################

ADD_EXECUTABLE(test_bignum25519 test_viper_ed25519_bignum25519.cpp)
target_link_libraries(test_bignum25519 PRIVATE
    botan::botan
    Threads::Threads
)
ADD_TEST(Bignum25519 test_bignum25519)

########################################################################
# Test the Curve25519 primitives
########################################################################

ADD_EXECUTABLE(test_curve25519 test_viper_ed25519_curve25519.cpp)
target_link_libraries(test_curve25519 PRIVATE
    botan::botan
    Threads::Threads
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
ADD_EXECUTABLE(test_donna ${TEST_VIPER_ED25519_DONNA_SOURCES})
target_link_libraries(test_donna PRIVATE
    botan::botan
    Threads::Threads
)
ADD_TEST(Ed25519_Donna_Tests test_donna)