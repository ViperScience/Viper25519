# Viper Ed25519
[![build](https://gitlab.com/viper-staking/ed25519-viper/badges/main/pipeline.svg)](https://gitlab.com/viper-staking/ed25519-viper/-/commits/main)
[![codecov](https://codecov.io/gl/viper-staking/ed25519-viper/branch/main/graph/badge.svg?token=B7F7UR16TG)](https://codecov.io/gl/viper-staking/ed25519-viper)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An implementation of the Ed25519 elliptic curve digital signature standard in
modern C++. The library is largley based on the popular [Ed25519-donna](https://github.com/floodyberry/ed25519-donna) constant 
time implementation with support for
[extended private keys](https://raw.githubusercontent.com/input-output-hk/adrestia/master/docs/static/Ed25519_BIP.pdf).

## Basic Usage
The Viper-Ed25519 library wraps the Ed25519 capability in three classes: `Ed25519PrivateKey`, `Ed25519PublicKey`, and `Ed25519ExtendedPrivateKey`. Examples of how to use these classes are demonstrated below. The examples assume the following to be at the top of the source file.

    #include <ed25519-viper/ed25519.hpp>
    using namespace ed25519; // the key objects exist within this namespace

### Generating Keys

    // Create a standard Ed25519 private key.
    auto key = Ed25519PrivateKey::generate();

    // Extend to an Extended Ed25519 private key
    auto ext_key = ed25519_key.extend();
    // Or create from scratch
    auto ext_key = Ed25519ExtendedPrivateKey::generate();

    // Derive the public key
    auto pub_key = key.publicKey();
    // Or from extended key
    auto pub_key = ext_key.publicKey();

### Generating Signatures

    // Create a message of bytes to sign
    auto msg = std::vector<uint8_t>();
    // fill msg...

    // Create a signature of the message with the key
    auto sig = key.sign(msg);
    // Or
    auto sig = ext_key.sign(msg);

### Verifying Signatures

    auto check = pub.verify(sig);

### Loading Keys

Existing keys may also be loaded into the constructors of each object as span of bytes.

    // Private key bytes may be loaded from any container type.
    auto pkey_bytes = std::array<uint8_t, 32>{...}; // <- load key bytes here
    auto ext_pkey_bytes = std::vector<uint8_t>(64);
    // fill ext_pkey_bytes ...

    auto key = Ed25519PrivateKey(pkey_bytes);
    auto ext_key = Ed25519ExtendedPrivateKey(ext_pkey_bytes);

## Building from source
While the primary intent of the Viper-Ed25519 library is to provide source files 
that may be included in modern C++ projects, the code may also be complied as a 
standalon library and linked separately to your project.

The following demonstrates how to build the Viper-Ed25519 library from source 
using CMake, including running unit tests and installation.

    git clone https://gitlab.com/viper-staking/viper-ed25519.git
    cd viper-ed25519
    mkdir build && cd build \
    cmake -DCMAKE_BUILD_TYPE=Release ..
    make -j 8
    make test
    make install

A Docker build option is also provided for a complete example that includes 
dependency installation.

    git clone https://gitlab.com/viper-staking/viper-ed25519.git
    cd viper-ed25519
    docker build -t com.viperscience.viper-ed25519:latest .

## Dependencies
The Viper-Ed25519 library links with Botan for SHA-512 hasing capability.

* [Botan-2](https://botan.randombit.net/)

The provided Docker file demonstrates how to build and install the required 
dependencies and Cmake find scripts are also provided.

## Related Projects

The Viper-Ed25519 library was originally started as part of the 
[libcardano](https://gitlab.com/viper-staking/libcardano) project.
