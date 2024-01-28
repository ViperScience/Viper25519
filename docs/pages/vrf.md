@page vrf-info VRF

Verifyable Random Functions (VRFs) are defined by the IETF in [RFC9381](https://datatracker.ietf.org/doc/rfc9381/) as
> A Verifiable Random Function (VRF) is the public key version of a
> keyed cryptographic hash.  Only the holder of the secret key can
> compute the hash, but anyone with the public key can verify the
> correctness of the hash.

The VRF implementation within viper25519 is based on that from the [Cardano fork of libsodum](https://github.com/IntersectMBO/libsodium/tree/iquerejeta/vrf_batchverify), which is itself based off of the [Algorand fork of libsodium](https://github.com/algorand/libsodium/tree/draft-irtf-cfrg-vrf-03).
While the elliptic curve functions within viper25519 provide much of the required functionality in order to implement an ed25519 key based VRF, it does not contain an implementation of [Elligator-2](https://elligator.cr.yp.to/elligator-20130828.pdf) hashing, which is used in the VRF implementation.
Thus, viper25519 links with the libsodium fork to gain the basic VRF implementations.

The viper25519 VRF implementation follows the libsodium implementation which deviates slightly from that defined in RFC9381. Specifically, the private key stores both the private and public key concatenated as a 64 byte vector in order to improve the efficiency of the computation.
More details may be found in the Algorand libsodium fork [readme](https://github.com/algorand/libsodium/blob/draft-irtf-cfrg-vrf-03/src/libsodium/crypto_vrf/ietfdraft03/README).  

@subsection vrf-cardano-compatibility Cardano Compatibility
The Cardano blockchain uses the IETF draft 03 version of the VRF code for stake pools keys.
Thus, the viper25519 VRF functions call the libsodium functions prefixed with `crypto_vrf_ietfdraft03_`.
