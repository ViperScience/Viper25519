// Copyright (c) 2024 Viper Science LLC
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#ifndef VIPER25519_ERRORS_HPP_
#define VIPER25519_ERRORS_HPP_

#include <stdexcept>
#include <string>

namespace ed25519
{

// This error occurs when a base signature (ed25519) is invalid.
// Ed25519Signature(String),

/// This error occurs when a slice of bytes is converted into a compressed point
/// format, and it fails.
class Ed25519InvalidCompressedFormat : public std::exception
{
  public:
    char* what() { return ""; }
};

/// Error occurs when the size of the secret key is not the expected.
// class InvalidSecretKeySize : public std::exception
// {
//   private:
//     std::string message_;
//
//   public:
//     InvalidSecretKeySize(size_t sz) : message(sz) {}
//     char* what() { return message_.c_str(); } // std::to_string(sz)
// };

//     (usize),
//     /// Error occurs when the size of the public key is not the expected.
//     InvalidPublicKeySize(usize),
//     /// Error occurs when the size of the signature is not the expected.
//     InvalidSignatureSize(usize),
//     /// Error occurs when the period associated with a signature is higher
//     than the threshold
//     /// allowed by the given `Depth`.
//     InvalidSignatureCount(usize, Depth),
//     /// Error that occurs when some expected data is found in an only zero
//     slice. DataInZeroArea,
//     /// This error occurs when a key that cannot be updated (the period has
//     reached the allowed
//     /// threshold) tries to be updated.
//     KeyCannotBeUpdatedMore,
//     /// This error occurs when the comparison of two hashes that are expected
//     to be equal fail. InvalidHashComparison,

// class Ed25519InvalidCompressedFormat : public std::exception
// {
//   private:
//     char* message;
//
//   public:
//     MyCustomException(char* msg) : message(msg) {}
//     char* what() { return message; }
// };

}  // namespace ed25519

#endif  // VIPER25519_ERRORS_HPP_