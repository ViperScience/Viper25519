// Copyright (c) 2022 Viper Science LLC
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

#ifndef _VIPER25519_CURVE25519_HPP_
#define _VIPER25519_CURVE25519_HPP_

#include <array>
#include <cstdint>
#include <span>

namespace curve25519
{

struct bignum25519 : public std::array<uint64_t, 5>
{
    // move these out of the bignum25519 struct
    static constexpr auto ecd() -> bignum25519
    {
        return {
            0x00034dca135978a3, 0x0001a8283b156ebd, 0x0005e7a26001c029,
            0x000739c663a03cbb, 0x00052036cee2b6ff};
    }

    static constexpr auto ec2d() -> bignum25519
    {
        return {
            0x00069b9426b2f159, 0x00035050762add7a, 0x0003cf44c0038052,
            0x0006738cc7407977, 0x0002406d9dc56dff};
    }

    static constexpr auto sqrtneg1() -> bignum25519
    {
        return {
            0x00061b274a0ea0b0, 0x0000d5a5fc8f189d, 0x0007ef5e9cbd0c60,
            0x00078595a6804c9e, 0x0002b8324804fc1d};
    }

    static auto expand(std::span<const uint8_t> in) -> bignum25519;

    static auto contract(const bignum25519 &input) -> std::array<uint8_t, 32>;

    /// @brief returns out = a + b
    constexpr auto add(bignum25519 const &rhs) const -> bignum25519
    {
        auto out = *this;
        for (size_t i = 0; i < this->size(); ++i) out[i] += rhs[i];
        return out;
    }  // bignum25519::add

    constexpr auto operator+(bignum25519 const &rhs) const -> bignum25519
    {
        return this->add(rhs);
    }  // operator +

    auto addReduce(bignum25519 const &rhs) const -> bignum25519;

    auto sub(bignum25519 const &rhs) const -> bignum25519;

    auto operator-(bignum25519 const &rhs) const -> bignum25519;

    auto subReduce(bignum25519 const &rhs) const -> bignum25519;

    auto subAfterBasic(bignum25519 const &rhs) const -> bignum25519;

    auto neg() const -> bignum25519;

    auto mul(bignum25519 const &rhs) const -> bignum25519;

    auto operator*(bignum25519 const &rhs) const -> bignum25519;

    auto square() const -> bignum25519;

    auto squareTimes(uint64_t count) const -> bignum25519;

    auto pow_two252m3() const -> bignum25519;

    // In:  b =   2^5 - 2^0
    // Out: b = 2^250 - 2^0
    auto pow_two5mtwo0_two250mtwo0() const -> bignum25519;

    auto recip() const -> bignum25519;

    //////////////////////////////////////////////////////////////////////////////
    //
    // Arithmetic modulo the group order
    // n = 2^252 + 27742317777372353535851937790883648493
    //   =
    // 7237005577332262213973186563042994240857116359379907606001950938285454250989
    //
    // k = 32
    // b = 1 << 8 = 256
    // m = 2^252 + 27742317777372353535851937790883648493
    //   = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
    // mu = floor( b^(k*2) / m )
    //    = 0xfffffffffffffffffffffffffffffffeb2106215d086329a7ed9ce5a30a2c131b
    //
    //////////////////////////////////////////////////////////////////////////////

    static auto reduce256_modm(const bignum25519 &r) -> bignum25519;

    static auto barrett_reduce256_modm(
        const bignum25519 &q1, const bignum25519 &r1
    ) -> bignum25519;

    static auto add256_modm(const bignum25519 &lhs, const bignum25519 &rhs)
        -> bignum25519;

    static auto mul256_modm(const bignum25519 &lhs, const bignum25519 &rhs)
        -> bignum25519;

    static auto expand256_modm(std::span<const uint8_t> in) -> bignum25519;

    static auto expand_raw256_modm(std::array<uint8_t, 32> const &in)
        -> bignum25519;

    static auto contract256_modm(bignum25519 const &in)
        -> std::array<uint8_t, 32>;

};  // bignum25519

// The following classes represent points on the Ed25519 curve stored in various
// forms. Here the EC group is the set of pairs (x,y) of field elements
// satisfying -x^2 + y^2 = 1 + d x^2y^2 where d = -121665/121666.
class CompletedPoint;
class ExtendedPoint;
class PrecomputedPoint;

/// @brief Representation of a point on the Ed25519 curve in partial form.
/// The partial point is stored as a three element array of bignum25519 values:
/// (X, Y, Z) satisfying x=X/Z, y=Y/Z.
class PartialPoint
{
  private:
    std::array<bignum25519, 3> data_{};

  public:
    [[nodiscard]] PartialPoint()
        : PartialPoint({bignum25519{}, bignum25519{}, bignum25519{}})
    {
    }
    [[nodiscard]] explicit PartialPoint(std::array<bignum25519, 3> a)
        : data_{std::move(a)}
    {
    }

    // Overloading [] operator to access elements in array style
    auto operator[](size_t index) const -> bignum25519;

    auto x() const -> bignum25519 { return data_[0]; }
    auto y() const -> bignum25519 { return data_[1]; }
    auto z() const -> bignum25519 { return data_[2]; }

    auto doubleCompleted() const -> CompletedPoint;

    auto doubleExtended() const -> ExtendedPoint;

    auto doublePartial() const -> PartialPoint;

};  // class PartialPoint

/// @brief Representation of a point on the Ed25519 curve in precomputed form.
/// The point is stored as a three element array of bignum25519 values. The
/// values are stored in precomputed from in order to save some computations
/// later on prior to being converted back to the final point.
class PrecomputedPoint
{
  private:
    std::array<bignum25519, 3> data_{};

  public:
    [[nodiscard]] PrecomputedPoint()
        : PrecomputedPoint({bignum25519{}, bignum25519{}, bignum25519{}})
    {
    }
    [[nodiscard]] explicit PrecomputedPoint(std::array<bignum25519, 3> a)
        : data_{std::move(a)}
    {
    }

    auto xaddy() const -> bignum25519 { return data_[0]; }
    auto ysubx() const -> bignum25519 { return data_[1]; }
    auto t2d() const -> bignum25519 { return data_[2]; }

    // Overloading [] operator to access elements in array style
    auto operator[](size_t index) const -> bignum25519;

    auto set_xaddy(bignum25519 &&nxaddy) -> void
    {
        data_[0] = std::forward<bignum25519>(nxaddy);
    }
    auto set_ysubx(bignum25519 &&nysubx) -> void
    {
        data_[1] = std::forward<bignum25519>(nysubx);
    }
    auto set_t2d(bignum25519 &&nt2d) -> void
    {
        data_[2] = std::forward<bignum25519>(nt2d);
    }
};  // class PackedPoint

/// @brief Representation of a point on the Ed25519 curve in precomputed form.
/// The point is stored as a three element array of bignum25519 values. The
/// values are stored in precomputed from in order to save some computations
/// later on prior to being converted back to the final point.
class ExtendedPrecomputedPoint
{
  private:
    std::array<bignum25519, 4> data_{};

  public:
    [[nodiscard]] ExtendedPrecomputedPoint()
        : ExtendedPrecomputedPoint(
              {bignum25519{}, bignum25519{}, bignum25519{}, bignum25519{}}
          )
    {
    }
    [[nodiscard]] explicit ExtendedPrecomputedPoint(std::array<bignum25519, 4> a
    )
        : data_{std::move(a)}
    {
    }

    auto xaddy() const -> bignum25519 { return data_[0]; }
    auto ysubx() const -> bignum25519 { return data_[1]; }
    auto z() const -> bignum25519 { return data_[2]; }
    auto t2d() const -> bignum25519 { return data_[3]; }

    // Overloading [] operator to access elements in array style
    auto operator[](size_t index) const -> bignum25519;

    auto set_xaddy(bignum25519 &&nxaddy) -> void
    {
        data_[0] = std::forward<bignum25519>(nxaddy);
    }
    auto set_ysubx(bignum25519 &&nysubx) -> void
    {
        data_[1] = std::forward<bignum25519>(nysubx);
    }
    auto set_z(bignum25519 &&nz) -> void
    {
        data_[2] = std::forward<bignum25519>(nz);
    }
    auto set_t2d(bignum25519 &&nt2d) -> void
    {
        data_[3] = std::forward<bignum25519>(nt2d);
    }
};

/// @brief Representation of a point on the Ed25519 curve.
/// The point is stored as a four element array of bignum25519 values:
/// ((X, Y), (Z, T)) satisfying x=X/Z, y=Y/T.
class CompletedPoint
{
  private:
    std::array<bignum25519, 4> data_{};

  public:
    [[nodiscard]] CompletedPoint()
        : CompletedPoint(
              {bignum25519{}, bignum25519{}, bignum25519{}, bignum25519{}}
          )
    {
    }
    [[nodiscard]] explicit CompletedPoint(std::array<bignum25519, 4> a)
        : data_{std::move(a)}
    {
    }

    [[nodiscard]] auto x() const -> bignum25519 { return data_[0]; }
    [[nodiscard]] auto y() const -> bignum25519 { return data_[1]; }
    [[nodiscard]] auto z() const -> bignum25519 { return data_[2]; }
    [[nodiscard]] auto t() const -> bignum25519 { return data_[3]; }

    // Overloading [] operator to access elements in array style
    auto operator[](size_t index) const -> bignum25519;

    auto set_x(bignum25519 &&nx) -> void
    {
        data_[0] = std::forward<bignum25519>(nx);
    }
    auto set_y(bignum25519 &&ny) -> void
    {
        data_[1] = std::forward<bignum25519>(ny);
    }
    auto set_z(bignum25519 &&nz) -> void
    {
        data_[2] = std::forward<bignum25519>(nz);
    }
    auto set_t(bignum25519 &&nt) -> void
    {
        data_[3] = std::forward<bignum25519>(nt);
    }

    auto toPartial() const -> PartialPoint;

    auto toExtended() const -> ExtendedPoint;

};  // class CompletedPoint

/// @brief Representation of a point on the Ed25519 curve.
/// The point is stored as a four element array of bignum25519 values:
/// (X, Y, Z, T) satisfying x=X/Z, y=Y/Z, XY=ZT.
class ExtendedPoint
{
  private:
    std::array<bignum25519, 4> data_{};

  public:
    [[nodiscard]] ExtendedPoint()
        : ExtendedPoint(
              {bignum25519{}, bignum25519{}, bignum25519{}, bignum25519{}}
          )
    {
    }
    [[nodiscard]] explicit ExtendedPoint(std::array<bignum25519, 4> a)
        : data_{std::move(a)}
    {
    }

    [[nodiscard]] auto x() const -> bignum25519 { return data_[0]; }
    [[nodiscard]] auto y() const -> bignum25519 { return data_[1]; }
    [[nodiscard]] auto z() const -> bignum25519 { return data_[2]; }
    [[nodiscard]] auto t() const -> bignum25519 { return data_[3]; }

    auto set_x(bignum25519 &&nx) -> void
    {
        data_[0] = std::forward<bignum25519>(nx);
    }
    auto set_y(bignum25519 &&ny) -> void
    {
        data_[1] = std::forward<bignum25519>(ny);
    }
    auto set_z(bignum25519 &&nz) -> void
    {
        data_[2] = std::forward<bignum25519>(nz);
    }
    auto set_t(bignum25519 &&nt) -> void
    {
        data_[3] = std::forward<bignum25519>(nt);
    }

    // Overloading [] operator to access elements in array style
    auto operator[](size_t index) const -> bignum25519;

    [[nodiscard]] static auto basepoint() -> ExtendedPoint
    {
        auto x = bignum25519{
            0x00062d608f25d51a, 0x000412a4b4f6592a, 0x00075b7171a4b31d,
            0x0001ff60527118fe, 0x000216936d3cd6e5};
        auto y = bignum25519{
            0x0006666666666658, 0x0004cccccccccccc, 0x0001999999999999,
            0x0003333333333333, 0x0006666666666666};
        auto z = bignum25519{
            0x0000000000000001, 0x0000000000000000, 0x0000000000000000,
            0x0000000000000000, 0x0000000000000000};
        auto t = bignum25519{
            0x00068ab3a5b7dda3, 0x00000eea2a5eadbb, 0x0002af8df483c27e,
            0x000332b375274732, 0x00067875f0fd78b7};
        return ExtendedPoint({x, y, z, t});
    }  // ExtendedPoint::basepoint

    [[nodiscard]] auto add(ExtendedPoint const &rhs) const -> CompletedPoint;

    [[nodiscard]] auto add(PrecomputedPoint const &q) const -> ExtendedPoint;

    [[nodiscard]] auto add(ExtendedPrecomputedPoint const &q) const
        -> ExtendedPrecomputedPoint;

    [[nodiscard]] auto add(
        ExtendedPrecomputedPoint const &q, uint8_t const signbit
    ) const -> CompletedPoint;

    [[nodiscard]] auto add(PrecomputedPoint const &q, uint8_t const signbit)
        const -> CompletedPoint;

    [[nodiscard]] auto add2(PrecomputedPoint const &q) -> ExtendedPoint &;

    auto operator+(ExtendedPoint const &rhs) const -> ExtendedPoint;

    auto operator+(PrecomputedPoint const &rhs) const -> ExtendedPoint;

    auto operator+=(PrecomputedPoint const &rhs) -> ExtendedPoint &;

    // auto toCompleted() const -> CompletedPoint;

    auto toPrecomputedExtendedPoint() const -> ExtendedPrecomputedPoint;

    auto doubleCompleted() const -> CompletedPoint;

    auto doublePartial() const -> PartialPoint;

    auto doubleExtended() const -> ExtendedPoint;

    /// @brief Computes [s1]p1 + [s2]basepoint
    auto doubleScalarMultiple(bignum25519 const &s1, bignum25519 const &s2)
        const -> ExtendedPoint;

    /// @brief Computes [s]B
    /// Compute [s]B where B is the curve 25519 basepoint and [s] is a scalar.
    [[nodiscard]] static auto multiplyBasepointByScalar(bignum25519 const &s)
        -> ExtendedPoint;

    auto pack() const -> std::array<uint8_t, 32>;

    [[nodiscard]] static auto unpack(std::span<const uint8_t> p)
        -> ExtendedPoint;

};  // class ExtendedPoint

// This function is largely just used for testing.
auto scalarmult_basepoint(std::array<uint8_t, 32> pk)
    -> std::array<uint8_t, 32>;

}  // namespace curve25519

#endif  // _VIPER25519_CURVE25519_HPP_