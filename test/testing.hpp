#include <iomanip>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>

#define TEST_ASSERT_THROW( condition )                              \
{                                                                   \
  if( !( condition ) )                                              \
  {                                                                 \
    throw std::runtime_error(   std::string( __FILE__ )             \
                              + std::string( ":" )                  \
                              + std::to_string( __LINE__ )          \
                              + std::string( " in " )               \
                              + std::string( __PRETTY_FUNCTION__ )  \
    );                                                              \
  }                                                                 \
}

#define TEST_ASSERT_EQUAL( x, y )                                   \
{                                                                   \
  if( ( x ) != ( y ) )                                              \
  {                                                                 \
    throw std::runtime_error(   std::string( __FILE__ )             \
                              + std::string( ":" )                  \
                              + std::to_string( __LINE__ )          \
                              + std::string( " in " )               \
                              + std::string( __PRETTY_FUNCTION__ )  \
                              + std::string( ": " )                 \
                              + std::to_string( ( x ) )             \
                              + std::string( " != " )               \
                              + std::to_string( ( y ) )             \
    );                                                              \
  }                                                                 \
}

#define TEST_TEST_BEGIN( name )                                     \
{                                                                   \
  std::cerr << "-- Running test \"" << name << "\"...";             \
}

#define TEST_TEST_END()                                             \
{                                                                   \
  std::cerr << "finished\n";                                        \
}

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

static void print_bignum(std::span<const uint64_t> data)
{
    for (auto v : data)
    {
        std::cout << "0x" << std::hex << std::setfill('0') << std::setw(16)
                  << v << " ";
    }
    std::cout << std::endl;
}

static void print_sbytes(std::span<const int8_t> data, size_t line_width = 16)
{
    size_t counter = 0;
    for (auto v : data)
    {
        std::cout << std::setfill('0') << std::setw(3)
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