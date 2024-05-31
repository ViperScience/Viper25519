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

cmake_minimum_required(VERSION 3.23)

# set the project name, language,  and version
project(viper25519
    DESCRIPTION "C++ development toolkit for ECDSA signatures and secret/public key operations on elliptic curve 25519."
    VERSION 1.0.0
    LANGUAGES CXX
)

# Default to Release build type if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release")
endif()

################################################################################
# Additional packages
################################################################################

# Include a thread library for linking that is specific to the platform.
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# Add the local cmake directory to the path for custom search files
list(INSERT CMAKE_MODULE_PATH 0 ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# Load static libraries since we are building a static library
if(WIN32)
    list(INSERT CMAKE_FIND_LIBRARY_SUFFIXES 0 .lib .a)
else()
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
endif()

# Add 3rd party libraries that should be installed on the system
find_package(Botan REQUIRED)

# Add libsodium
set(sodium_USE_STATIC_LIBS ON)
find_package(Sodium REQUIRED)

################################################################################
# Define the Library Target
################################################################################

# Specify the Viper-Ed25519 source files (including submodules)
set(VIPER25519_SOURCES
    ${CMAKE_SOURCE_DIR}/src/curve25519.cpp
    ${CMAKE_SOURCE_DIR}/src/ed25519.cpp
    ${CMAKE_SOURCE_DIR}/src/vrf25519.cpp
    ${CMAKE_SOURCE_DIR}/src/kes25519.cpp
)

# Add the library to build but do not specify STATIC vs. SHARED. A shared
# library will be built if CMake is run with: -DBUILD_SHARED_LIBS=ON
add_library(${PROJECT_NAME} ${VIPER25519_SOURCES})
add_library(${PROJECT_NAME}::${PROJECT_NAME} ALIAS ${PROJECT_NAME})

################################################################################
# Include directories
################################################################################

# Make cache variables for install destinations
include(GNUInstallDirs)

target_include_directories(${PROJECT_NAME}
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# Note: We need to tell CMake that we want to use different include directories
# depending on if we're building the library or using it from an installed
# location.

################################################################################
# Additional Target Properties
################################################################################

set_target_properties(${PROJECT_NAME} PROPERTIES
    COMPILE_WARNING_AS_ERROR ON
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED ON
)

# if(MSVC)
#     target_compile_options(${PROJECT_NAME} PRIVATE /W4 /WX)
# else()
#     target_compile_options(${PROJECT_NAME} PRIVATE
#         -Wall -Wextra -Wpedantic -Wshadow -Wconversion
#         "$<$<CONFIG:DEBUG>:-g;-O0;--coverage>"
#     )
#     add_link_options(
#         "$<$<CONFIG:DEBUG>:--coverage>"
#     )
# endif()

if(MSVC)
    # target_compile_options(${PROJECT_NAME} PRIVATE /W4 /WX)
else()
    target_compile_options(${PROJECT_NAME} PRIVATE
        # -Wall # -Wextra -Wpedantic -Wshadow -Wconversion
    )
endif()

################################################################################
# Link
################################################################################

# Specify libraries for linking
target_link_libraries(${PROJECT_NAME} PRIVATE
    botan::botan
    Threads::Threads
    OpenSSL::SSL
    sodium::sodium
)

################################################################################
# Tests
################################################################################

# Enable testing globally. Individual tests may be found in the `tests`
# subdirectory of the repository.
option(RUN_ALL_TESTS "Run all the unittests (mainly for debugging)" OFF)

# Enable testing only if this is the top level project.
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    include(CTest)
endif()
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING)
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/CTestCustom.cmake.in
        ${CMAKE_BINARY_DIR}/CTestCustom.cmake
    )

    # Individual tests may be found in the `tests`subdirectory of the
    # repository.
    add_subdirectory(test)
endif()

################################################################################
# Install the Target
################################################################################
set(PROJECT_NAME_TARGETS ${PROJECT_NAME}Targets)

# # Install the library file.
# install(TARGETS ${PROJECT_NAME}
# EXPORT ${PROJECT_NAME_TARGETS}
# LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
# ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
# RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
# INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cardano
# )

# Install the header files. Use lowercase for the directory name.
set(VIPER_ED25519_HEADERS
    ${CMAKE_SOURCE_DIR}/include/ed25519-viper/ed25519.hpp
    ${CMAKE_SOURCE_DIR}/include/ed25519-viper/curve25519.hpp
)

# install(FILES ${CARDANO_HEADERS}
# DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cardano
# )

################################################################################
# Install the CMake Target files
################################################################################

# # Install the CMake files required in order to use `find_package(Cardano)`
# install(EXPORT ${PROJECT_NAME_TARGETS}
# FILE ${PROJECT_NAME_TARGETS}.cmake
# NAMESPACE ${PROJECT_NAME}::
# DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
# )

# include(CMakePackageConfigHelpers)

# configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/Config.cmake.in
# "${CMAKE_CURRENT_BINARY_DIR}/CardanoConfig.cmake"
# INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
# )
# write_basic_package_version_file(
# "${CMAKE_CURRENT_BINARY_DIR}/CardanoConfigVersion.cmake"
# VERSION ${PROJECT_VERSION}
# COMPATIBILITY SameMajorVersion
# )

# install(FILES
# "${CMAKE_CURRENT_BINARY_DIR}/CardanoConfig.cmake"
# "${CMAKE_CURRENT_BINARY_DIR}/CardanoConfigVersion.cmake"
# DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
# )