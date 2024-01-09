FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y \
  autoconf \
  automake \
  build-essential \
  curl \
  git \
  libssl-dev \
  libtool \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# Install the newer version of CMake
RUN curl -LO https://github.com/Kitware/CMake/releases/download/v3.25.1/cmake-3.25.1-linux-x86_64.tar.gz \
  && tar --extract --file cmake-3.25.1-linux-x86_64.tar.gz \
  && mv cmake-3.25.1-linux-x86_64/bin/* /usr/local/bin \
  && mv cmake-3.25.1-linux-x86_64/share/cmake-3.25 /usr/local/share/

# Build and install Botan 3
WORKDIR /tmp
RUN curl -LO https://botan.randombit.net/releases/Botan-3.1.1.tar.xz \
  && tar --extract --file Botan-3.1.1.tar.xz \
  && cd Botan-3.1.1 \
  && python3 ./configure.py \
  && make -j8 \
  && make install \
  && cd .. && rm -rf Botan*

# Install the Cardano fork of libsodium
WORKDIR /tmp
RUN git clone https://github.com/input-output-hk/libsodium \
  && cd libsodium \
  && git checkout dbb48cc \
  && ./autogen.sh \
  && ./configure \
  && make -j8 \
  && make install \
  && cd .. && rm -rf libsodium
RUN export LD_LIBRARY_PATH="/usr/local/lib:$LD_LIBRARY_PATH" \
  && export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH"

COPY . /opt
WORKDIR /opt

# Debug build and test
RUN cmake -S . -B cmake-build-debug/ -D CMAKE_BUILD_TYPE=Debug \
  && cmake --build cmake-build-debug/ --parallel 8 \
  && ctest --test-dir cmake-build-debug/ --output-on-failure -T Test -T Coverage

# Release build and test
# RUN cmake -S . -B cmake-build-release/ -D CMAKE_BUILD_TYPE=Release \
#   && cmake --build cmake-build-release/ --parallel 8 \
#   && ctest --test-dir cmake-build-release/ --output-on-failure -T Test
