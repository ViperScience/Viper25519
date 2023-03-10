FROM debian:bookworm

RUN apt-get update && apt-get install -y \
    git \
    curl \
    libssl-dev \
    libbotan-2-dev \
    build-essential \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Install the newer version of CMake
RUN curl -LO https://github.com/Kitware/CMake/releases/download/v3.25.1/cmake-3.25.1-linux-x86_64.tar.gz \
 && tar --extract --file cmake-3.25.1-linux-x86_64.tar.gz \
 && mv cmake-3.25.1-linux-x86_64/bin/* /usr/local/bin \
 && mv cmake-3.25.1-linux-x86_64/share/cmake-3.25 /usr/local/share/

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
