FROM python:3.9-slim-bullseye

RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    gdb \
    git \
    libssl-dev \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Install later version of CMake than what is included in the package repos
WORKDIR /opt
ARG CMAKE_VERSION=3.23.0
RUN curl -LO https://github.com/Kitware/CMake/releases/download/v$CMAKE_VERSION/cmake-$CMAKE_VERSION-linux-x86_64.tar.gz \
 && mkdir -p cmake \
 && tar -xf cmake-$CMAKE_VERSION-linux-x86_64.tar.gz -C cmake --strip-components=1 \
 && cp /opt/cmake/bin/* /usr/local/bin \
 && cp -r /opt/cmake/share/* /usr/local/share \
 && rm -rf /opt/cmake*

# Install the botan library
WORKDIR /opt
RUN git clone https://github.com/randombit/botan.git \
 && cd botan \
 && git checkout tags/2.19.1 \
 && python3 ./configure.py \
 && make \
 && make install \
 && cd .. && rm -rf botan

# Build, test, and install the ed25519-viper library
WORKDIR /opt
COPY . /opt
# ENV CTEST_OUTPUT_ON_FAILURE=1
RUN cmake -S . -B debug/ -D CMAKE_BUILD_TYPE=Debug \
  && cmake --build debug/ --parallel 8 \
  && ctest --test-dir debug/ --output-on-failure -T Test -T Coverage
RUN cmake -S . -B release/ -D CMAKE_BUILD_TYPE=Release \
  && cmake --build release/ --parallel 8 \
  && ctest --test-dir debug/ --output-on-failure

