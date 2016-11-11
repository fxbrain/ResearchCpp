cmake_minimum_required(VERSION 3.6)
project(Research)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14")

set(SOURCE_FILES main.cpp)

include_directories(
        /usr/local/opt/openssl/include
)

link_directories(
        /usr/local/opt/openssl/lib
)

add_executable(Research ${SOURCE_FILES})

target_link_libraries( Research
        libcrypto.a
)