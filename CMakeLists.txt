cmake_minimum_required(VERSION 3.30)
project(webctl)

set(CMAKE_CXX_STANDARD 23)

include(cmake/CPM.cmake)

CPMAddPackage("gh:boostorg/boost#boost-1.89.0")
CPMAddPackage(
        URI "gh:aws/aws-sdk-cpp#1.11.640"
        OPTIONS "BUILD_ONLY cognito-idp"
)

add_executable(webctl src/main.cpp)
target_link_libraries(webctl PUBLIC Boost::beast Boost::asio)