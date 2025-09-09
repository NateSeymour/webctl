cmake_minimum_required(VERSION 3.28)
project(webctl)

set(CMAKE_CXX_STANDARD 23)

include(cmake/CPM.cmake)

find_package(OpenSSL COMPONENTS SSL Crypto REQUIRED)
CPMAddPackage("gh:boostorg/boost#boost-1.89.0")
CPMAddPackage("gh:Kistler-Group/sdbus-cpp@2.1.0")
CPMAddPackage("gh:tplgy/cppcodec#master")

add_executable(
    webctl 
    src/main.cpp
    src/JwksProvider.cpp
)
target_link_libraries(
    webctl 
    PUBLIC Boost::beast Boost::url Boost::asio Boost::json Boost::algorithm Boost::iterator OpenSSL::SSL sdbus-c++ cppcodec
)