cmake_minimum_required(VERSION 3.28)
project(webctl)

set(CMAKE_CXX_STANDARD 23)

include(cmake/CPM.cmake)

find_package(OpenSSL COMPONENTS SSL Crypto REQUIRED)
# Boost is a bit of a PITA with CPM, so just expect it to be installed by other means.
find_package(Boost 1.89.0 COMPONENTS beast url asio json algorithm iterator REQUIRED)
CPMAddPackage("gh:Kistler-Group/sdbus-cpp@2.1.0")
CPMAddPackage("gh:tplgy/cppcodec#master")

add_executable(
        webctl
        src/main.cpp
        src/HTTPServer.cpp
        src/OIDCProvider.cpp
        src/HTTPClient.cpp
)
target_link_libraries(
        webctl
        PUBLIC Boost::beast Boost::url Boost::asio Boost::json Boost::algorithm Boost::iterator OpenSSL::SSL sdbus-c++ cppcodec
)