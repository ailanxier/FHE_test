cmake_minimum_required(VERSION 3.10.2 FATAL_ERROR)

## Use -std=c++17 as default.
set(CMAKE_CXX_STANDARD 17)
## Disable C++ extensions
set(CMAKE_CXX_EXTENSIONS OFF)
## Require full C++ standard
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(helib_test LANGUAGES CXX)
option( DEBUG "Set to OFF to disable printing debug messages" ON)

if(DEBUG)
    message("Working in DEBUG mode (print debug messages).")
    add_definitions(-DDEBUG)
endif()
# Define standard installation directories (GNU)
# include(GNUInstallDirs)

# # Set default output folder
# set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY
#     "${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}")
# set(CMAKE_LIBRARY_OUTPUT_DIRECTORY
#     "${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}")
# set(CMAKE_RUNTIME_OUTPUT_DIRECTORY
#     "${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_BINDIR}")

# STRINGS avoids having the 2 newline characters at the end of the string.
# Alternatively it's possible to use file(READ ...) and then
# string(REGEX REPLACE "\n$" "" HELIB_VERSION "${HELIB_VERSION}")
file(STRINGS "HElib_VERSION" HELIB_VERSION)

find_package(helib "${HELIB_VERSION}" EXACT REQUIRED)
link_libraries(helib)
include_directories(PUBLIC ${CMAKE_SOURCE_DIR}/include)
add_executable(client client.cpp) 
add_executable(server server.cpp)
