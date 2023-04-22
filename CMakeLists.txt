cmake_minimum_required (VERSION 3.5.1)

project(OpenFHE_test LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
option( BUILD_STATIC "Set to ON to include static versions of the library" OFF)
option( DEBUG "Set to OFF to disable printing debug messages" ON)
message("Building static libraries: ${BUILD_STATIC}")

if(DEBUG)
    message("=============== Working in DEBUG mode (print debug messages) =============== ")
    add_definitions(-DDEBUG)
else()
    message("=============== Working in RELEASE mode (no debug messages) ===============")
endif()

find_package(OpenFHE)
set( CMAKE_CXX_FLAGS ${OpenFHE_CXX_FLAGS} )

include_directories( ${OPENMP_INCLUDES} )
include_directories( ${OpenFHE_INCLUDE} ${OpenFHE_INCLUDE}/third-party/include ${OpenFHE_INCLUDE}/core ${OpenFHE_INCLUDE}/pke )
include_directories( ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/proto )

### add directories for other OpenFHE modules as needed for your project
link_directories( ${OpenFHE_LIBDIR} )
link_directories( ${OPENMP_LIBRARIES} )

# Protobuf input
find_package(Protobuf REQUIRED)
include_directories(${PROTOBUF_INCLUDE_DIRS})
set(PROTO_SRC_DIR ${CMAKE_SOURCE_DIR}/proto)
include_directories(PROTO_SRC_DIR)
message("PROTOBUF_INCLUDE_DIRS: ${PROTOBUF_INCLUDE_DIRS}")

if(BUILD_STATIC)
    set( CMAKE_EXE_LINKER_FLAGS "${OpenFHE_EXE_LINKER_FLAGS}")
    link_libraries(asan ${OpenFHE_STATIC_LIBRARIES} /usr/local/lib/afl/afl-compiler-rt-64.o)
    message("OpenFHE_STATIC_LIBRARIES: ${OpenFHE_STATIC_LIBRARIES}")
else()
    set( CMAKE_EXE_LINKER_FLAGS ${OpenFHE_EXE_LINKER_FLAGS} )
    link_libraries( ${OpenFHE_SHARED_LIBRARIES} )
    message("OpenFHE_SHARED_LIBRARIES: ${OpenFHE_SHARED_LIBRARIES}")
endif()

# ======================= OPENFHE-CKKS =======================
set(PROTO_SRC ${PROTO_SRC_DIR}/openfhe_ckks.pb.cc)
add_executable(openfhe_ckks_test openfhe_test.cpp ${PROTO_SRC})
target_link_libraries(openfhe_ckks_test ${PROTOBUF_LIBRARIES})