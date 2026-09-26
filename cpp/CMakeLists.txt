cmake_minimum_required(VERSION 3.15)
project(Dacar LANGUAGES C CXX VERSION 0.1.0)

# -----------------------------------------------------------------------------
# Defaults
# -----------------------------------------------------------------------------
if(NOT CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD 17)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# -----------------------------------------------------------------------------
# Options
# -----------------------------------------------------------------------------
option(DACAR_BUILD_TESTS "Build Unity test suites under test/" ON)

# Pinned microReticulum revision this port was developed against (work doc #16
# risk mitigation: pin against upstream 0.5.x API churn).
set(DACAR_MICRORETICULUM_GIT_TAG
    "40fa628809d57140180c1c833559ab96fec992c1"
    CACHE STRING "microReticulum git revision to build against")

# Local-checkout override for microReticulum (mirrors microReticulum's own
# rns_fetch() *_SOURCE_DIR overrides). Skips the network fetch when set, e.g.:
#   cmake -B build -DDACAR_MICRORETICULUM_SOURCE_DIR=../reticulum.js/microReticulum
set(DACAR_MICRORETICULUM_SOURCE_DIR "" CACHE PATH "Use a local microReticulum checkout instead of FetchContent")

#-----------------------------------------------------------------------------
# Toolchain compatibility
#-----------------------------------------------------------------------------
# GCC 15 / libstdc++ 15 dropped transitive <cstdint> includes that the pinned
# microReticulum revision (and possibly other fetched deps) relied on.
# Force-include <cstdint> for every C++ source compiled in this tree.
add_compile_options("$<$<COMPILE_LANGUAGE:CXX>:-include;cstdint>")

# Dacar state / outbox records exceed microStore's default 1 KB value cap.
# Raise it tree-wide so every TU (Dacar + microReticulum's header-only
# BasicFileStore instantiations) agrees on the limit — a build mixing values
# would ODR-diverge, and records larger than a build's limit drop as corrupt.
add_compile_definitions(USTORE_MAX_VALUE_LEN=16384)

# The §13 loose-file backend (native targets). Embedded builds use the
# microStore backend (MicroStoreIo.h) instead.
add_compile_definitions(DACAR_POSIX_STORE)

# -----------------------------------------------------------------------------
# Dependencies
# -----------------------------------------------------------------------------
include(FetchContent)

if(DACAR_MICRORETICULUM_SOURCE_DIR AND IS_DIRECTORY "${DACAR_MICRORETICULUM_SOURCE_DIR}")
    message(STATUS "Using local microReticulum from ${DACAR_MICRORETICULUM_SOURCE_DIR}")
    FetchContent_Declare(microreticulum SOURCE_DIR "${DACAR_MICRORETICULUM_SOURCE_DIR}")
else()
    message(STATUS "Fetching microReticulum ${DACAR_MICRORETICULUM_GIT_TAG}")
    FetchContent_Declare(microreticulum
        GIT_REPOSITORY https://github.com/attermann/microReticulum.git
        GIT_TAG        ${DACAR_MICRORETICULUM_GIT_TAG}
    )
endif()

# Consume microReticulum via its own CMakeLists: it fetches the shared
# dependency set (MsgPack, Crypto, ArduinoJson, microStore, ...) and exposes
# them transitively on its PUBLIC interface. Its own tests/examples/interop
# suites are disabled; ours live under test/.
set(RNS_BUILD_TESTS   OFF CACHE BOOL "" FORCE)
set(RNS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(RNS_BUILD_INTEROP OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(microreticulum)

# -----------------------------------------------------------------------------
# Dacar library
# -----------------------------------------------------------------------------
file(GLOB_RECURSE DACAR_SOURCES CONFIGURE_DEPENDS src/*.cpp src/*.c)

add_library(Dacar ${DACAR_SOURCES})
set_target_properties(Dacar PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_include_directories(Dacar PUBLIC
    "${PROJECT_SOURCE_DIR}/src"
)

target_compile_options(Dacar PRIVATE
    -Wall
    -Wno-missing-field-initializers
    -Wno-unused-parameter
)

# microReticulum already propagates NATIVE, the MsgPack/Crypto/microStore
# includes and the allocator configuration on its PUBLIC interface.
target_link_libraries(Dacar PUBLIC microReticulum)

# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------
if(DACAR_BUILD_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()
