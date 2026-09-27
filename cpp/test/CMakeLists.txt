# Unity-based test suites — mirrors microReticulum's test layout.

include(FetchContent)

if(RNS_UNITY_SOURCE_DIR AND IS_DIRECTORY "${RNS_UNITY_SOURCE_DIR}")
    message(STATUS "Using local Unity from ${RNS_UNITY_SOURCE_DIR}")
    FetchContent_Declare(unity SOURCE_DIR "${RNS_UNITY_SOURCE_DIR}")
else()
    FetchContent_Declare(unity
        GIT_REPOSITORY https://github.com/ThrowTheSwitch/Unity.git
        GIT_TAG        v2.6.0
    )
endif()
FetchContent_MakeAvailable(unity)

# Shared helpers header.
include_directories("${CMAKE_CURRENT_SOURCE_DIR}")

# Discover every test/test_* directory and build each as its own executable.
file(GLOB DACAR_TEST_DIRS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}"
    CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/test_*")

foreach(test_dir IN LISTS DACAR_TEST_DIRS)
    set(abs_dir "${CMAKE_CURRENT_SOURCE_DIR}/${test_dir}")
    if(NOT IS_DIRECTORY "${abs_dir}")
        continue()
    endif()

    file(GLOB suite_sources CONFIGURE_DEPENDS "${abs_dir}/*.cpp")
    if(NOT suite_sources)
        continue()
    endif()

    add_executable(${test_dir} ${suite_sources})
    target_link_libraries(${test_dir} PRIVATE Dacar unity)
    target_include_directories(${test_dir} PRIVATE "${abs_dir}")
    target_compile_definitions(${test_dir} PRIVATE PIO_UNIT_TESTING)

    add_test(NAME ${test_dir} COMMAND ${test_dir})
endforeach()

# -----------------------------------------------------------------------------
# Two-process §8 challenge interop over UDP loopback (native only).
#
# The standalone challenge_authority executable is a second Reticulum stack;
# a single stack can't deliver data packets to itself (Transport's packet-hash
# dedup filters looped-back traffic), so the full §8 Link flow needs two.
# The authority doubles as a manual testing tool against Python clients.
# -----------------------------------------------------------------------------
if(DACAR_BUILD_TESTS)
    add_executable(challenge_authority tools/challenge_authority.cpp)
    target_link_libraries(challenge_authority PRIVATE Dacar)

    add_executable(test_challenge_udp tools/challenge_udp_test.cpp)
    target_link_libraries(test_challenge_udp PRIVATE Dacar)
    target_include_directories(test_challenge_udp PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/tools")
    target_compile_definitions(test_challenge_udp PRIVATE
        AUTHORITY_EXECUTABLE="$<TARGET_FILE:challenge_authority>"
    )
    add_test(NAME test_challenge_udp COMMAND test_challenge_udp)

    # Manual rfed compact-format cross-implementation tool (see its header):
    # C++ wraps, the Python dacar.transport.rfed_compact unwraps. Not a test.
    add_executable(rfed_wrap_tool EXCLUDE_FROM_ALL tools/rfed_wrap_tool.cpp)
    target_link_libraries(rfed_wrap_tool PRIVATE Dacar)
endif()
