cmake_minimum_required(VERSION 3.14)
project(entropy_tests)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        v1.14.0
  GIT_SHALLOW    TRUE
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Identify the server include directory
set(SERVER_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../include)
set(SERVER_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../src)

# Libraries needed (same as server)
find_package(Boost REQUIRED COMPONENTS system thread json)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Hiredis and redis++ configuration
set(DISABLE_TESTS ON CACHE BOOL "" FORCE)
set(ENABLE_EXAMPLES OFF CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    hiredis
    GIT_REPOSITORY https://github.com/redis/hiredis.git
    GIT_TAG        v1.2.0
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(hiredis)

file(MAKE_DIRECTORY "${hiredis_SOURCE_DIR}/hiredis")
file(GLOB HIREDIS_HEADERS "${hiredis_SOURCE_DIR}/*.h")
file(COPY ${HIREDIS_HEADERS} DESTINATION "${hiredis_SOURCE_DIR}/hiredis")

set(HIREDIS_HEADER "${hiredis_SOURCE_DIR}")
set(HIREDIS_JSY_HEADER "${hiredis_SOURCE_DIR}")
set(HIREDIS_LIB hiredis CACHE STRING "Hiredis target" FORCE)
set(HIREDIS_STATIC_LIB hiredis CACHE STRING "Hiredis target" FORCE)

set(REDIS_PLUS_PLUS_BUILD_TEST OFF CACHE BOOL "" FORCE)
set(REDIS_PLUS_PLUS_BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    redis-plus-plus
    GIT_REPOSITORY https://github.com/sewenew/redis-plus-plus.git
    GIT_TAG        master
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(redis-plus-plus)

enable_testing()

# We need to link against the same objects as the server, but without main.cpp
# Since we can't easily change the server target to a library without modifying source code,
# we will just compile the necessary source files directly into the test executable or a test lib.

set(SERVER_LIB_SOURCES
    ${SERVER_SRC_DIR}/http_session.cpp
    ${SERVER_SRC_DIR}/websocket_session.cpp
    ${SERVER_SRC_DIR}/connection_manager.cpp
    ${SERVER_SRC_DIR}/message_relay.cpp
    ${SERVER_SRC_DIR}/redis_manager.cpp
    ${SERVER_SRC_DIR}/rate_limiter.cpp
)

add_library(server_logic STATIC ${SERVER_LIB_SOURCES})
target_include_directories(server_logic PUBLIC ${SERVER_INCLUDE_DIR})
target_link_libraries(server_logic PUBLIC
    Boost::system
    Boost::thread
    Boost::json
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
    hiredis
    redis++
)

# Define individual test executables or one big one
add_executable(unit_tests
    test_main.cpp
    test_input_validator.cpp
    test_pow_verifier.cpp
    test_metrics.cpp
    test_challenge.cpp
    test_message_relay.cpp
    test_server_config.cpp
    test_security_logger.cpp
    test_connection_manager.cpp
    test_rate_limiter.cpp
    test_stress.cpp
    test_fuzz.cpp
    test_redis_manager.cpp
    test_hardening.cpp
)

target_link_libraries(unit_tests PRIVATE
    server_logic
    GTest::gtest
    GTest::gtest_main
)

add_test(NAME AllUnitTests COMMAND unit_tests)
