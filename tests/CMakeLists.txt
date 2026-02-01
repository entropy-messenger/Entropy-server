# Google Test is required for unit tests
if(NOT TARGET gtest)
    include(FetchContent)
    FetchContent_Declare(
      googletest
      GIT_REPOSITORY https://github.com/google/googletest.git
      GIT_TAG        v1.14.0
      GIT_SHALLOW    TRUE
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
endif()

set(SERVER_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../include)
set(SERVER_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../src)

enable_testing()

set(SERVER_LIB_SOURCES
    ${SERVER_SRC_DIR}/http_session.cpp
    ${SERVER_SRC_DIR}/websocket_session.cpp
    ${SERVER_SRC_DIR}/connection_manager.cpp
    ${SERVER_SRC_DIR}/message_relay.cpp
    ${SERVER_SRC_DIR}/redis_manager.cpp
    ${SERVER_SRC_DIR}/rate_limiter.cpp
    ${SERVER_SRC_DIR}/handlers/identity_handler.cpp
    ${SERVER_SRC_DIR}/handlers/health_handler.cpp
    ${SERVER_SRC_DIR}/traffic_normalizer.cpp
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
