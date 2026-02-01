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

target_include_directories(unit_tests PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/handlers
)

target_link_libraries(unit_tests PRIVATE
    server_core
    GTest::gtest
    GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(unit_tests)
