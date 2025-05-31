cmake_minimum_required(VERSION 3.10)
project(librfidx C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN 1)
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/external/sanitizers-cmake/cmake" ${CMAKE_MODULE_PATH})

set(ENABLE_CJSON_TEST OFF CACHE BOOL "" FORCE)
add_subdirectory(external/cjson)

set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)

set(MBEDTLS_USER_CONFIG_FILE "${CMAKE_CURRENT_SOURCE_DIR}/config/mbedtls_config.h")
add_compile_definitions(MBEDTLS_CONFIG_FILE="${MBEDTLS_USER_CONFIG_FILE}")
add_subdirectory(external/mbedtls)

option(NO_PLATFORM "Disable platform-dependent code" OFF)

file(GLOB_RECURSE CORE_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/core/*.c)
if(NO_PLATFORM)
        set(PLATFORM_SOURCES "")  # No platform-specific sources
else()
        file(GLOB_RECURSE PLATFORM_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/platform/*.c)
endif()
set(SOURCES ${CORE_SOURCES} ${PLATFORM_SOURCES})

add_library(librfidx_shared SHARED ${SOURCES})
set_target_properties(librfidx_shared PROPERTIES OUTPUT_NAME rfidx)
target_include_directories(librfidx_shared PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/external/cjson>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/external/mbedtls/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(librfidx_shared PRIVATE
        cjson
        mbedcrypto
        mbedtls
)

add_library(librfidx_static STATIC ${SOURCES})
set_target_properties(librfidx_static PROPERTIES OUTPUT_NAME rfidx)
target_include_directories(librfidx_static PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/external/cjson>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/external/mbedtls/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(librfidx_static PRIVATE
        cjson
        mbedcrypto
        mbedtls
)

add_executable(rfidx
        src/platform/rfidx.c
)
set_target_properties(rfidx PROPERTIES OUTPUT_NAME rfidx)
target_link_libraries(rfidx
        librfidx_shared
)

# ------------- UNIT TESTS SETUP -------------
option(BUILD_TESTS "Build unit tests" ON)
option(ENABLE_SANITIZERS "Enable sanitizers if available (disabled in Release mode)" OFF)

if(BUILD_TESTS)
    find_package(cmocka QUIET)

    if(cmocka_FOUND)
        message(STATUS "cmocka found.")
        enable_testing()

        file(GLOB_RECURSE TEST_SOURCE tests/*.c)

        add_executable(unit_test 
                ${TEST_SOURCE}
        )

        if(ENABLE_SANITIZERS AND NOT CMAKE_BUILD_TYPE STREQUAL "Release")
            message(STATUS "Sanitizers are enabled. Do not run with Valgrind!")
            find_package(Sanitizers QUIET)
            if(Sanitizers_FOUND)
                message(STATUS "Sanitizers enabled and found.")
                add_sanitizers(unit_test)
                add_sanitizers(librfidx_shared)
            endif()
        else()
            if(ENABLE_SANITIZERS)
                message(STATUS "Sanitizers are enabled but skipped due to Release build.")
            endif()
        endif()

        target_include_directories(unit_test PRIVATE
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:include>
            ${cmocka_INCLUDE_DIRS}
        )

        target_link_libraries(unit_test
            librfidx_shared
            cmocka
        )

        target_compile_definitions(unit_test PRIVATE UNIT_TESTING)
        target_compile_options(unit_test PRIVATE -g -O0)

        file(COPY ${CMAKE_SOURCE_DIR}/tests/assets
            DESTINATION ${CMAKE_BINARY_DIR}/tests
        )

        include(CTestRegistration.cmake)

        find_program(GCOVR_EXECUTABLE gcovr)

        if (GCOVR_EXECUTABLE)
            message(STATUS "gcovr found, registering coverage target.")
            add_custom_target(coverage-html
                COMMAND gcovr -r ${CMAKE_SOURCE_DIR} --object-directory ${CMAKE_BINARY_DIR} -f "${CMAKE_SOURCE_DIR}/src" --html --html-details -o coverage.html
                WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
                COMMENT "Generating code coverage report"
            )
            add_custom_target(coverage-lcov
                COMMAND gcovr -r ${CMAKE_SOURCE_DIR} --object-directory ${CMAKE_BINARY_DIR} -f "${CMAKE_SOURCE_DIR}/src" --lcov -o coverage.info
                WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
                COMMENT "Generating LCOV coverage report"
            )
        else()
            message(WARNING "gcovr not found, coverage targets will not be available.")
        endif()
    else()
        message(WARNING "cmocka not found, unit tests will not be built.")
    endif()
endif()
