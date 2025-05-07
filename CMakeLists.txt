cmake_minimum_required(VERSION 3.10)
project(librfidx C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/external/sanitizers-cmake/cmake" ${CMAKE_MODULE_PATH})

set(ENABLE_CJSON_TEST OFF CACHE BOOL "" FORCE)
add_subdirectory(external/cjson)
file(GLOB_RECURSE SOURCES src/*.c)

set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)

set(MBEDTLS_USER_CONFIG_FILE "${CMAKE_CURRENT_SOURCE_DIR}/config/mbedtls_config.h")
add_compile_definitions(MBEDTLS_CONFIG_FILE="${MBEDTLS_USER_CONFIG_FILE}")
add_subdirectory(external/mbedtls)

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
        src/rfidx.c
)
set_target_properties(rfidx PROPERTIES OUTPUT_NAME rfidx)
target_link_libraries(rfidx
        librfidx_shared
)

# ------------- UNIT TESTS SETUP -------------
option(BUILD_TESTS "Build unit tests" ON)

if(BUILD_TESTS)
        find_package(PkgConfig QUIET)
        if(PkgConfig_FOUND)
                message(STATUS "PkgConfig found: ${PkgConfig_FOUND}")
                pkg_check_modules(Check QUIET check)
        endif()

        if(PkgConfig_FOUND AND Check_FOUND)
                message(STATUS "Check found: ${Check_FOUND}")
                enable_testing()

                file(GLOB_RECURSE TEST_SOURCE tests/*.c)

                add_executable(unit_test ${TEST_SOURCE})

                find_package(Sanitizers QUIET)
                if (Sanitizers_FOUND)
                        message(STATUS "Sanitizers found: ${Sanitizers_FOUND}")
                        add_sanitizers(unit_test)
                        add_sanitizers(librfidx_shared)
                endif ()

                target_include_directories(unit_test PRIVATE
                        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                        $<INSTALL_INTERFACE:include>
                        ${Check_INCLUDE_DIRS}
                )
                target_link_libraries(unit_test
                        librfidx_shared
                        ${Check_LIBRARIES}
                )
                target_compile_definitions(unit_test PRIVATE UNIT_TESTING)

                target_compile_options(unit_test PRIVATE -g -O0)

                file(COPY ${CMAKE_SOURCE_DIR}/tests/assets
                        DESTINATION ${CMAKE_BINARY_DIR}/tests
                )

                add_test(NAME unit_test
                        COMMAND unit_test
                )
        else()
                message(WARNING "Unit tests will not be built: 'check' or 'pkg-config' not found.")
        endif()
endif()
