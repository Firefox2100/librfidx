cmake_minimum_required(VERSION 3.10)
project(librfidx C)

set(CMAKE_C_STANDARD 11)

set(ENABLE_CJSON_TEST OFF CACHE BOOL "" FORCE)
add_subdirectory(external/cjson)
file(GLOB_RECURSE SOURCES src/*.c)

add_library(librfidx_shared SHARED ${SOURCES})
set_target_properties(librfidx_shared PROPERTIES OUTPUT_NAME rfidx)
target_include_directories(librfidx_shared PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/external/cjson>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(librfidx_shared PRIVATE cJSON)

add_library(librfidx_static STATIC ${SOURCES})
set_target_properties(librfidx_static PROPERTIES OUTPUT_NAME rfidx)
target_include_directories(librfidx_static PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/external/cjson>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(librfidx_static PRIVATE cJSON)

# ------------- UNIT TESTS SETUP -------------
option(BUILD_TESTS "Build unit tests" ON)

if(BUILD_TESTS)
        find_package(PkgConfig QUIET)
        if(PkgConfig_FOUND)
                pkg_check_modules(Check QUIET check)
        endif()

        if(PkgConfig_FOUND AND Check_FOUND)
                enable_testing()

                file(GLOB_RECURSE TEST_SOURCE tests/*.c)

                add_executable(unit_test ${TEST_SOURCE})
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

                file(COPY ${CMAKE_SOURCE_DIR}/tests/assets
                        DESTINATION ${CMAKE_BINARY_DIR}/tests)

                add_test(NAME unit_test
                        COMMAND unit_test
                        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/tests
                )
        else()
                message(WARNING "Unit tests will not be built: 'check' or 'pkg-config' not found.")
        endif()
endif()
