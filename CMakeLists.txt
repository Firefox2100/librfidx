cmake_minimum_required(VERSION 3.10)
project(librfidx C)

set(CMAKE_C_STANDARD 11)

file(GLOB_RECURSE SOURCES src/*.c)

add_library(librfidx_shared SHARED ${SOURCES})
set_target_properties(librfidx_shared PROPERTIES OUTPUT_NAME rfidx)
target_include_directories(librfidx_shared PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

add_library(librfidx_static STATIC ${SOURCES})
set_target_properties(librfidx_static PROPERTIES OUTPUT_NAME rfidx)
target_include_directories(librfidx_static PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# ------------- UNIT TESTS SETUP -------------
find_package(PkgConfig REQUIRED)
pkg_check_modules(Check REQUIRED check)

enable_testing()

file(GLOB_RECURSE TEST_SOURCE tests/*.c)

# Test target
add_executable(tests ${TEST_SOURCE})

target_include_directories(tests PRIVATE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
        ${Check_INCLUDE_DIRS}
)

target_link_libraries(tests
        librfidx_shared
        ${Check_LIBRARIES}
)

target_compile_definitions(tests PRIVATE UNIT_TESTING)

# file(COPY ${CMAKE_SOURCE_DIR}/tests/assets
#         DESTINATION ${CMAKE_BINARY_DIR}/tests)

add_test(NAME tests
        COMMAND tests
        # WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/tests
        )
