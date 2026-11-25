cmake_minimum_required(VERSION 3.20)
project(keel_compress VERSION 0.2.0 LANGUAGES CXX)

option(KEEL_COMPRESS_NO_EXCEPTIONS_RTTI "Compile keel_compress without C++ exceptions and RTTI" OFF)
option(KEEL_COMPRESS_BUILD_TESTS "Build keel_compress unit tests and header purity checks" ${PROJECT_IS_TOP_LEVEL})

if(NOT TARGET keel::keel)
    find_package(keel QUIET CONFIG)
endif()
if(NOT TARGET keel::keel)
    include(FetchContent)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../keel/CMakeLists.txt" AND NOT DEFINED FETCHCONTENT_SOURCE_DIR_KEEL)
        set(FETCHCONTENT_SOURCE_DIR_KEEL "${CMAKE_CURRENT_SOURCE_DIR}/../keel" CACHE PATH "Local keel checkout")
    endif()
    set(KEEL_NO_EXCEPTIONS_RTTI ${KEEL_COMPRESS_NO_EXCEPTIONS_RTTI} CACHE BOOL "" FORCE)
    FetchContent_Declare(
        keel
        GIT_REPOSITORY https://github.com/keelcpp/keel.git
        GIT_TAG        869a5c07a5d77341e5f6acbac5f8e024b274ea08
    )
    FetchContent_MakeAvailable(keel)
endif()

add_library(keel_compress STATIC
    src/checksum.cpp
    src/deflate.cpp
    src/gzip.cpp
    src/lz4.cpp
    src/zip.cpp
)
add_library(keel::compress ALIAS keel_compress)

target_link_libraries(keel_compress PUBLIC keel::keel)
target_compile_features(keel_compress PUBLIC cxx_std_20)
set_target_properties(keel_compress PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON
)

target_include_directories(keel_compress PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

if(MSVC)
    target_compile_options(keel_compress PRIVATE /W4 /utf-8)
    if(KEEL_COMPRESS_NO_EXCEPTIONS_RTTI)
        string(REGEX REPLACE "/EH[a-z]+" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
        string(REGEX REPLACE "/GR" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
        target_compile_options(keel_compress PUBLIC /EHs-c- /GR-)
        target_compile_definitions(keel_compress PUBLIC _HAS_EXCEPTIONS=0)
    endif()
else()
    target_compile_options(keel_compress PRIVATE -Wall -Wextra -Wpedantic)
    if(KEEL_COMPRESS_NO_EXCEPTIONS_RTTI)
        target_compile_options(keel_compress PUBLIC -fno-exceptions -fno-rtti)
    endif()
endif()

if(COMMAND keel_enforce_guidelines)
    keel_enforce_guidelines(keel_compress
        SCOPE ALL
        BAN_RAW_INTS ALL
        BAN_RAW_FLOATS ALL
        HEADERS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include"
        STANDALONE_HEADERS ${KEEL_COMPRESS_BUILD_TESTS}
        TEST_NAME test_guidelines_headers
        WARNINGS OFF
    )
endif()

include(CMakePackageConfigHelpers)
install(TARGETS keel_compress EXPORT keel_compressTargets
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)
install(DIRECTORY include/keel DESTINATION include)
install(EXPORT keel_compressTargets
    FILE keel_compressTargets.cmake
    NAMESPACE keel::
    DESTINATION lib/cmake/keel_compress
)
configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/keel_compressConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/keel_compressConfig.cmake"
    INSTALL_DESTINATION lib/cmake/keel_compress
)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/keel_compressConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMinorVersion
)
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/keel_compressConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/keel_compressConfigVersion.cmake"
    DESTINATION lib/cmake/keel_compress
)

if(KEEL_COMPRESS_BUILD_TESTS)
    enable_testing()

    add_executable(test_compress tests/test_compress.cpp)
    target_link_libraries(test_compress PRIVATE keel::compress)
    if(MSVC)
        target_compile_options(test_compress PRIVATE /W4 /utf-8)
    else()
        target_compile_options(test_compress PRIVATE -Wall -Wextra -Wpedantic)
    endif()
    if(COMMAND keel_enforce_guidelines)
        keel_enforce_guidelines(test_compress
            SCOPE ALL
            BAN_RAW_INTS ALL
            BAN_RAW_FLOATS ALL
            WARNINGS OFF
        )
    endif()
    add_test(NAME test_compress COMMAND test_compress)
endif()
