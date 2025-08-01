cmake_minimum_required(VERSION 3.16)

project(SecretSharingPSI VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

# Find required packages
find_package(OpenSSL REQUIRED)
if(NOT OpenSSL_FOUND)
    message(FATAL_ERROR "OpenSSL not found")
else()
    message(STATUS "OpenSSL found: ${OPENSSL_VERSION}")
endif()

# Include directories
include_directories(include)

# Source files
set(SOURCES
    src/secret_sharing_manager.cpp
    src/secret_sharing_psi_receiver.cpp
)

# Headers
set(HEADERS
    include/secret_sharing_manager.h
    include/secret_sharing_psi_receiver.h
)

# Create library
add_library(secret_sharing_psi STATIC ${SOURCES} ${HEADERS})

# Link libraries
target_link_libraries(secret_sharing_psi
    PUBLIC OpenSSL::SSL
    PUBLIC OpenSSL::Crypto
)

# Set include directories for the library
target_include_directories(secret_sharing_psi
    PUBLIC 
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# Compiler flags
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(secret_sharing_psi PRIVATE -g -O0 -Wall -Wextra)
else()
    target_compile_options(secret_sharing_psi PRIVATE -O2 -DNDEBUG)
endif()

# Tests
option(BUILD_TESTS "Build tests" ON)
if(BUILD_TESTS)
    add_subdirectory(tests)
endif()

# Examples
option(BUILD_EXAMPLES "Build examples" ON)
if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Install targets
install(TARGETS secret_sharing_psi
    EXPORT SecretSharingPSITargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES ${HEADERS}
    DESTINATION include/secret_sharing_psi
)

install(EXPORT SecretSharingPSITargets
    FILE SecretSharingPSITargets.cmake
    NAMESPACE SecretSharingPSI::
    DESTINATION lib/cmake/SecretSharingPSI
)

# Create config file
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    SecretSharingPSIConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/SecretSharingPSIConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/SecretSharingPSIConfig.cmake
    INSTALL_DESTINATION lib/cmake/SecretSharingPSI
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/SecretSharingPSIConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/SecretSharingPSIConfigVersion.cmake
    DESTINATION lib/cmake/SecretSharingPSI
)