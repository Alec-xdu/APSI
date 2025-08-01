# Test executable
add_executable(secret_sharing_test test_secret_sharing.cpp)

# Link with the library
target_link_libraries(secret_sharing_test secret_sharing_psi)

# Add test
enable_testing()
add_test(NAME SecretSharingTest COMMAND secret_sharing_test)