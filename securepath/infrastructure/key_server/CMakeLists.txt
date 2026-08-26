# key server library (protocol is header-only); the daemon is key_serverd to avoid clashing with
# the library target name
securepath_add_library(key_server server_lib/*.cpp server_lib/*.hpp protocol/*.hpp)
target_link_libraries(key_server PUBLIC network crypto database util)

add_executable(key_serverd main.cpp)
securepath_apply_warnings(key_serverd)
target_link_libraries(key_serverd PRIVATE key_server securepath_common)

securepath_add_test_directory(server_lib/test)
