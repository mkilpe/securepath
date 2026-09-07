# key material of a deployment: the root + CA pki directory and certified server/client
# identities (library keygen); sp_keygen is the command line tool on top of it
securepath_add_library(keygen pki.cpp pki.hpp)
target_link_libraries(keygen PUBLIC crypto database serialisation util log)

add_executable(sp_keygen main.cpp)
securepath_apply_warnings(sp_keygen)
target_link_libraries(sp_keygen PRIVATE keygen common securepath_common)

securepath_add_test_directory(test)
