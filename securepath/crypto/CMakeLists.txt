# post-quantum crypto on Botan 3; design in doc/crypto.md
securepath_add_library(crypto *.cpp *.hpp detail/*.cpp detail/*.hpp)
target_link_libraries(crypto PUBLIC util serialisation database log Botan::Botan)
securepath_add_test_directory(test)
