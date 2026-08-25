# transport: TLS 1.3 (Botan) over standalone asio; design in doc/network.md
securepath_add_library(network *.cpp *.hpp
	encryption/*.cpp encryption/*.hpp
	encryption/detail/*.cpp encryption/detail/*.hpp
	encryption/handshake/*.cpp encryption/handshake/*.hpp)
target_link_libraries(network PUBLIC util serialisation log crypto common asio::asio Botan::Botan)
securepath_add_test_directory(test)
