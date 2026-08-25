securepath_add_library(packet_server_lib *.cpp *.hpp)
target_link_libraries(packet_server_lib PUBLIC packet_transport_protocol server_common network crypto database)
