securepath_add_library(packet_transport_protocol *.cpp *.hpp)
target_link_libraries(packet_transport_protocol PUBLIC network crypto serialisation util)
