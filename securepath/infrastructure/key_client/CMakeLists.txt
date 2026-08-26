securepath_add_library(key_client *.cpp *.hpp)
target_link_libraries(key_client PUBLIC network crypto event_system util)
