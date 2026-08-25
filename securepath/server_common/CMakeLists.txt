# server side helpers; ro_server_base returns together with remote_object
securepath_add_library(server_common *.cpp *.hpp)
target_link_libraries(server_common PUBLIC network crypto log util)
