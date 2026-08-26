add_subdirectory(packet_transport)
add_subdirectory(key_server)
add_subdirectory(key_client)

# consumers (spsync) include <infrastructure/...> as well as the canonical
# <securepath/infrastructure/...> form; make the short form resolve for every infrastructure target
foreach(lib IN ITEMS packet_transport_protocol packet_transport_client packet_server_lib key_server key_client)
	target_include_directories(${lib} PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/securepath>)
endforeach()
