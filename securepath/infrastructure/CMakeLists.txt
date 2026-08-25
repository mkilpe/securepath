add_subdirectory(packet_transport)

# consumers (spsync) include <infrastructure/packet_transport/...>; make that resolve next to
# the canonical <securepath/infrastructure/...> form
foreach(lib IN ITEMS packet_transport_protocol packet_transport_client packet_server_lib)
	target_include_directories(${lib} PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/securepath>)
endforeach()
