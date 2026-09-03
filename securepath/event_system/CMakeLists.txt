securepath_add_library(event_system *.cpp *.hpp impl/*.cpp impl/*.hpp)
target_link_libraries(event_system PUBLIC util)
if(SECUREPATH_HAVE_ASIO)
    target_link_libraries(event_system PUBLIC asio::asio)
else()
    # the asio_* observers are the only asio-dependent part; the rest of the
    # library works without it
    get_target_property(EVENT_SRC event_system SOURCES)
    list(FILTER EVENT_SRC EXCLUDE REGEX "/asio_[^/]*$")
    set_property(TARGET event_system PROPERTY SOURCES "${EVENT_SRC}")
    message(STATUS "event_system: asio not found, asio observers excluded")
endif()
securepath_add_test_directory(test)
