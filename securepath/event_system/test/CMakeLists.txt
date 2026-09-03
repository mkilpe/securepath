securepath_add_test(test_event_system event_system test_frame)
if(NOT SECUREPATH_HAVE_ASIO)
    # asio_* test files cover the asio observers, the rest run without asio
    get_target_property(TEST_SRC test_event_system SOURCES)
    list(FILTER TEST_SRC EXCLUDE REGEX "/asio_[^/]*$")
    set_property(TARGET test_event_system PROPERTY SOURCES "${TEST_SRC}")
endif()
