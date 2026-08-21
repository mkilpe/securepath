# dependency order: log <- util <- serialisation; event_system standalone;
# test_frame is a Catch2 support library used by every test suite
add_subdirectory(log)
add_subdirectory(util)
add_subdirectory(event_system)
add_subdirectory(serialisation)
if(SECUREPATH_BUILD_TESTS OR SECUREPATH_BUILD_TEST_FRAME)
    add_subdirectory(test_frame)
endif()
