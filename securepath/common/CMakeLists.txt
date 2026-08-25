securepath_add_library(common *.cpp *.hpp)
target_link_libraries(common PUBLIC database serialisation util)
securepath_add_test_directory(test)
