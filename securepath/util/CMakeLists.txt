securepath_add_library(util *.cpp *.hpp)
target_link_libraries(util PUBLIC log)
securepath_add_test_directory(test)
