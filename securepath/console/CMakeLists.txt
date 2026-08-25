securepath_add_library(console *.cpp *.hpp)
target_link_libraries(console PUBLIC event_system log util Curses::Curses)
securepath_add_test_directory(test)
