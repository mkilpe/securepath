# test helpers (test::pki_test_context ...) also linked by consumers' tests (spsync)
securepath_add_library(crypto_test_support *.cpp *.hpp)
target_link_libraries(crypto_test_support PUBLIC crypto)
