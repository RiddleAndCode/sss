add_executable(test_hazmat_app
    tests.c
)


add_subdirectory(Unity)
 
target_link_libraries(test_hazmat_app
    sss
    Unity
)
 
add_test(test_sss test_hazmat_app)
