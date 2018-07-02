add_executable(test_hazmat_app
    tests.c
)

add_subdirectory(Unity)
 
target_link_libraries(test_hazmat_app
    sss
    Unity
)

target_compile_options(test_hazmat_app PRIVATE 
    -m64 -pedantic -Wall -Wshadow -Wpointer-arith -Wcast-qual
    -Wformat -Wformat-security -Werror=format-security
    -Wstrict-prototypes -Wmissing-prototypes
    -fPIC -fno-strict-overflow
    -D_FORTIFY_SOURCE=2
)

target_compile_features(test_hazmat_app PRIVATE
    c_std_99
)

add_test(test_sss test_hazmat_app)

