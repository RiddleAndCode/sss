add_executable(test_hazmat_app
    tests.c
)

add_subdirectory(Unity)
 
target_link_libraries(test_hazmat_app
    sss
    Unity
    gcov
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

add_custom_target(gcovr
    COMMAND ${CMAKE_BINARY_DIR}/tests/test_hazmat_app
    COMMAND gcovr -k  --branches  -r  ${CMAKE_SOURCE_DIR}
              --object-directory=${CMAKE_BINARY_DIR}/tests/CMakeFiles/test_hazmat_app.dir/
              --xml-pretty -o ${CMAKE_BINARY_DIR}/coverage.xml
    COMMAND gcovr -k  --branches  -r  ${CMAKE_SOURCE_DIR}
              --object-directory=${CMAKE_BINARY_DIR}/tests/CMakeFiles/test_hazmat_app.dir/
              --html --html-details -o ${CMAKE_BINARY_DIR}/coverage.html
    COMMENT "Creating Coverage HTML and XML summary")

add_custom_command(TARGET test_hazmat_app POST_BUILD
    COMMAND ${CMAKE_BINARY_DIR}/tests/test_hazmat_app
    COMMAND gcovr -k  --branches  -r  ${CMAKE_SOURCE_DIR}
              --object-directory=${CMAKE_BINARY_DIR}/tests/CMakeFiles/test_hazmat_app.dir/
              --xml-pretty -o ${CMAKE_BINARY_DIR}/coverage.xml
    COMMAND gcovr -k  --branches  -r  ${CMAKE_SOURCE_DIR}
              --object-directory=${CMAKE_BINARY_DIR}/tests/CMakeFiles/test_hazmat_app.dir/
              --html --html-details -o ${CMAKE_BINARY_DIR}/coverage.html
    COMMENT "Creating Coverage HTML and XML summary")

add_test(test_sss test_hazmat_app)

