file(GLOB TEST_LIB_SOURCES "*.c")

add_executable(test_hazmat_app
    ${TEST_LIB_SOURCES}
)

target_include_directories(test_hazmat_app PUBLIC .
)

add_subdirectory(Unity)
 
target_link_libraries(test_hazmat_app
    sss
    Unity
    gcov
    asan
)

target_compile_features(test_hazmat_app PRIVATE
    c_std_99
)

target_compile_options(test_hazmat_app PRIVATE 
    -m64 -pedantic -Wall -Wshadow -Wpointer-arith -Wcast-qual
    -Wformat -Wformat-security -Werror=format-security
    -Wstrict-prototypes -Wmissing-prototypes
    -fPIC -fno-strict-overflow
    -D_FORTIFY_SOURCE=2
)

add_custom_target(check
    COMMENT "Creating Coverage HTML and XML summary"
    COMMAND ${CMAKE_BINARY_DIR}/tests/test_hazmat_app
    COMMAND gcovr -k  --branches  -r  ${CMAKE_SOURCE_DIR}
              --object-directory=${CMAKE_BINARY_DIR}/tests/CMakeFiles/test_hazmat_app.dir/
              --xml-pretty -o ${CMAKE_BINARY_DIR}/coverage.xml
    COMMAND gcovr -k  --branches  -r  ${CMAKE_SOURCE_DIR}
              --object-directory=${CMAKE_BINARY_DIR}/tests/CMakeFiles/test_hazmat_app.dir/
              --html --html-details -o ${CMAKE_BINARY_DIR}/coverage.html
    COMMENT "Creating Gprof results from testing."              
    COMMAND cd ${CMAKE_BINARY_DIR}/tests && gprof test_hazmat_app gmon.out > analysis_test_hazmat_app)

add_test(test_sss test_hazmat_app)
