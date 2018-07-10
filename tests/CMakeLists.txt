file(GLOB TEST_LIB_SOURCES "*.c")

add_subdirectory(Unity)

add_custom_target(check
    COMMENT "Creating Coverage HTML and XML summary"
    COMMAND ctest -T Test --no-compress-output || true 
    COMMAND gcovr -k  --branches  -r  ${CMAKE_SOURCE_DIR}
              --xml-pretty -o ${CMAKE_BINARY_DIR}/coverage.xml
    COMMAND gcovr -k  --branches  -r  ${CMAKE_SOURCE_DIR}
              --html --html-details -o ${CMAKE_BINARY_DIR}/coverage.html
    )

macro(do_test test_name sources)
    add_executable(${test_name}
        ${sources}
    )

    target_include_directories(${test_name} PUBLIC .
    )

    target_link_libraries(${test_name}
        sss
        Unity
        gcov
        asan
    )

    target_compile_options(${test_name} PRIVATE 
    -m64 -pedantic -Wall -Wshadow -Wpointer-arith -Wcast-qual
    -Wformat -Wformat-security -Werror=format-security
    -Wstrict-prototypes -Wmissing-prototypes
    -fPIC -fno-strict-overflow
    -D_FORTIFY_SOURCE=2
    )

    add_test(${test_name} ${test_name})
endmacro()

foreach(arg1  ${TEST_LIB_SOURCES} )
    get_filename_component(name ${arg1} NAME_WE)
    get_filename_component(file ${arg1} NAME)
    do_test(${name} ${file})
endforeach(arg1)