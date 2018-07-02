
file(GLOB SOURCES "*.c")
add_library(sss STATIC
    ${SOURCES}
)
 
target_include_directories(sss PUBLIC
    ../include
)