cmake_minimum_required(VERSION 3.16)

set(CMAKE_C_STANDARD 99)

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/_include
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/common
)

# Source files
set(MSV1_0_SOURCES src/msv1_0/msv1_0_bof.c)
set(KERBEROS_SOURCES src/kerberos/kerberos_bof.c)
set(CLOUDAP_SOURCES src/cloudap/cloudap_bof.c)

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Os -DBOF -w -Wno-unused-variable -Wno-unused-function")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -s")

# Object file targets
add_library(msv1_0_bof OBJECT ${MSV1_0_SOURCES})
add_library(kerberos_bof OBJECT ${KERBEROS_SOURCES})
add_library(cloudap_bof OBJECT ${CLOUDAP_SOURCES})

# Create _bin directory
file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/_bin)

# Custom commands to copy object files to _bin
add_custom_target(copy_msv1_0 ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:msv1_0_bof> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/msv1_0_bof.x64.o
    DEPENDS msv1_0_bof
    COMMENT "Copying msv1_0_bof object file"
)

add_custom_target(copy_kerberos ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:kerberos_bof> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/kerberos_bof.x64.o
    DEPENDS kerberos_bof
    COMMENT "Copying kerberos_bof object file"
)

add_custom_target(copy_cloudap ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:cloudap_bof> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/cloudap_bof.x64.o
    DEPENDS cloudap_bof
    COMMENT "Copying cloudap_bof object file"
)
