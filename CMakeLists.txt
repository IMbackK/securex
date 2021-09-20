cmake_minimum_required(VERSION 2.4)

project(securex)

set(SRC_FILES main.c)

add_executable(${PROJECT_NAME} ${SRC_FILES})

add_definitions("-Wall -Os")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -s")

set(CMAKE_INSTALL_PREFIX "/usr")
install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)
