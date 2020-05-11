cmake_minimum_required (VERSION 2.8)

project(openvas_xml_parser)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)
#set(CMAKE_C_COMPILER gcc)
#set(CMAKE_CXX_COMPILER g++)

add_executable(${PROJECT_NAME} ${PROJECT_NAME}.cpp)

FIND_PACKAGE(pugixml)

target_link_libraries(${PROJECT_NAME} pugixml)

