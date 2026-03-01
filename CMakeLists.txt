cmake_minimum_required(VERSION 3.20)

project(sshpass VERSION 1.0.7)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_executable(${PROJECT_NAME} main.c argparse.c)
add_compile_options(/W4 /utf8)
target_compile_definitions(${PROJECT_NAME} PRIVATE SSHPASS_VERSION="${PROJECT_VERSION}")
set_property(TARGET ${PROJECT_NAME} PROPERTY
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")



