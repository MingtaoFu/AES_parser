cmake_minimum_required(VERSION 3.7)
project(AES)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES main.c core.c interface.c main.h)
add_executable(AES ${SOURCE_FILES})