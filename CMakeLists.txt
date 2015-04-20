# This file is part of pdhcp
# Copyright (c) 2015 Pierre-Yves Kerembellec <py.kerembellec@gmail.com>

CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
INCLUDE(ExternalProject)
INCLUDE_DIRECTORIES(BEFORE ${CMAKE_BINARY_DIR}/include ${CMAKE_SOURCE_DIR}/src)
ADD_DEFINITIONS(-std=c++0x -fno-strict-aliasing -Wall -Werror -pedantic -Wno-write-strings)
LINK_DIRECTORIES(${CMAKE_BINARY_DIR}/lib)
SET(BUILD_SHARED_LIBRARIES OFF)
SET(CMAKE_EXE_LINKER_FLAGS "-static")

PROJECT(pdhcp)
FILE(GLOB source_files src/*.cpp)
ADD_EXECUTABLE(pdhcp ${source_files})
TARGET_LINK_LIBRARIES(pdhcp ev m)
ADD_DEPENDENCIES(pdhcp ev)

EXTERNALPROJECT_ADD(
  ev
  URL ${CMAKE_SOURCE_DIR}/vendor/libev-4.19.tar.gz
  CONFIGURE_COMMAND ./configure --prefix=${CMAKE_BINARY_DIR} --disable-shared
  BUILD_IN_SOURCE 1
)
