cmake_minimum_required(VERSION 3.19)
project(DynamicAnalyzer LANGUAGES CXX C)

# ==== 全局设置 ====
# 要求 C++17 标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 如果没有指定构建类型，默认 Release
if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# ==== LLVM & Clang 查找 ====
find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in ${LLVM_DIR}")

list(APPEND CMAKE_MODULE_PATH ${LLVM_CMAKE_DIR})

find_package(Clang REQUIRED CONFIG)
message(STATUS "Found Clang ${Clang_VERSION}")
message(STATUS "Using ClangConfig.cmake in ${Clang_DIR}")

list(APPEND CMAKE_MODULE_PATH ${CLANG_CMAKE_DIR})
include(${CLANG_CMAKE_DIR}/AddClang.cmake)

# 强制要求 LLVM/Clang 版本 ≥ 18
if (LLVM_VERSION_MAJOR LESS 18)
  message(FATAL_ERROR "Found LLVM ${LLVM_VERSION_MAJOR}, need >= 18")
endif()
if (Clang_VERSION_MAJOR LESS 18)
  message(FATAL_ERROR "Found Clang ${Clang_VERSION_MAJOR}, need >= 18")
endif()

# 处理 LLVM 是否需要 RTTI
if (NOT LLVM_REQUIRES_RTTI)
  add_compile_options(-fno-rtti)
endif()

# 将 LLVM 定义宏转为 CMake 定义
separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})

# ==== 子目录输出 ====
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ==== 添加 src 子项目 ====
add_subdirectory(src)

# ==== 单元测试（可选） ====
if (BUILD_TESTING)
  include(CTest)
  enable_testing()
  find_package(Catch2 REQUIRED)
  include(Catch)
  add_subdirectory(test)
endif()
