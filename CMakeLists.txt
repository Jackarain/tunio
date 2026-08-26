cmake_minimum_required(VERSION 3.20)
project(tunio VERSION 3.0.0 LANGUAGES CXX)

# CMake 3.30+ 移除 FindBoost 模块（CMP0167）：系统提供 BoostConfig 时
# find_package 自动回退到 config 模式，此处显式声明旧策略以抑制告警。
if(POLICY CMP0167)
  cmake_policy(SET CMP0167 OLD)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Debug)
endif()

find_package(Boost 1.74 REQUIRED)

set(TUNIO_SOURCES
  src/packet_buffer.cpp
  src/tcp_engine.cpp
  src/udp_engine.cpp
  src/tun_acceptor.cpp
  src/tunio.cpp
  src/tun_stream.cpp
  src/tun_udp_acceptor.cpp
  src/tun_udp_socket.cpp
)

# 平台相关实现按平台拆分（参考 Asio 的 impl 布局）：
#   Windows -> packet_device_windows.cpp
#   其他 POSIX -> packet_device_posix.cpp
if(WIN32)
  list(APPEND TUNIO_SOURCES src/packet_device_windows.cpp)
else()
  list(APPEND TUNIO_SOURCES src/packet_device_posix.cpp)
endif()

add_library(tunio STATIC ${TUNIO_SOURCES})
target_include_directories(tunio PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/src
)
if(TARGET Boost::headers)
  target_link_libraries(tunio PUBLIC Boost::headers)
else()
  target_link_libraries(tunio PUBLIC Boost::boost)
endif()
target_compile_options(tunio PRIVATE -Wall -Wextra)

option(TUNIO_BUILD_TESTS "构建单元测试" ON)
option(TUNIO_BUILD_EXAMPLES "构建示例程序" ON)

if(TUNIO_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

if(TUNIO_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()
