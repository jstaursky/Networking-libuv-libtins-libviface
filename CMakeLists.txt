cmake_minimum_required(VERSION 3.1)
project (Networking)

set(CMAKE_BUILD_TYPE Debug)

find_library (TINS_LIB NAMES tins)
find_library (VIFACE_LIB NAMES viface)
find_library (UV_LIB NAMES uv)
find_library (PCAP_LIB NAMES pcap)

find_path (TINS_INCLUDE tins/tins.h)
find_path (VIFACE_INCLUDE viface/viface.hpp)
find_path (UV_INCLUDE uv.h)
find_path (PCAP_INCLUDE pcap.h)

set (HEADERS async-networking.hpp)
set (SOURCES main.cpp async-networking.cpp)

include_directories (${TINS_INCLUDE} ${VIFACE_INCLUDE} ${UV_INCLUDE} ${PCAP_INCLUDE})
add_executable (output_exe ${SOURCES} ${HEADERS})

target_link_libraries (output_exe ${TINS_LIB} ${VIFACE_LIB} ${UV_LIB} ${PCAP_LIB})
