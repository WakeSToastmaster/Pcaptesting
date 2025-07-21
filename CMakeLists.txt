cmake_minimum_required(VERSION 3.10)



project(WinPcapTesting)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
include(FindPCAP)
##find_package(winpcap CONFIG REQUIRED)

find_package(fmt CONFIG REQUIRED)

add_executable(WinPcapTesting WinPcapTesting.cpp )


target_link_libraries(WinPcapTesting PRIVATE fmt::fmt ${PCAP_LIBRARIES})