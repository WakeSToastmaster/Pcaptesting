cmake_minimum_required(VERSION 3.10)



project(WinPcapTesting)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
include(FindPCAP)
##find_package(winpcap CONFIG REQUIRED)

find_package(fmt CONFIG REQUIRED)
find_package(Eigen3 CONFIG REQUIRED)

add_executable(WinPcapTesting WinPcapTesting.cpp  "approx.h" "approx.cpp")
set_property(TARGET WinPcapTesting PROPERTY CXX_STANDARD 20)


target_link_libraries(WinPcapTesting PRIVATE fmt::fmt ${PCAP_LIBRARIES} Eigen3::Eigen)