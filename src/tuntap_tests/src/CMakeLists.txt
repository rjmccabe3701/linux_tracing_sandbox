cmake_minimum_required(VERSION 3.10)
# set the project name
project(Tuntap_test)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 17)


find_package(Boost 1.69 REQUIRED COMPONENTS
   program_options
   # property_tree
   )

include_directories(${Boost_INCLUDE_DIRS})

# add the executable
add_executable(app app.cpp)

target_link_libraries(app ${Boost_LIBRARIES})
