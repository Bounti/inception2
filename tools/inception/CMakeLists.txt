#===------------------------------------------------------------------------===#
#
#                     The KLEE Symbolic Virtual Machine
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
#
#===------------------------------------------------------------------------===#

# Inception build

add_executable(inception
  main.cc
  inception.cc
  inception_executor.cc
  klee-handler.cpp
  target/jlink/JlinkUtil.c
  target/target.cc
  target/usb3dap/usb3dap.cc
  target/usb3dap/usb_device.cc
  target/verilator/verilator.cc
  target/openocd/openocd.cc
  target/jlink/jlink.cc
  target/dummy/dummy.cc
  snapshotting/criu.cc
)

set(KLEE_LIBS
  kleeCore
  kleeModule
)

set(LLVM_COMPONENTS
  core
  bitreader
  bitwriter
  codegen
  ipo
  irreader
  linker
  support
  option
)

target_include_directories(inception PRIVATE target/)
#target_include_directories(inception PRIVATE /home/nasm/Projects/IP4Verilator/criu/lib/c/)

klee_get_llvm_libs(LLVM_LIBS ${LLVM_COMPONENTS})

message(${LLVM_LIBS})

target_link_libraries(inception PUBLIC ${LLVM_LIBS} usb-1.0 jsoncpp criu rt)
target_link_libraries(inception PRIVATE ${KLEE_LIBS} jim openocd target jtag helper transport jaylink pld server ${CMAKE_CURRENT_SOURCE_DIR}/target/jlink/libjlinkarm.so usb-1.0)

install(TARGETS inception RUNTIME DESTINATION bin)

# The KLEE binary depends on the runtimes
add_dependencies(inception BuildKLEERuntimes)
