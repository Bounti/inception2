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
  target/openocd.cc
  target/target.cc
)

set(KLEE_LIBS
  kleeCore
  kleeModule
  Device
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

klee_get_llvm_libs(LLVM_LIBS ${LLVM_COMPONENTS})

message(${LLVM_LIBS})

target_link_libraries(inception PUBLIC ${LLVM_LIBS} usb-1.0 jsoncpp)
target_link_libraries(inception PRIVATE ${KLEE_LIBS} jim openocd target jtag helper transport jaylink pld server)

install(TARGETS inception RUNTIME DESTINATION bin)

# The KLEE binary depends on the runtimes
add_dependencies(inception BuildKLEERuntimes)
