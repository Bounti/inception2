#===------------------------------------------------------------------------===#
#
#                     The KLEE Symbolic Virtual Machine
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
#
#===------------------------------------------------------------------------===#

# Inception build

include_directories("${CMAKE_SOURCE_DIR}/lib/Core")

set(SOURCE_FILES
  main.cc
  inception.cc
  inception_executor.cc
  klee-handler.cpp
  target/target.cc
)

  if(TARGET_JLINK_ACTIVE)
  list(APPEND SOURCE_FILES
  target/jlink/JlinkUtil.c
  target/jlink/jlink.cc
  )
  endif()
  if(TARGET_STEROIDS_ACTIVE)
  list(APPEND SOURCE_FILES
  target/usb3dap/usb3dap.cc
  target/usb3dap/usb_device.cc
  )
  endif()
  if(TARGET_VERILATOR_ACTIVE)
  list(APPEND SOURCE_FILES
  target/verilator/verilator.cc
  )
  endif()
  if(TARGET_OPENOCD_ACTIVE)
  list(APPEND SOURCE_FILES
  target/openocd/openocd.cc
  )
  endif()

add_executable(inception ${SOURCE_FILES})

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

target_link_libraries(inception PUBLIC ${LLVM_LIBS} usb-1.0 jsoncpp rt ${CMAKE_CURRENT_SOURCE_DIR}/target/jlink/libjlinkarm.so pthread)
#criu
target_link_libraries(inception PRIVATE ${KLEE_LIBS})
# jim openocd target jtag helper transport jaylink pld server)

install(TARGETS inception RUNTIME DESTINATION bin)

# The KLEE binary depends on the runtimes
add_dependencies(inception BuildKLEERuntimes)
