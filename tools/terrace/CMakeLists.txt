#===------------------------------------------------------------------------===#
#
#                     The KLEE Symbolic Virtual Machine
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
#
#===------------------------------------------------------------------------===#

# Terrace build

add_executable(terrace
  main.cc
  terrace.cc
  klee-handler.cpp
  ./passes/CleanFunctions/CleanFunctions.cpp
  ./passes/Utils/Utils.cpp
  ./passes/BreakIntToPtr/BreakIntToPtr.cpp
)

set(KLEE_LIBS
  kleeCore
  kleeModule
  kleeProto
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
)

klee_get_llvm_libs(LLVM_LIBS ${LLVM_COMPONENTS})

message(${LLVM_LIBS})

target_link_libraries(terrace PUBLIC ${LLVM_LIBS})
target_link_libraries(terrace PRIVATE ${KLEE_LIBS})

install(TARGETS terrace RUNTIME DESTINATION bin)

# The KLEE binary depends on the runtimes
add_dependencies(terrace BuildKLEERuntimes)
