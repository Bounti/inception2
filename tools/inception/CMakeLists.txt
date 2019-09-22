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
  utils/dummy_object_file.cpp
  helper_functions/functions_helper_writer.cpp
  passes/ir_merger.cpp
)

set(KLEE_LIBS
  kleeCore
  kleeModule
  CodeInv
  Target
  Transforms
  Utils
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
  all all-targets analysis arm bitreader bitwriter codegen core debuginfo engine executionengine instcombine instrumentation interpreter ipa ipo irreader lineeditor linker lto mc mcdisassembler mcjit mcparser mips mipsasmparser mipsasmprinter mipscodegen mipsdesc mipsdisassembler mipsinfo msp430 msp430asmprinter msp430codegen msp430desc msp430info native nativecodegen nvptx nvptxasmprinter nvptxcodegen nvptxdesc nvptxinfo objcarcopts object option powerpc powerpcasmparser powerpcasmprinter powerpccodegen powerpcdesc powerpcdisassembler powerpcinfo profiledata r600 r600asmparser r600asmprinter r600codegen r600desc r600info runtimedyld scalaropts selectiondag sparc sparcasmparser sparcasmprinter sparccodegen sparcdesc sparcdisassembler sparcinfo support systemz systemzasmparser systemzasmprinter systemzcodegen systemzdesc systemzdisassembler systemzinfo tablegen target transformutils vectorize x86 x86asmparser x86asmprinter x86codegen x86desc x86disassembler x86info x86utils xcore xcoreasmprinter xcorecodegen xcoredesc xcoredisassembler xcoreinfo
  )

klee_get_llvm_libs(LLVM_LIBS ${LLVM_COMPONENTS})

message(${LLVM_LIBS})

target_link_libraries(inception PUBLIC ${LLVM_LIBS})
target_link_libraries(inception PRIVATE ${KLEE_LIBS})

install(TARGETS inception RUNTIME DESTINATION bin)

# The KLEE binary depends on the runtimes
add_dependencies(inception BuildKLEERuntimes)
