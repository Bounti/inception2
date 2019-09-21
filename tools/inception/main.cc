/* -*- mode: c++; c-basic-offset: 2; -*- */

//===-- main.cpp ------------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
#include "llvm/Support/CommandLine.h"

#include <fstream>
#include <sstream>
#include <string>

using namespace llvm;
using namespace std;

#include "inception.hpp"

/*
 * Arguments specific to Inception
 */

cl::opt<std::string> bitcode_file("bitcode", cl::desc("<input bitcode>"),
                                  cl::Required);

cl::opt<std::string> elf_file("elf", cl::desc("<input ELF binary>"),
                                  cl::Required);

cl::opt<bool>
hasDebugger("has-debugger",
          cl::init(false),
          cl::desc("is the Inception debugger attached (default=false)"));

//cl::opt<std::string> irq_hook_table_file("irq_hook_table_file", cl::desc("<irq hook table file>"));

static void parseArguments(int argc, char **argv) {
  // cl::SetVersionPrinter(klee::printVersion);
  // This version always reads response files
  cl::ParseCommandLineOptions(argc, argv, " klee\n");
}

int main(int argc, char **argv) {

  // Call llvm_shutdown() on exit.
  atexit(llvm_shutdown);

  KCommandLine::HideOptions(llvm::cl::GeneralCategory);

  llvm::InitializeNativeTarget();

  parseArguments(argc, argv);
  sys::PrintStackTraceOnErrorSignal();

  /*
   * This main is a refacto of the original klee code
   */

  // 1. We init Inception
  Inception *inception = new Inception();

  // 2. We load the bitfile
  inception->load_llvm_bitcode_from_file(bitcode_file.c_str());

  // 3. Load ELF binary
  inception->load_elf_binary_from_file(elf_file.c_str());

  // 4. Load IRQ Hooks Table from file
  //inception->load_irq_hook_table_from_file(irq_hook_table_file.c_str());

  // 4. Run Inception Passes to lower assembly and binary dependencies in LLVM IR
  inception->runPasses();

  inception->load_configuration(argv);

  // 5. start analysis
  inception->run();

  // 6. Clean memory and close inception
  inception->shutdown();

  return 0;
}
