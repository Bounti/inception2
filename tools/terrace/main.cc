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

#include "terrace.hpp"

cl::opt<std::string> bitcode_file("bitcode", cl::desc("<input bitcode>"),
                                  cl::Required);

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
  sys::PrintStackTraceOnErrorSignal(argv[0]);

  /*
   * This main is a refacto of the original klee code
   */
  // Local declarations
  TBBBlocks *tbb = NULL;

  // 1. We init Terrace
  Terrace *terrace = new Terrace();

  // 2. We load the bitfile
  terrace->load_llvm_bitcode_from_file(bitcode_file.c_str());

  // 3. Run Terrace Passes to make LLVM IR from Panda compliant
  // * Break nested instructions into atomic ones so that next step becomes easier
  // * Remove unnecessary instructions such as instructions counting
  // * Create main function with call tree based on input traces
  terrace->runPasses();

  // Here we run some passes to remove code intrinsic to Panda
  terrace->load_configuration(argv);

  // 5. We set the entry point and start execution
  // klee->set_main_function_by_address(->get_entry_point());
  terrace->run();

  // 6. We ask Klee to solved all constraints
  // terrace->generate_test_cases();

  // 7. We backup our constraints in files
  // terrace->export_test_cases("test_cases.bin");

  // 8. Shutdown of all components
  // terrace->shutdown();

  return 0;
}
