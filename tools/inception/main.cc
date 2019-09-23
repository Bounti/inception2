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

#include "device.hpp"

/*
 * Arguments specific to Inception
 */

cl::opt<std::string> bitcode_file("bitcode", cl::desc("<input bitcode>"),
                                  cl::Required);

cl::opt<std::string> elf_file("elf", cl::desc("<input ELF binary>"),
                                  cl::Required);

cl::opt<bool>
has_debugger("has_debugger",
          cl::init(false),
          cl::desc("is the Inception debugger attached (default=false)"));

cl::opt<bool>
inspect_ir("inspect_ir",
          cl::init(false),
          cl::desc("inspect lifted IR functions (default=false)"));

cl::opt<std::string> mem_conf_file("mem_conf_file", cl::desc("<memory configuration file>"));

static void parseArguments(int argc, char **argv) {
  // cl::SetVersionPrinter(klee::printVersion);
  // This version always reads response files
  cl::ParseCommandLineOptions(argc, argv, " klee\n");
}

int main(int argc, char **argv) {

  device* io = NULL;

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

  if( has_debugger ) {
    io = new device(0x04B4, 0x00F1, 0);

    io->init();

    inception->add_target(io);
  }

  // 2. We load the bitfile
  inception->load_llvm_bitcode_from_file(bitcode_file.c_str());

  // 3. Load ELF binary
  inception->load_elf_binary_from_file(elf_file.c_str());

  // 4. Run Inception Passes to lower assembly and binary dependencies in LLVM IR
  inception->runPasses();

  // is interactive mode asked ?
  if( inspect_ir ) {}

  inception->load_configuration(argv);

  inception->prepare();
 
  
  // 4. Load memory configuration from file
  inception->load_mem_conf_from_file(mem_conf_file.c_str());

  // 5. start analysis
  inception->start_analysis();

  // 6. Clean memory and close inception
  inception->shutdown();

  if( has_debugger ) {
    io->close();
  }

  return 0;
}
