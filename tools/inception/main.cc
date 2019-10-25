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

#include "device/device.hpp"
#include "target/target.hpp"

/*
 * Arguments specific to Inception
 */

cl::opt<std::string> bitcode_file("bitcode", cl::desc("<input bitcode>"),
                                  cl::Required);

cl::opt<std::string> elf_file("elf", cl::desc("<input ELF binary>"),
                                  cl::Required);

cl::opt<bool>
enable_hw_snapshot("enable_hw_snapshot",
          cl::init(false),
          cl::desc("<enable hardware snapshot> (default=false)"));

cl::opt<std::string> mem_conf_file("mem_conf_file", cl::desc("<memory configuration file>"));

cl::opt<std::string> interrupt_conf_file("interrupt_conf_file", cl::desc("<interrupt configuration file>"));

static void parseArguments(int argc, char **argv) {
  // cl::SetVersionPrinter(klee::printVersion);
  // This version always reads response files
  cl::ParseCommandLineOptions(argc, argv, " klee\n");
}

int main(int argc, char **argv) {

  Target* io     = NULL;
  device* io_snp = NULL;
  device* irq_io = NULL;

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

  //if( enable_hw_snapshot ) {

    //io_snp = new device(0x04B4, 0x00F1, 0);
    //io_snp->init();
  //}

  //if( has_debugger ) {

  //  io = Target::build(debugger_name);
  //  io->init();

  //  irq_io = new device(0x04b4, 0x00f1, 0, 0x02, 0x82);
  //  irq_io->init();
  //  irq_io->accept_timeout();

  //  inception->add_target(io, irq_io);
  //}

  // 2. We load the bitfile
  inception->load_llvm_bitcode_from_file(bitcode_file.c_str());

  // 3. Load ELF binary
  inception->load_elf_binary_from_file(elf_file.c_str());

  // 4. Run Inception Passes to lower assembly and binary dependencies in LLVM IR
  inception->runPasses();

  inception->load_configuration(argv);

  inception->prepare();

  // 4. Load memory configuration from file
  inception->load_mem_conf_from_file(mem_conf_file.c_str());

  // 5. We load the configuration
  inception->load_targets_conf_from_file(mem_conf_file.c_str());

  // 6. Load interrupt model from file
  inception->load_interrupt_conf_from_file(interrupt_conf_file.c_str());

  // 7. start analysis
  inception->start_analysis();

  // 8. Clean memory and close inception
  inception->shutdown();

  //if( has_debugger ) {
  //  irq_io->close();
  //  io->close();
  //}

  return 0;
}
