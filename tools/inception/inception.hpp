#ifndef KLEE_API_H
#define KLEE_API_H

#include "klee/Config/Version.h"
#include "klee/ExecutionState.h"
#include "klee/Expr.h"
#include "klee/Internal/Support/ErrorHandling.h"
#include "klee/Internal/Support/FileHandling.h"
#include "klee/Internal/Support/ModuleUtil.h"
#include "klee/Internal/Support/PrintVersion.h"
#include "klee/Internal/System/Time.h"
#include "klee/Interpreter.h"
#include "klee/OptionCategories.h"
#include "klee/SolverCmdLine.h"
#include "klee/Statistics.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Errno.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/Signals.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Object/ObjectFile.h"
// #include "llvm/Bitcode/ReaderWriter.h"

#include <dirent.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <sstream>

#include "klee-handler.hpp"
#include "device/device.hpp"

#include "klee/Internal/Module/LLVMPassManager.h"

#include "inception_executor.hpp"

using namespace llvm;
using namespace klee;

class Inception {
public:
  Inception() {
    mainModule = NULL;
    divergence = 1;
    main_fct = NULL;

    // For now, it is fixed here but it could be programmed by users
    Interpreter::InterpreterOptions IOpts;
    IOpts.MakeConcreteSymbolic = false;

    // Create empty arguments for KleeHandler
    auto pArgc = 0;
    auto pArgv = new char *[pArgc];
    // Create a new KleeHandler
    handler = new KleeHandler(pArgc, pArgv, bc_file_name);
    // Create the Executor
    interpreter = new InceptionExecutor(ctx, IOpts, handler);

    handler->setInterpreter(interpreter);
  };

  ~Inception() { shutdown(); };

  void add_target(Target* io_device, device* irq_device){
    interpreter->add_target(io_device, irq_device);
  }

  void load_configuration(char **argv) {

    std::string LibraryDir = KleeHandler::getRunTimeLibraryPath(argv[0]);

    Interpreter::ModuleOptions Opts(LibraryDir.c_str(), "main",
                                    /*Optimize=*/false,
                                    /*CheckDivZero=*/true,
                                    /*CheckOvershift=*/true);

    std::vector<std::unique_ptr<llvm::Module>> loadedModules;
    loadedModules.emplace_back(std::move(mainModule));

    auto finalModule = interpreter->setModule(loadedModules, Opts);

    mainModule = finalModule;
  }

  // We load the bitfile
  void load_llvm_bitcode_from_file(const char *_bc_file_name);

  // Load ELF binary
  void load_elf_binary_from_file(const char* _elf_file_name);

  // Load memory configuration from file
  void load_mem_conf_from_file(const char* _mem_conf_file_name);

  // Load interrupt configuration from file
  void load_interrupt_conf_from_file(const char* _interrupt_conf_file_name);

  // We set the entry point and start execution
  void set_main_function_by_address(unsigned int address){};

  // Execute trace
  void run();

  // Shutdown of all components
  void shutdown() { 
    interpreter->shutdown();
    
    delete interpreter;
  };

  void interrupt_handle() {
    if (!interrupted && interpreter) {
      llvm::errs()
          << "KLEE: ctrl-c detected, requesting interpreter to halt.\n";
      interpreter->setHaltExecution(true);
      // sys::SetInterruptFunction(interrupt_handle);
    } else {
      llvm::errs() << "KLEE: ctrl-c detected, exiting.\n";
      exit(1);
    }
    interrupted = true;
  }

  void runPasses();

  void prepare();

  void start_analysis();

private:
  bool record_time;

  uint64_t divergence;

  LLVMContext ctx;

  InceptionExecutor *interpreter;

  KleeHandler *handler;

  llvm::Module *mainModule;

  llvm::Function *main_fct;

  bool interrupted = false;

  std::string bc_file_name;
};

#endif
