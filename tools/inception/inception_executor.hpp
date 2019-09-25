#ifndef INCEPTION_EXECUTOR
#define INCEPTION_EXECUTOR

#include "klee/ExecutionState.h"
#include "klee/Interpreter.h"
#include "../lib/Core/Executor.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Object/ObjectFile.h"
#include "device/device.hpp"

#include <string>
#include <vector>
#include <set>

using namespace llvm;

namespace klee {

class InceptionExecutor : public Executor{
  private:
  /// The set of legal function addresses, used to validate function
  /// pointers. We use the symbol table to get the function address.
  // Otherwise we use the Function address.
  std::map<uint64_t, llvm::Function *> inceptionLegalFunctions;

  std::unique_ptr<object::ObjectFile> elf;
  //object::ObjectFile* elf;
  
  ExecutionState *init_state; 

  object::SymbolRef resolve_elf_symbol_by_name(std::string expected_name, bool* success);

  object::SectionRef resolve_elf_section_by_name(std::string expected_name, bool* success);

  std::set<uint64_t> forwarded_mem; 

  device* io;

  public: 

  void add_target(device* _device){
    io = _device;
  }

  void set_elf(std::unique_ptr<object::ObjectFile>& _elf) {
    elf = std::move(_elf);
  }

  void allocate_device_memory();

  MemoryObject* addCustomObject(std::string name, std::uint64_t addr, unsigned size, 
                        bool isReadOnly, bool isSymbolic,
                        bool isRandomized, bool isForwarded, const llvm::Value* allocSite = nullptr);

  void start_analysis();

  void executeInstruction(ExecutionState &state, KInstruction *ki);

  void initializeGlobals(ExecutionState &state);

  void run(ExecutionState &initialState);

  void initFunctionAsMain(Function *f,
				 int argc,
				 char **argv,
				 char **envp);

  InceptionExecutor(llvm::LLVMContext &ctx, const InterpreterOptions &opts,
      InterpreterHandler *ie) : Executor(ctx, opts, ie){
    io = NULL;
  };

	void executeMemoryOperation(ExecutionState &state,
                                      bool isWrite,
                                      ref<Expr> address,
                                      ref<Expr> value /* undef if read */,
                                      KInstruction *target /* undef if write */);
};
}
#endif
