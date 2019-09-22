#ifndef INCEPTION_EXECUTOR
#define INCEPTION_EXECUTOR

#include "klee/ExecutionState.h"
#include "klee/Interpreter.h"
#include "../lib/Core/Executor.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"

#include <string>
#include <vector>

using namespace llvm;

namespace klee {

class InceptionExecutor : public Executor{
  public:

  ExecutionState *init_state; 

  void addCustomObject(std::string name, std::uint64_t addr, unsigned size, 
                        bool isReadOnly, bool isSymbolic,
                        bool isRandomized, bool isForwarded);

  void start_analysis();

  void executeInstruction(ExecutionState &state, KInstruction *ki);

  void initializeGlobals(ExecutionState &state);

  void run(ExecutionState &initialState);

  void initFunctionAsMain(Function *f,
				 int argc,
				 char **argv,
				 char **envp);

  InceptionExecutor(llvm::LLVMContext &ctx, const InterpreterOptions &opts,
      InterpreterHandler *ie) : Executor(ctx, opts, ie) {
  };

	void executeMemoryOperation(ExecutionState &state,
                                      bool isWrite,
                                      ref<Expr> address,
                                      ref<Expr> value /* undef if read */,
                                      KInstruction *target /* undef if write */);
};
}
#endif
