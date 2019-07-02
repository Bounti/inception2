#ifndef CLEAN_FUNCTIONS_H
#define CLEAN_FUNCTIONS_H

#include "llvm/IR/Function.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

int remove_instructions_from_function(Function *F, LLVMContext *ctx);

struct CleanFunctions : public FunctionPass {
  static char ID; // Pass identification, replacement for typeid
  CleanFunctions() : FunctionPass(ID) {}

  LLVMContext *ctx;

  void setLLVMContext(LLVMContext *_ctx) { ctx = _ctx; }

  virtual bool runOnFunction(Function &F) {
    if (remove_instructions_from_function(&F, ctx) > 0)
      return true;
    return false;
  }
};

CleanFunctions *createCleanFunctionsPass();

#endif
