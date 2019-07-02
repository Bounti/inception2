#ifndef LLVMDEMO_UTILS_H
#define LLVMDEMO_UTILS_H

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/CommandLine.h"

#include <stdarg.h>

using namespace llvm;
using namespace std;

extern cl::opt<bool> PrintFunctions;

extern cl::opt<bool> InsertPrintf;

IntegerType *IntType(LLVMContext *ctx, int size);

ConstantInt *ConstInt(LLVMContext *ctx, int size, int val);

void llvm_printf(Module *mod, IRBuilder<> &builder, int count,
                 const char *format_string, ...);

void watch_value(Function *F, string val_to_watch);

#endif
