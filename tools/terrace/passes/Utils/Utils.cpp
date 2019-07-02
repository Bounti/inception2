#include "Utils.h"

#include "llvm/Support/raw_ostream.h"

using namespace llvm;

cl::opt<bool> PrintFunctions("print_funcs",
                             cl::desc("Print functions after cleaning"),
                             cl::init(false));

cl::opt<bool>
    InsertPrintf("v", cl::desc("Insert information to be printed at runtime"),
                 cl::init(false));

// XXX: some parts of the code assume that the max size of an int is 32bit,
// there may be problems with 64bit numbers

IntegerType *IntType(LLVMContext *ctx, int size) {
  return IntegerType::get(*ctx, size);
}

ConstantInt *ConstInt(LLVMContext *ctx, int size, int val) {
  return ConstantInt::get(IntType(ctx, size), val);
}
