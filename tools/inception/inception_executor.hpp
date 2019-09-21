#ifdef INCEPTION_EXECUTOR
#define INCEPTION_EXECUTOR

#include "klee/ExecutionState.h"
#include "klee/Interpreter.h"

#include <string>
#include <vector>

class InceptionExecutor : public Executor{

	InceptionExecutor::InceptionExecutor();

	void InceptionExecutor::executeMemoryOperation(ExecutionState &state,
                                      bool isWrite,
                                      ref<Expr> address,
                                      ref<Expr> value /* undef if read */,
                                      KInstruction *target /* undef if write */);
};

#endif
