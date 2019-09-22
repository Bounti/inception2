#include "inception_executor.hpp"

#include "klee/ExecutionState.h"
#include "klee/Expr.h"
#include "../lib/Core/Executor.h"

#include "../lib/Core/Context.h"
#include "../lib/Core/CoreStats.h"
#include "../lib/Core/ExecutorTimerInfo.h"
#include "../lib/Core/ExternalDispatcher.h"
#include "../lib/Core/ImpliedValue.h"
#include "../lib/Core/Memory.h"
#include "../lib/Core/MemoryManager.h"
#include "../lib/Core/PTree.h"
#include "../lib/Core/Searcher.h"
#include "../lib/Core/SeedInfo.h"
#include "../lib/Core/SpecialFunctionHandler.h"
#include "../lib/Core/StatsTracker.h"
#include "../lib/Core/TimingSolver.h"
#include "../lib/Core/UserSearcher.h"

#include "klee/Common.h"
#include "klee/Config/Version.h"
#include "klee/ExecutionState.h"
#include "klee/Expr.h"
#include "klee/Internal/ADT/KTest.h"
#include "klee/Internal/ADT/RNG.h"
#include "klee/Internal/Module/Cell.h"
#include "klee/Internal/Module/InstructionInfoTable.h"
#include "klee/Internal/Module/KInstruction.h"
#include "klee/Internal/Module/KModule.h"
#include "klee/Internal/Support/ErrorHandling.h"
#include "klee/Internal/Support/FileHandling.h"
#include "klee/Internal/Support/FloatEvaluation.h"
#include "klee/Internal/Support/ModuleUtil.h"
#include "klee/Internal/System/MemoryUsage.h"
#include "klee/Internal/System/Time.h"
#include "klee/Interpreter.h"
#include "klee/OptionCategories.h"
#include "klee/SolverCmdLine.h"
#include "klee/SolverStats.h"
#include "klee/TimerStatIncrementer.h"
#include "klee/util/Assignment.h"
#include "klee/util/ExprPPrinter.h"
#include "klee/util/ExprSMTLIBPrinter.h"
#include "klee/util/ExprUtil.h"
#include "klee/util/GetElementPtrTypeIterator.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"

using namespace llvm;

namespace klee {

extern void *__dso_handle __attribute__ ((__weak__));

void InceptionExecutor::addCustomObject(std::string name, std::uint64_t addr, unsigned size,
                                           bool isReadOnly, bool isSymbolic,
                                           bool isRandomized, bool isForwarded) {

  klee_message("adding custom object at %08x with size %08x with name %s - conf [ReadOnly;Symbolic;Randomized;Forwarded] %c|%c|%c|%c", addr, size, name.c_str(), isReadOnly ? 'Y':'N', isSymbolic ? 'Y':'N', isRandomized ? 'Y':'N', isForwarded ? 'Y':'N');
  
  auto mo = memory->allocateFixed(addr, size, nullptr);

  mo->setName(name);
  //mo->isSymbolic = isSymbolic;
  //mo->isRandomized = isRandomized;
  //mo->isForwarded = isForwarded;
  
  ObjectState *os = bindObjectInState(*init_state, mo, false);
  if(isReadOnly)
    os->setReadOnly(true);

  if( isRandomized )
    os->initializeToRandom();
  else if( isSymbolic )
    executeMakeSymbolic(*init_state, mo, name);
  else if( isForwarded )
    os->initializeToZero();
  else 
    os->initializeToZero();
}

void InceptionExecutor::executeInstruction(ExecutionState &state, KInstruction *ki) {

  Instruction *i = ki->inst;
  switch (i->getOpcode()) {
    case Instruction::Load: {
      ref<Expr> base = eval(ki, 0, state).value;
      executeMemoryOperation(state, false, base, 0, ki);
      break;
    }
    case Instruction::Store: {
      ref<Expr> base = eval(ki, 1, state).value;
      ref<Expr> value = eval(ki, 0, state).value;
      executeMemoryOperation(state, true, base, value, 0);
      break;
    }
    default:
     Executor::executeInstruction(state, ki);
    break;
  }
}

void InceptionExecutor::initializeGlobals(ExecutionState &state) {
  Module *m = kmodule->module.get();

  if (m->getModuleInlineAsm() != "")
    klee_warning("executable has module level assembly (ignoring)");
  // represent function globals using the address of the actual llvm function
  // object. given that we use malloc to allocate memory in states this also
  // ensures that we won't conflict. we don't need to allocate a memory object
  // since reading/writing via a function pointer is unsupported anyway.
  for (Module::iterator i = m->begin(), ie = m->end(); i != ie; ++i) {
    Function *f = &*i;
    ref<ConstantExpr> addr(0);

    // If the symbol has external weak linkage then it is implicitly
    // not defined in this module; if it isn't resolvable then it
    // should be null.
    if (f->hasExternalWeakLinkage() &&
        !externalDispatcher->resolveSymbol(f->getName())) {
      addr = Expr::createPointer(0);
    } else {
      addr = Expr::createPointer(reinterpret_cast<std::uint64_t>(f));
      legalFunctions.insert(reinterpret_cast<std::uint64_t>(f));
    }

    globalAddresses.insert(std::make_pair(f, addr));
  }

#ifndef WINDOWS
  int *errno_addr = getErrnoLocation(state);
  MemoryObject *errnoObj =
      addExternalObject(state, (void *)errno_addr, sizeof *errno_addr, false);
  // Copy values from and to program space explicitly
  errnoObj->isUserSpecified = true;
#endif

  // Disabled, we don't want to promote use of live externals.
#ifdef HAVE_CTYPE_EXTERNALS
#ifndef WINDOWS
#ifndef DARWIN
  /* from /usr/include/ctype.h:
       These point into arrays of 384, so they can be indexed by any `unsigned
       char' value [0,255]; by EOF (-1); or by any `signed char' value
       [-128,-1).  ISO C requires that the ctype functions work for `unsigned */
  const uint16_t **addr = __ctype_b_loc();
  addExternalObject(state, const_cast<uint16_t*>(*addr-128),
                    384 * sizeof **addr, true);
  addExternalObject(state, addr, sizeof(*addr), true);

  const int32_t **lower_addr = __ctype_tolower_loc();
  addExternalObject(state, const_cast<int32_t*>(*lower_addr-128),
                    384 * sizeof **lower_addr, true);
  addExternalObject(state, lower_addr, sizeof(*lower_addr), true);

  const int32_t **upper_addr = __ctype_toupper_loc();
  addExternalObject(state, const_cast<int32_t*>(*upper_addr-128),
                    384 * sizeof **upper_addr, true);
  addExternalObject(state, upper_addr, sizeof(*upper_addr), true);
#endif
#endif
#endif

  // allocate and initialize globals, done in two passes since we may
  // need address of a global in order to initialize some other one.

  // allocate memory objects for all globals
  for (Module::const_global_iterator i = m->global_begin(),
         e = m->global_end();
       i != e; ++i) {
    const GlobalVariable *v = &*i;
    size_t globalObjectAlignment = getAllocationAlignment(v);
    if (i->isDeclaration()) {
      // FIXME: We have no general way of handling unknown external
      // symbols. If we really cared about making external stuff work
      // better we could support user definition, or use the EXE style
      // hack where we check the object file information.

      Type *ty = i->getType()->getElementType();
      uint64_t size = 0;
      if (ty->isSized()) {
	size = kmodule->targetData->getTypeStoreSize(ty);
      } else {
        klee_warning("Type for %.*s is not sized", (int)i->getName().size(),
			i->getName().data());
      }

      // XXX - DWD - hardcode some things until we decide how to fix.
#ifndef WINDOWS
      if (i->getName() == "_ZTVN10__cxxabiv117__class_type_infoE") {
        size = 0x2C;
      } else if (i->getName() == "_ZTVN10__cxxabiv120__si_class_type_infoE") {
        size = 0x2C;
      } else if (i->getName() == "_ZTVN10__cxxabiv121__vmi_class_type_infoE") {
        size = 0x2C;
      }
#endif

      if (size == 0) {
        klee_warning("Unable to find size for global variable: %.*s (use will result in out of bounds access)",
			(int)i->getName().size(), i->getName().data());
      }

      MemoryObject *mo = memory->allocate(size, /*isLocal=*/false,
                                          /*isGlobal=*/true, /*allocSite=*/v,
                                          /*alignment=*/globalObjectAlignment);
      ObjectState *os = bindObjectInState(state, mo, false);
      globalObjects.insert(std::make_pair(v, mo));
      globalAddresses.insert(std::make_pair(v, mo->getBaseExpr()));

      // Program already running = object already initialized.  Read
      // concrete value and write it to our copy.
      if (size) {
        void *addr;
        if (i->getName() == "__dso_handle") {
          addr = &__dso_handle; // wtf ?
        } else {
          addr = externalDispatcher->resolveSymbol(i->getName());
        }
        if (!addr)
          klee_error("unable to load symbol(%s) while initializing globals.",
                     i->getName().data());

        for (unsigned offset=0; offset<mo->size; offset++)
          os->write8(offset, ((unsigned char*)addr)[offset]);
      }
    } else {
      Type *ty = i->getType()->getElementType();
      uint64_t size = kmodule->targetData->getTypeStoreSize(ty);
      MemoryObject *mo = memory->allocate(size, /*isLocal=*/false,
                                          /*isGlobal=*/true, /*allocSite=*/v,
                                          /*alignment=*/globalObjectAlignment);
      if (!mo)
        llvm::report_fatal_error("out of memory");
      ObjectState *os = bindObjectInState(state, mo, false);
      globalObjects.insert(std::make_pair(v, mo));
      globalAddresses.insert(std::make_pair(v, mo->getBaseExpr()));

      if (!i->hasInitializer())
          os->initializeToRandom();
    }
  }

  // link aliases to their definitions (if bound)
  for (auto i = m->alias_begin(), ie = m->alias_end(); i != ie; ++i) {
    // Map the alias to its aliasee's address. This works because we have
    // addresses for everything, even undefined functions.

    // Alias may refer to other alias, not necessarily known at this point.
    // Thus, resolve to real alias directly.
    const GlobalAlias *alias = &*i;
    while (const auto *ga = dyn_cast<GlobalAlias>(alias->getAliasee())) {
      assert(ga != alias && "alias pointing to itself");
      alias = ga;
    }

    globalAddresses.insert(std::make_pair(&*i, evalConstant(alias->getAliasee())));
  }

  // once all objects are allocated, do the actual initialization
  for (Module::const_global_iterator i = m->global_begin(),
         e = m->global_end();
       i != e; ++i) {
    if (i->hasInitializer()) {
      const GlobalVariable *v = &*i;
      MemoryObject *mo = globalObjects.find(v)->second;
      const ObjectState *os = state.addressSpace.findObject(mo);
      assert(os);
      ObjectState *wos = state.addressSpace.getWriteable(mo, os);

      initializeGlobalObject(state, wos, i->getInitializer(), 0);
      // if(i->isConstant()) os->setReadOnly(true);
    }
  }
}

void InceptionExecutor::executeMemoryOperation(ExecutionState &state,
                                      bool isWrite,
                                      ref<Expr> address,
                                      ref<Expr> value /* undef if read */,
                                      KInstruction *target /* undef if write */) {

  Expr::Width type = (isWrite ? value->getWidth() :
                     getWidthForLLVMType(target->inst->getType()));
  unsigned bytes = Expr::getMinBytesForWidth(type);

  address = optimizer.optimizeExpr(address, true);

  // fast path: single in-bounds resolution
  ObjectPair op;
  bool success;
  solver->setTimeout(coreSolverTimeout);
  if (!state.addressSpace.resolveOne(state, solver, address, op, success)) {
    address = toConstant(state, address, "resolveOne failure");
    success = state.addressSpace.resolveOne(cast<ConstantExpr>(address), op);
  }
  solver->setTimeout(time::Span());

  if (success) {
    const MemoryObject *mo = op.first;

    ref<Expr> offset = mo->getOffsetExpr(address);
    ref<Expr> check = mo->getBoundsCheckOffset(offset, bytes);
    check = optimizer.optimizeExpr(check, true);

    bool inBounds;
    solver->setTimeout(coreSolverTimeout);
    bool success = solver->mustBeTrue(state, check, inBounds);
    solver->setTimeout(time::Span());
    if (!success) {
      state.pc = state.prevPC;
      terminateStateEarly(state, "Query timed out (bounds check).");
      return;
    }

    if (inBounds) {
      const ObjectState *os = op.second;
      if (isWrite) {
        if (os->readOnly) {
          terminateStateOnError(state, "memory error: object read only",
                                ReadOnly);
        } else {
          ObjectState *wos = state.addressSpace.getWriteable(mo, os);
          wos->write(offset, value);
        }
      } else {
        ref<Expr> result = os->read(offset, type);

        if (interpreterOpts.MakeConcreteSymbolic)
          result = replaceReadWithSymbolic(state, result);

        bindLocal(target, state, result);
      }

      return;
    }
  }

  // we are on an error path (no resolution, multiple resolution, one
  // resolution with out of bounds)

  address = optimizer.optimizeExpr(address, true);
  ResolutionList rl;
  solver->setTimeout(coreSolverTimeout);
  bool incomplete = state.addressSpace.resolve(state, solver, address, rl,
                                               0, coreSolverTimeout);
  solver->setTimeout(time::Span());

  // XXX there is some query wasteage here. who cares?
  ExecutionState *unbound = &state;

  for (ResolutionList::iterator i = rl.begin(), ie = rl.end(); i != ie; ++i) {
    const MemoryObject *mo = i->first;
    const ObjectState *os = i->second;
    ref<Expr> inBounds = mo->getBoundsCheckPointer(address, bytes);

    StatePair branches = fork(*unbound, inBounds, true);
    ExecutionState *bound = branches.first;

    // bound can be 0 on failure or overlapped
    if (bound) {
      if (isWrite) {
        if (os->readOnly) {
          terminateStateOnError(*bound, "memory error: object read only",
                                ReadOnly);
        } else {
          ObjectState *wos = bound->addressSpace.getWriteable(mo, os);
          wos->write(mo->getOffsetExpr(address), value);
        }
      } else {
        ref<Expr> result = os->read(mo->getOffsetExpr(address), type);
        bindLocal(target, *bound, result);
      }
    }

    unbound = branches.second;
    if (!unbound)
      break;
  }

  // XXX should we distinguish out of bounds and overlapped cases?
  if (unbound) {
    if (incomplete) {
      terminateStateEarly(*unbound, "Query timed out (resolve).");
    } else {
      terminateStateOnError(*unbound, "memory error: out of bound pointer", Ptr,
                            NULL, getAddressInfo(*unbound, address));
    }
  }

  //klee_message("ExecutorMemoryOperation !");
  //Executor::executeMemoryOperation(state, isWrite, address, value, target);
}

/*
 * Overriding the run method, enables Inception to force the execution of interrupt when one is pending.
 * Futermore, it enables overriding subsequent methods such as executeMemoryOperation
*/
void InceptionExecutor::run(ExecutionState &initialState) {
  bindModuleConstants();

  // Delay init till now so that ticks don't accrue during
  // optimization and such.
  initTimers();

  states.insert(&initialState);

  searcher = constructUserSearcher(*this);

  std::vector<ExecutionState *> newStates(states.begin(), states.end());
  searcher->update(0, newStates, std::vector<ExecutionState *>());

  while (!states.empty() && !haltExecution) {
    ExecutionState &state = searcher->selectState();
    KInstruction *ki = state.pc;
    stepInstruction(state);

    executeInstruction(state, ki);
    processTimers(&state, maxInstructionTime);

    checkMemoryUsage();

    updateStates(&state);
  }

  delete searcher;
  searcher = 0;

  doDumpStates();
}

void InceptionExecutor::initFunctionAsMain(Function *f,
				 int argc,
				 char **argv,
				 char **envp) {

  klee_message("inception module enabled");

  std::vector<ref<Expr> > arguments;

  // force deterministic initialization of memory objects
  srand(1);
  srandom(1);

  MemoryObject *argvMO = 0;

  // In order to make uclibc happy and be closer to what the system is
  // doing we lay out the environments at the end of the argv array
  // (both are terminated by a null). There is also a final terminating
  // null that uclibc seems to expect, possibly the ELF header?

  int envc;
  for (envc=0; envp[envc]; ++envc) ;

  unsigned NumPtrBytes = Context::get().getPointerWidth() / 8;
  KFunction *kf = kmodule->functionMap[f];
  assert(kf);
  Function::arg_iterator ai = f->arg_begin(), ae = f->arg_end();
  if (ai!=ae) {
    arguments.push_back(ConstantExpr::alloc(argc, Expr::Int32));
    if (++ai!=ae) {
      Instruction *first = &*(f->begin()->begin());
      argvMO =
          memory->allocate((argc + 1 + envc + 1 + 1) * NumPtrBytes,
                           /*isLocal=*/false, /*isGlobal=*/true,
                           /*allocSite=*/first, /*alignment=*/8);

      if (!argvMO)
        klee_error("Could not allocate memory for function arguments");

      arguments.push_back(argvMO->getBaseExpr());

      if (++ai!=ae) {
        uint64_t envp_start = argvMO->address + (argc+1)*NumPtrBytes;
        arguments.push_back(Expr::createPointer(envp_start));

        if (++ai!=ae)
          klee_error("invalid main function (expect 0-3 arguments)");
      }
    }
  }

  init_state = new ExecutionState(kmodule->functionMap[f]);

  if (pathWriter)
    init_state->pathOS = pathWriter->open();
  if (symPathWriter)
    init_state->symPathOS = symPathWriter->open();


  if (statsTracker)
    statsTracker->framePushed(*init_state, 0);

  assert(arguments.size() == f->arg_size() && "wrong number of arguments");
  for (unsigned i = 0, e = f->arg_size(); i != e; ++i)
    bindArgument(kf, i, *init_state, arguments[i]);

  if (argvMO) {
    ObjectState *argvOS = bindObjectInState(*init_state, argvMO, false);

    for (int i=0; i<argc+1+envc+1+1; i++) {
      if (i==argc || i>=argc+1+envc) {
        // Write NULL pointer
        argvOS->write(i * NumPtrBytes, Expr::createPointer(0));
      } else {
        char *s = i<argc ? argv[i] : envp[i-(argc+1)];
        int j, len = strlen(s);

        MemoryObject *arg =
            memory->allocate(len + 1, /*isLocal=*/false, /*isGlobal=*/true,
                             /*allocSite=*/init_state->pc->inst, /*alignment=*/8);
        if (!arg)
          klee_error("Could not allocate memory for function arguments");
        ObjectState *os = bindObjectInState(*init_state, arg, false);
        for (j=0; j<len+1; j++)
          os->write8(j, s[j]);

        // Write pointer to newly allocated and initialised argv/envp c-string
        argvOS->write(i * NumPtrBytes, arg->getBaseExpr());
      }
    }
  }

  initializeGlobals(*init_state);
}

void InceptionExecutor::start_analysis() {
  processTree = new PTree(init_state);
  init_state->ptreeNode = processTree->root;
  run(*init_state);
  delete processTree;
  processTree = 0;

  // hack to clear memory objects
  delete memory;
  memory = new MemoryManager(NULL);

  globalObjects.clear();
  globalAddresses.clear();

  if (statsTracker)
    statsTracker->done();
}


}
