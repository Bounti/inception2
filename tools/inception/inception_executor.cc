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

#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"

using namespace llvm;

namespace klee {

extern void *__dso_handle __attribute__ ((__weak__));

void irq_handler(device* io_irq, InceptionExecutor* executor) {

  while(1) {
    
    uint8_t buffer[8] = {0};
    uint32_t value=0;
    uint32_t error_code;

    io_irq->receive(buffer, 8);

    error_code |= buffer[0] << 24;
    error_code |= buffer[1] << 16;
    error_code |= buffer[2] << 8;
    error_code |= buffer[3];

    value |= buffer[4] << 24;
    value |= buffer[5] << 16;
    value |= buffer[6] << 8;
    value |= buffer[7];

    //printf("[Trace] Interrupt error_code : %08x\n", error_code); 

    if(value != 0) {
      executor->push_irq(value); 
      printf("[Trace] Interrupt ID : %08x\n", value); 
    }
  }
}


object::SymbolRef InceptionExecutor::resolve_elf_symbol_by_name(std::string expected_name, bool *success) {
  uint64_t addr, size;
  StringRef name;
  std::error_code ec;

  for (object::symbol_iterator I = elf->symbols().begin(),
                               E = elf->symbols().end();
       I != E; ++I) {

    if ((ec = I->getName(name))) {
      klee_warning("error while reading ELF symbol  %s", ec.message().c_str());
      continue;
    }

    if( name.equals(expected_name) ) {
      *success = true;
      return *I;
    }

    //addCustomObject(name, addr, size, false, false, false, false);
  }
  *success = false;
  return object::SymbolRef();
}

object::SectionRef InceptionExecutor::resolve_elf_section_by_name(std::string expected_name, bool *success) {
  StringRef name;
  std::error_code ec;

  for (object::section_iterator I = elf->sections().begin(),
                                E = elf->sections().end();
       I != E; ++I) {

    if ((ec = I->getName(name))) {
      klee_warning("error while reading ELF symbol  %s", ec.message().c_str());
      continue;
    }

    if( name.equals(expected_name) ) {
      *success = true;
      return *I;
    }

    //addCustomObject(name, addr, size, false, false, false, false);
  }
  *success = false;
  return object::SectionRef();
}


MemoryObject* InceptionExecutor::addCustomObject(std::string name, std::uint64_t addr, unsigned size,
                                           bool isReadOnly, bool isSymbolic,
                                           bool isRandomized, bool isForwarded, const llvm::Value* allocSite) {

  klee_message("adding custom object at %08x with size %08x with name %s - conf [ReadOnly;Symbolic;Randomized;Forwarded] %c|%c|%c|%c", addr, size, name.c_str(), isReadOnly ? 'Y':'N', isSymbolic ? 'Y':'N', isRandomized ? 'Y':'N', isForwarded ? 'Y':'N');

  auto mo = memory->allocateFixed(addr, size, allocSite);

  mo->setName(name);
  mo->isUserSpecified = true;
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
  else if( isForwarded ) {
    if( io == NULL )
      klee_error("unsupported forwarding strategy when no debugger are attached (--has_debugger)");
    
    os->initializeToZero();
    forwarded_mem.insert(addr); 
  }
  else
    os->initializeToZero();

  return mo;
}

/*
 * Overwrite load, store, call and ret 
 * 'load' and 'store' has to call our own executeMemoryOperation so that wa can catch forwarded requests
 * 'call' has a custom logic to support functions pointer. This is part of the unified memory
 * 'ret' has to check if we are returning from an interrupt handler, if it is the case  
*/
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
    case Instruction::Invoke:
    case Instruction::Call: {
      // Ignore debug intrinsic calls
      if (isa<DbgInfoIntrinsic>(i))
        break;
      CallSite cs(i);

      unsigned numArgs = cs.arg_size();
      Value *fp = cs.getCalledValue();
      Function *f = getTargetFunction(fp, state);

      // Skip debug intrinsics, we can't evaluate their metadata arguments.
      if (isa<DbgInfoIntrinsic>(i))
        break;

      if (isa<InlineAsm>(fp)) {
        terminateStateOnExecError(state, "inline assembly is unsupported");
        break;
      }
      // evaluate arguments
      std::vector< ref<Expr> > arguments;
      arguments.reserve(numArgs);

      for (unsigned j=0; j<numArgs; ++j)
        arguments.push_back(eval(ki, j+1, state).value);

      if (f) {
        const FunctionType *fType =
          dyn_cast<FunctionType>(cast<PointerType>(f->getType())->getElementType());
        const FunctionType *fpType =
          dyn_cast<FunctionType>(cast<PointerType>(fp->getType())->getElementType());

        // special case the call with a bitcast case
        if (fType != fpType) {
          assert(fType && fpType && "unable to get function type");

          // XXX check result coercion

          // XXX this really needs thought and validation
          unsigned i=0;
          for (std::vector< ref<Expr> >::iterator
                 ai = arguments.begin(), ie = arguments.end();
               ai != ie; ++ai) {
            Expr::Width to, from = (*ai)->getWidth();

            if (i<fType->getNumParams()) {
              to = getWidthForLLVMType(fType->getParamType(i));

              if (from != to) {
                // XXX need to check other param attrs ?
  #if LLVM_VERSION_CODE >= LLVM_VERSION(5, 0)
                bool isSExt = cs.paramHasAttr(i, llvm::Attribute::SExt);
  #else
                bool isSExt = cs.paramHasAttr(i+1, llvm::Attribute::SExt);
  #endif
                if (isSExt) {
                  arguments[i] = SExtExpr::create(arguments[i], to);
                } else {
                  arguments[i] = ZExtExpr::create(arguments[i], to);
                }
              }
            }

            i++;
          }
        }

        executeCall(state, ki, f, arguments);
      } else {
        ref<Expr> v = eval(ki, 0, state).value;

        ExecutionState *free = &state;
        bool hasInvalid = false, first = true;

        /* XXX This is wasteful, no need to do a full evaluate since we
           have already got a value. But in the end the caches should
           handle it for us, albeit with some overhead. */
        do {
          v = optimizer.optimizeExpr(v, true);
          ref<ConstantExpr> value;
          bool success = solver->getValue(*free, v, value);
          assert(success && "FIXME: Unhandled solver failure");
          (void) success;
          StatePair res = fork(*free, EqExpr::create(v, value), true);
          if (res.first) {
            uint64_t addr = value->getZExtValue();
            std::map<uint64_t, Function *>::iterator seek = inceptionLegalFunctions.find(addr);
            if (seek != inceptionLegalFunctions.end()) {
              f = seek->second;
//            if (legalFunctions.count(addr)) {
              //f = (Function*) addr;
              
              // Don't give warning on unique resolution
              if (res.second || !first)
                klee_warning_once(reinterpret_cast<void*>(addr),
                                  "resolved symbolic function pointer to: %s",
                                  f->getName().data());

              executeCall(*res.first, ki, f, arguments);
            } else {
              if (!hasInvalid) {
                terminateStateOnExecError(state, "invalid function pointer");
                hasInvalid = true;
              }
            }
          }

          first = false;
          free = res.second;
        } while (free);
      }
      break;
    }
  case Instruction::Ret: {
    ReturnInst *ri = cast<ReturnInst>(i);
    KInstIterator kcaller = state.stack.back().caller;
    Instruction *caller = kcaller ? kcaller->inst : 0;
    bool isVoidReturn = (ri->getNumOperands() == 0);
    ref<Expr> result = ConstantExpr::alloc(0, Expr::Bool);

    bool interrupted = false;
    if( interrupted_states.count(&state) != 0 ) {

      std::map<ExecutionState*,Function*>::iterator it;
      it = interrupted_states.find(&state);
      if(it != interrupted_states.end() && it->second == caller->getParent()->getParent()) {
        interrupted_states.erase(it);
        interrupted = true;
      }
    }


    if (!isVoidReturn) {
      result = eval(ki, 0, state).value;
    }
    
    if (state.stack.size() <= 1) {
      assert(!caller && "caller set on initial stack frame");
      terminateStateOnExit(state);
    } else {
      state.popFrame();

      if (statsTracker)
        statsTracker->framePopped(state);

      if (InvokeInst *ii = dyn_cast<InvokeInst>(caller)) {
        transferToBasicBlock(ii->getNormalDest(), caller->getParent(), state);
      } else {
        state.pc = kcaller;
        if(!interrupted)
          ++state.pc;
      }

      if (!isVoidReturn) {
        Type *t = caller->getType();
        if (t != Type::getVoidTy(i->getContext())) {
          // may need to do coercion due to bitcasts
          Expr::Width from = result->getWidth();
          Expr::Width to = getWidthForLLVMType(t);
            
          if (from != to) {
            CallSite cs = (isa<InvokeInst>(caller) ? CallSite(cast<InvokeInst>(caller)) : 
                           CallSite(cast<CallInst>(caller)));

            // XXX need to check other param attrs ?
#if LLVM_VERSION_CODE >= LLVM_VERSION(5, 0)
            bool isSExt = cs.hasRetAttr(llvm::Attribute::SExt);
#else
            bool isSExt = cs.paramHasAttr(0, llvm::Attribute::SExt);
#endif
            if (isSExt) {
              result = SExtExpr::create(result, to);
            } else {
              result = ZExtExpr::create(result, to);
            }
          }

          bindLocal(kcaller, state, result);
        }
      } else {
        // We check that the return value has no users instead of
        // checking the type, since C defaults to returning int for
        // undeclared functions.
        if (!caller->use_empty() && !interrupted) {
          terminateStateOnExecError(state, "return void when caller expected a result");
        }

      }
    }      
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

    uint64_t device_address, device_size;

    // If the symbol has external weak linkage then it is implicitly
    // not defined in this module; if it isn't resolvable then it
    // should be null.
    if (f->hasExternalWeakLinkage() &&
        !externalDispatcher->resolveSymbol(f->getName())) {
      addr = Expr::createPointer(0);
    } else {
      //addr = Expr::createPointer(reinterpret_cast<std::uint64_t>(f));
      //legalFunctions.insert(reinterpret_cast<std::uint64_t>(f));
      std::error_code ec;

      bool success = false;
      auto symbol = resolve_elf_symbol_by_name(f->getName(), &success);


      if(success) {
        if ((ec = symbol.getAddress(device_address))) {
          klee_warning("error while reading ELF symbol  %s", ec.message().c_str());
        } else {
          success = true;
          klee_message("mapping function %s to device address %016lx", f->getName().str().c_str(), device_address);
        } 
      } else {
        device_address = reinterpret_cast<std::uint64_t>(f); 
      }

      // Create a 32bits pointer
      addr = Expr::createPointer((unsigned long)device_address);
      inceptionLegalFunctions.insert(std::make_pair(device_address, f));
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
      MemoryObject* mo;

      //XXX: Inception Unified Memory
      // When symbols are available, we force the allocation of globals to device address
      std::error_code ec;
      bool success = false;
      auto symbol = resolve_elf_symbol_by_name(v->getName(), &success);
      uint64_t device_address;

      if(success) {
        if ((ec = symbol.getAddress(device_address))) {
          klee_warning("error while reading ELF symbol  %s", ec.message().c_str());
        } else {
          success = true;
          klee_message("mapping object %s to device address %016lx", v->getName().str().c_str(), device_address);
        } 
      }

      if( success ){
        mo = addCustomObject(v->getName(), device_address, size,
                                           /*isReadOnly*/false, /*isSymbolic*/false,
                                           /*isRandomized*/false, /*isForwarded*/false, v);
      } else {
        mo = memory->allocate(size, /*isLocal=*/false,
                                          /*isGlobal=*/true, /*allocSite=*/v,
                                          /*alignment=*/globalObjectAlignment);
        klee_message("object %s to address %016lx", v->getName().str().c_str(), mo->address);

      } 

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

          if( forwarded_mem.count(mo->address) > 0 ) {

            io->write(address, value, type); 
          } 
        }
      } else {

        if( forwarded_mem.count(mo->address) > 0 ) {
          ref<Expr> result = io->read(address, type);

          bindLocal(target, state, result);
        } else {
          ref<Expr> result = os->read(offset, type);

          if (interpreterOpts.MakeConcreteSymbolic)
            result = replaceReadWithSymbolic(state, result);
          
          bindLocal(target, state, result);
        } 

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
          if( forwarded_mem.count(mo->address) > 0 ) {

            io->write(address, value, type); 
          } 
        }
      } else {

        if( forwarded_mem.count(mo->address) > 0 ) {
          ref<Expr> result = io->read(address, type);

          bindLocal(target, state, result);
        } else {
          ref<Expr> result = os->read(mo->getOffsetExpr(address), type);
          bindLocal(target, *bound, result);
        }
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

void InceptionExecutor::serve_pending_interrupt(ExecutionState* current) {
  // Return immediately if we do not have to serve interrupts (if any of the
  // following conditions is true. The order is chose for efficiency
  if (pending_interrupts.empty()) // no interrupt is pending
    return;

  Function* caller = current->pc->inst->getParent()->getParent();

  interrupted_states.insert(std::pair<ExecutionState*, Function*>(current, caller)); 
  
  // return if the caller is one klee or inception function that should be
  // atomic
  if (caller->getName().find("klee_") != std::string::npos ||
      caller->getName().find("inception_") != std::string::npos)
    return;

  // get the pending interrupt
  uint32_t current_interrupt = pending_interrupts.top();
  pending_interrupts.pop();

  klee_message("[InterruptController] Suspending %s to execute "
               "inception_interrupt_handler",
               caller->getName().str().c_str());

  Function *f_interrupt = kmodule->module->getFunction("inception_interrupt_handler");

  KFunction *kf = kmodule->functionMap[f_interrupt];

  // push a stack frame, saying that the caller is current->pc, see IMPORTANT
  // NOTE for the reason
  current->pushFrame(current->pc, kf);

  // the generic handler takes as parameter the address of the interrupt
  // vector location in which to look for the handler address
 {
    // the generic handler takes as parameter the address of the interrupt
    // vector location in which to look for the handler address
    uint32_t vector_address = 0x10000000 + (current_interrupt << 2);

    klee::ref<klee::Expr> Vector_address =
        klee::ConstantExpr::create(vector_address, Expr::Int32);
    klee::ref<klee::Expr> Handler_address = readAt(*current, Vector_address);

    klee::ConstantExpr *handler_address_ce =
        dyn_cast<klee::ConstantExpr>(Handler_address);
    uint32_t handler_address = handler_address_ce->getZExtValue();

    klee_message("resolving handler address: vector(%p) = %p", vector_address,
                 handler_address);

    Cell &argumentCell = current->stack.back().locals[kf->getArgRegister(0)];
    argumentCell.value = Handler_address;
  }


  // finally "call" the handler by setting the pc to point to it
  current->pc = kf->instructions;
}

 ref<Expr> InceptionExecutor::readAt(ExecutionState &state, ref<Expr> address) const {
 
   ObjectPair op;
   bool success;
 
   solver->setTimeout(coreSolverTimeout);
 
   state.addressSpace.resolveOne(state, solver, address, op, success);
 
   if (success) {
 
     const MemoryObject *mo = op.first;
 
     ref<Expr> addr = mo->getOffsetExpr(address);
 
     const ObjectState *os = state.addressSpace.findObject(mo);
     assert(os);
 
     ref<Expr> result = os->read(addr, Expr::Int32);
  
     return result;
   } else
     return klee::ConstantExpr::create(-1, Expr::Int32);
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

  instructions_counter = 0;

  while (!states.empty() && !haltExecution) {
    ExecutionState &state = searcher->selectState();

    if( instructions_counter > min_irq_threshold && interrupted_states.count(&state) == 0 ) {
      for (std::map<uint32_t,uint32_t>::iterator it=irq_model.begin(); it!=irq_model.end(); ++it) {

        if((instructions_counter % it->second) == 0) {
          // We use the interrupt stack to keep compatibility with real device interrupt controller
          push_irq(it->first);
          serve_pending_interrupt(&state);
        } 
      }
          
    }
    KInstruction *ki = state.pc;
    stepInstruction(state);

    executeInstruction(state, ki);
    //processTimers(&state, maxInstructionTime);

    checkMemoryUsage();

    updateStates(&state);
    instructions_counter++;
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
