#include "inception_executor.hpp"

#include "ExecutionState.h"
#include "klee/Expr/Expr.h"
#include "../lib/Core/Executor.h"

#include "Context.h"
#include "CoreStats.h"
// #include "ExecutorTimerInfo.h"
#include "ExternalDispatcher.h"
#include "ImpliedValue.h"
#include "Memory.h"
#include "MemoryManager.h"
#include "PTree.h"
#include "Searcher.h"
#include "SeedInfo.h"
#include "SpecialFunctionHandler.h"
#include "StatsTracker.h"
#include "TimingSolver.h"
#include "UserSearcher.h"

#include "klee/ADT/TreeStream.h"
#include "klee/Config/Version.h"
#include "klee/Core/Interpreter.h"
#include "klee/Expr/Expr.h"
#include "klee/ADT/KTest.h"
#include "klee/Support/OptionCategories.h"
#include "klee/Statistics/Statistics.h"
#include "klee/Solver/SolverCmdLine.h"
#include "klee/Support/Debug.h"
#include "klee/Support/ErrorHandling.h"
#include "klee/Support/FileHandling.h"
#include "klee/Support/ModuleUtil.h"
#include "klee/Support/PrintVersion.h"
#include "klee/System/Time.h"

#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"

using namespace llvm;

namespace klee {

extern void *__dso_handle __attribute__ ((__weak__));

object::SymbolRef InceptionExecutor::resolve_elf_symbol_by_name(std::string expected_name, bool *success) {
  std::error_code ec;

  for (object::symbol_iterator I = elf->symbols().begin(),
                               E = elf->symbols().end();
       I != E; ++I) {

    Expected<StringRef> symbol = I->getName();
    
    if ( symbol ) {
      klee_warning("error while reading ELF symbol  %s", expected_name.c_str());
      continue;
    }

    auto name = symbol.get();
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

  for (object::section_iterator I = elf->sections().begin(),
                                E = elf->sections().end();
       I != E; ++I) {
  
    Expected<StringRef> section = I->getName();
    
    if ( section ) {
      klee_warning("error while reading ELF symbol  %s", expected_name.c_str());
      continue;
    }

    auto name = section.get();
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
                                           bool isRandomized, bool isForwarded, std::string target_name, const llvm::Value* allocSite) {

  klee_message("adding custom object at %16x with size %16x with name %s - conf [ReadOnly;Symbolic;Randomized;Forwarded] %c|%c|%c|%c", addr, size, name.c_str(), isReadOnly ? 'Y':'N', isSymbolic ? 'Y':'N', isRandomized ? 'Y':'N', isForwarded ? 'Y':'N');

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

    os->initializeToZero();

    Target* target = resolve_target(target_name);
    if( target == NULL ) {
      klee_error("Configuration missmatch: unknown target %s ", target_name.c_str());
    }

    forwarded_mem.insert(std::pair<uint64_t, Target*>(addr, target));
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

#if LLVM_VERSION_CODE >= LLVM_VERSION(8, 0)
    const CallBase &cs = cast<CallBase>(*i);
    Value *fp = cs.getCalledOperand();
#else
    const CallSite cs(i);
    Value *fp = cs.getCalledValue();
#endif

    unsigned numArgs = cs.arg_size();
    Function *f = getTargetFunction(fp, state);

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
        bool success =
            solver->getValue(free->constraints, v, value, free->queryMetaData);
        assert(success && "FIXME: Unhandled solver failure");
        (void) success;
        StatePair res = fork(*free, EqExpr::create(v, value), true);
        if (res.first) {
          uint64_t addr = value->getZExtValue();
          std::map<uint64_t, Function *>::iterator seek = inceptionLegalFunctions.find(addr);
          if (seek != inceptionLegalFunctions.end()) {
          // if (legalFunctions.count(addr)) {
            // f = (Function*) addr;
            f = seek->second;

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
    std::map<ExecutionState*,Function*>::iterator it;
    it = interrupted_states.find(&state);
    if(it != interrupted_states.end() && it->second == caller->getParent()->getParent()) {
      interrupted_states.erase(it);
      interrupted = true;

      Target* target = get_active_target();
      target->irq_ack();
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
        ++state.pc;
      }

      if (ri->getFunction()->getName() == "_klee_eh_cxx_personality") {
        assert(dyn_cast<ConstantExpr>(result) &&
               "result from personality fn must be a concrete value");

        auto *sui = dyn_cast_or_null<SearchPhaseUnwindingInformation>(
            state.unwindingInformation.get());
        assert(sui && "return from personality function outside of "
                      "search phase unwinding");

        // unbind the MO we used to pass the serialized landingpad
        state.addressSpace.unbindObject(sui->serializedLandingpad);
        sui->serializedLandingpad = nullptr;

        if (result->isZero()) {
          // this lpi doesn't handle the exception, continue the search
          unwindToNextLandingpad(state);
        } else {
          // a clause (or a catch-all clause or filter clause) matches:
          // remember the stack index and switch to cleanup phase
          state.unwindingInformation =
              std::make_unique<CleanupPhaseUnwindingInformation>(
                  sui->exceptionObject, cast<ConstantExpr>(result),
                  sui->unwindingProgress);
          // this pointer is now invalidated
          sui = nullptr;
          // continue the unwinding process (which will now start with the
          // cleanup phase)
          unwindToNextLandingpad(state);
        }

        // never return normally from the personality fn
        break;
      }

      if (!isVoidReturn) {
        Type *t = caller->getType();
        if (t != Type::getVoidTy(i->getContext())) {
          // may need to do coercion due to bitcasts
          Expr::Width from = result->getWidth();
          Expr::Width to = getWidthForLLVMType(t);
            
          if (from != to) {
#if LLVM_VERSION_CODE >= LLVM_VERSION(8, 0)
            const CallBase &cs = cast<CallBase>(*caller);
#else
            const CallSite cs(isa<InvokeInst>(caller)
                                  ? CallSite(cast<InvokeInst>(caller))
                                  : CallSite(cast<CallInst>(caller)));
#endif

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
        if (!caller->use_empty()) {
          terminateStateOnExecError(state, "return void when caller expected a result");
        }
      }
    }      
    break;
  }
  case Instruction::Br: {
    BranchInst *bi = cast<BranchInst>(i);
    if (bi->isUnconditional()) {
      transferToBasicBlock(bi->getSuccessor(0), bi->getParent(), state);
    } else {
      // FIXME: Find a way that we don't have this hidden dependency.
      assert(bi->getCondition() == bi->getOperand(0) &&
             "Wrong operand index!");
      ref<Expr> cond = eval(ki, 0, state).value;

      cond = optimizer.optimizeExpr(cond, false);
      Executor::StatePair branches = fork(state, cond, false);

      //XXX: create hardware snapshot for the new states
      if( !(branches.first == 0 || branches.second == 0) )
        klee_message("forking execution state %p and %p", branches.first, branches.second);

      // NOTE: There is a hidden dependency here, markBranchVisited
      // requires that we still be in the context of the branch
      // instruction (it reuses its statistic id). Should be cleaned
      // up with convenient instruction specific data.
      if (statsTracker && state.stack.back().kf->trackCoverage)
        statsTracker->markBranchVisited(branches.first, branches.second);
      
      // we need to restore the current hw state
      Target* target = get_active_target();

      if (branches.first) {
        if( update_hw_state(branches.first) )
          target->restore(get_state_id(&state));
        transferToBasicBlock(bi->getSuccessor(0), bi->getParent(), *branches.first); 
      }
      if (branches.second) {
        if( update_hw_state(branches.second) )
          target->restore(get_state_id(&state));
        transferToBasicBlock(bi->getSuccessor(1), bi->getParent(), *branches.second); 
      }

    }
    break;
  }  
  default:
     Executor::executeInstruction(state, ki);
    break;
  }
}

bool InceptionExecutor::update_hw_state(ExecutionState* state) {

  uint64_t hw_id = 0;
  
  Target* target = get_active_target();

  std::map<ExecutionState*, uint32_t>::iterator it;
 
  if(state == NULL)
    return false;

  it = sw_to_hw.find(state);
  if(it == sw_to_hw.end()) {
    klee_message("    creating new hw state for sw state %p", state);
    // First time we create a snapshot for this state
    hw_id = target->save();
    sw_to_hw.insert(std::pair<ExecutionState*, uint32_t>(state, hw_id)); 
    return true;
  } else if( it->second == 0) {
    klee_message("    updating existing hw state for sw state %p", state);
    hw_id = target->save();
    it->second = hw_id;
    return true;
  }
  return false;
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
    
    klee_warning("%s", f->getName().str().c_str());

    // If the symbol has external weak linkage then it is implicitly
    // not defined in this module; if it isn't resolvable then it
    // should be null.
    if (f->hasExternalWeakLinkage() &&
        !externalDispatcher->resolveSymbol(f->getName())) {
      addr = Expr::createPointer(0);
      klee_warning("%s is an external function", f->getName().str().c_str());
    } else {
      //addr = Expr::createPointer(reinterpret_cast<std::uint64_t>(f));
      //legalFunctions.insert(reinterpret_cast<std::uint64_t>(f));
      std::error_code ec;

      bool success = false;
      auto symbol = resolve_elf_symbol_by_name(f->getName(), &success);

      auto symbol_address = symbol.getAddress();
      if(success) {
        device_address = symbol_address.get();
        success = true;
        klee_message("mapping function %s to device address %016lx", f->getName().str().c_str(), device_address);
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
      
      auto symbol_address = symbol.getAddress();
      if(success) {
        device_address = symbol_address.get();
        success = true;
        klee_message("mapping object %s to device address %016lx", v->getName().str().c_str(), device_address);
        mo = addCustomObject(v->getName(), device_address, size,
                                           /*isReadOnly*/false, /*isSymbolic*/false,
                                           /*isRandomized*/false, /*isForwarded*/false, "", v);
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

  // if (SimplifySymIndices) {
    // if (!isa<ConstantExpr>(address))
      // address = ConstraintManager::simplifyExpr(state.constraints, address);
    // if (isWrite && !isa<ConstantExpr>(value))
      // value = ConstraintManager::simplifyExpr(state.constraints, value);
  // }

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
    bool success = solver->mustBeTrue(state.constraints, check, inBounds,
                                      state.queryMetaData);
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


          std::map<uint64_t, Target*>::iterator it;

          it = forwarded_mem.find(mo->address);
          if (it != forwarded_mem.end()) {
            Target* device = it->second;

            device->write(address, value, type);
          }
        }
      } else {

        std::map<uint64_t, Target*>::iterator it;

        it = forwarded_mem.find(mo->address);
        if (it != forwarded_mem.end()) {
          Target* device = it->second;

          ref<Expr> result = device->read(address, type);

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
          
          std::map<uint64_t, Target*>::iterator it;

          it = forwarded_mem.find(mo->address);
          if (it != forwarded_mem.end()) {
            Target* device = it->second;

            device->write(address, value, type);
          }
        }
      } else {

        std::map<uint64_t, Target*>::iterator it;

        it = forwarded_mem.find(mo->address);
        if (it != forwarded_mem.end()) {
          Target* device = it->second;

          ref<Expr> result = device->read(address, type);

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

void InceptionExecutor::serve_pending_interrupt(ExecutionState* current, uint32_t active_irq) {

  Function* caller = current->pc->inst->getParent()->getParent();

  // return if the caller is one klee or inception function that should be
  // atomic
  if (caller->getName().find("klee_") != std::string::npos ||
      caller->getName().find("inception_") != std::string::npos)
    return;

  interrupted_states.insert(std::pair<ExecutionState*, Function*>(current, caller));

  klee_message("[InterruptController] Suspending %s to execute "
               "inception_interrupt_handler",
               caller->getName().str().c_str());

  Function *f_interrupt = kmodule->module->getFunction("inception_interrupt_handler");

  KFunction *kf = kmodule->functionMap[f_interrupt];

  // push a stack frame, saying that the caller is current->pc, see IMPORTANT
  // NOTE for the reason
  current->pushFrame(current->pc, kf);

  if (statsTracker)
    statsTracker->framePushed(*current, &current->stack[current->stack.size()-2]);

  // the generic handler takes as parameter the address of the interrupt
  // vector location in which to look for the handler address
 {
    // the generic handler takes as parameter the address of the interrupt
    // vector location in which to look for the handler address
    //TODO: avoid hardwire
    uint32_t vector_address = 0x100000 + (active_irq << 2);

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
 * Brief: this function sanitize the hw state so that it follows sw execution.
 * Each time the state heuristic select a different execution path, this save
 * and restore hw state.
 */
void InceptionExecutor::sanitize_hw_state(ExecutionState* current_state, ExecutionState* new_state) {

  Target* target = get_active_target();

  uint64_t current_hw_id = 0;
  uint64_t new_hw_id    = 0;

  std::map<ExecutionState*, uint32_t>::iterator it_old;
  std::map<ExecutionState*, uint32_t>::iterator it_new;
  
  it_old = sw_to_hw.find(current_state);
  if(it_old != sw_to_hw.end())
    current_hw_id = it_old->second;
 
  it_new = sw_to_hw.find(new_state);
  if(it_new != sw_to_hw.end())
    new_hw_id = it_new->second; 

  if(current_state == NULL)
    current_state = new_state;

  // We are moving to a different path
  if (new_state != current_state) {
    klee_message("Switching sw state from %p [%d] to %p [%d]", current_state, current_hw_id, new_state, new_hw_id);

    // do we have a hw snapshot associated to the old path ? 
    if ( current_hw_id != 0) {
      //klee_message("    previous state has already a hw snp on storage, updating...");
      current_hw_id = target->save(current_hw_id);
      it_old->second = current_hw_id; 
    } else {
      //klee_message("    previous state has no hw snp on storage...");
      current_hw_id = target->save();
      sw_to_hw.insert(std::pair<ExecutionState*, uint64_t>(current_state, current_hw_id));
    }

    if(new_hw_id != 0) {
      //klee_message("    restoring hw snp for state %p with id %p", new_state, new_hw_id);
      target->restore(new_hw_id);
    } else {
      //klee_error("    no hw snp on storage for %p, using running design", new_state);
    }
  }
}

/*
 * Overriding the run method, enables Inception to force the execution of interrupt when one is pending.
 * Futermore, it enables overriding subsequent methods such as executeMemoryOperation
*/
void InceptionExecutor::run(ExecutionState &initialState) {
  bindModuleConstants();

  // Delay init till now so that ticks don't accrue during optimization and such.
  timers.reset();

  states.insert(&initialState);

  searcher = constructUserSearcher(*this);

  std::vector<ExecutionState *> newStates(states.begin(), states.end());
  searcher->update(0, newStates, std::vector<ExecutionState *>());

  ExecutionState* state = NULL;

  Target* target = get_active_target();
  instructions_counter = 0;
  
  while (!states.empty() && !haltExecution) {
    uint32_t irq_id = 0;

    bool active_interrupt = false;

    //if( instructions_counter > 100 && target->has_pending_irq() ) {
    if((interrupted_states.count(state) == 0) && target->has_pending_irq(get_state_id(state)) ) {
      irq_id = target->get_active_irq(get_state_id(state));
      active_interrupt = true;

      if( irq_id != 0 ) {
        klee_warning("pending irq 0x%08x", irq_id);
        serve_pending_interrupt(state, irq_id);
      }
    }

    if ( is_state_heuristic_enabled && ((state == NULL) || (active_interrupt == false)) ) {
      ExecutionState* new_state = &(searcher->selectState());
      if(state != new_state)
        klee_warning("current state is %p with id %d", new_state, get_state_id(new_state));

      sanitize_hw_state(state, new_state);
      state = new_state;
      
    }
 
    KInstruction *ki = state->pc;
    stepInstruction(*state);

    executeInstruction(*state, ki);
    //processTimers(&state, maxInstructionTime);

    checkMemoryUsage();

    updateStates(state);
    instructions_counter++;
  }

  //while (!states.empty() && !haltExecution) {
  //  ExecutionState &state = searcher->selectState();

  //  std::vector<Target*>::iterator it;
  //  for (it = targets.begin() ; it != targets.end(); ++it) {
  //    Target* target = *it;
  //    if( target->has_pending_irq() ) {
  //      uint32_t irq_id = target->get_active_irq();

  //      if( irq_id != -1 ) {
  //        push_irq(irq_id);
  //      }
  //    }
  //  }

  //  sanitize_hw_state(&state);

  //  if( interrupted_states.count(&state) == 0 ) {
  //    serve_pending_interrupt(&state);
  //  }

  //  KInstruction *ki = state.pc;
  //  stepInstruction(state);

  //  executeInstruction(state, ki);
  //  //processTimers(&state, maxInstructionTime);

  //  checkMemoryUsage();

  //  updateStates(&state);
  //  instructions_counter++;
  //}

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
}

void InceptionExecutor::start_analysis() {
 
  initializeGlobals(*init_state);

  processTree = std::make_unique<PTree>(init_state);
  run(*init_state);
  processTree = nullptr;

  // hack to clear memory objects
  delete memory;
  memory = new MemoryManager(NULL);

  globalObjects.clear();
  globalAddresses.clear();

  if (statsTracker)
    statsTracker->done();
}

}


