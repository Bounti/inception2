#ifndef INCEPTION_EXECUTOR
#define INCEPTION_EXECUTOR

#include "klee/ExecutionState.h"
#include "klee/Interpreter.h"
#include "../lib/Core/Executor.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Object/ObjectFile.h"
#include "device/device.hpp"
#include "target/target.hpp"

#include "target/openocd/openocd.hpp"
#include "target/jlink/jlink.hpp"
#include "target/verilator/verilator.hpp"
#include "target/usb3dap/usb3dap.hpp"

#include <string>
#include <vector>
#include <set>
#include <thread>
#include <map>

using namespace llvm;

namespace klee {

class InceptionExecutor;

void irq_handler(device* io_irq, InceptionExecutor* executor);

class InceptionExecutor : public Executor{
  public:
  std::vector<Target*> targets;
  
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

  std::map<uint64_t, Target*> forwarded_mem;

  Target* io;

  device* io_irq;

  std::map<ExecutionState*, Function*> interrupted_states;
  
  std::map<ExecutionState*, uint32_t> sw_to_hw;

  void serve_pending_interrupt(ExecutionState* state, uint32_t active_irq);

  ref<Expr> readAt(ExecutionState &state, ref<Expr> address) const;

  uint64_t min_irq_threshold;

  uint64_t instructions_counter;

  std::map<uint32_t, uint32_t> irq_model;

  std::thread* irq_handler_thread;

  Target* resolve_target(std::string name) {

    std::vector<Target*>::iterator it;  
    
    for (it = targets.begin() ; it != targets.end(); ++it) {
      Target* target = *it;
      if( target->getName().compare(name) == 0)
        return target;
    }

    return NULL;
  }
 
  void sanitize_hw_state(ExecutionState* current_state, ExecutionState* new_state);

  bool update_hw_state(ExecutionState* state);

  Target* get_active_target() {
  
    std::vector<Target*>::iterator it;
    for (it = targets.begin() ; it != targets.end(); ++it) {
      Target* target = *it;
      if(target->is_active())
        return target;
    } 
    klee_error("not active target");
  }

  uint32_t get_state_id(ExecutionState* state) {
    if(state == NULL)
      return 0;

    std::map<ExecutionState*, uint32_t>::iterator it;
  
    it = sw_to_hw.find(state);
    if(it != sw_to_hw.end())
      return it->second;
    return 0;
  }

  public:
  void add_target(Target* target) {
    targets.push_back(target);
  }

  void shutdown() {
 
    std::vector<Target*>::iterator it;     
    for (it = targets.begin() ; it != targets.end(); ++it) {
      Target* target = *it;
      target->shutdown();
    }
  }

  void set_min_irq_threshold(uint64_t _min_irq_threshold) {
    min_irq_threshold = _min_irq_threshold; 
  }


  void add_irq_to_model(uint32_t irq_id, uint32_t frequency) {
    irq_model.insert(std::pair<uint32_t, uint32_t>(irq_id, frequency));
  }

  void set_elf(std::unique_ptr<object::ObjectFile>& _elf) {
    elf = std::move(_elf);
  }

  void allocate_device_memory();

  MemoryObject* addCustomObject(std::string name, std::uint64_t addr, unsigned size,
                        bool isReadOnly, bool isSymbolic,
                        bool isRandomized, bool isForwarded, std::string target="", const llvm::Value* allocSite = nullptr);

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
    io_irq = NULL;
    min_irq_threshold = 0;
    is_state_heuristic_enabled = true;
  };

	void executeMemoryOperation(ExecutionState &state,
                                      bool isWrite,
                                      ref<Expr> address,
                                      ref<Expr> value /* undef if read */,
                                      KInstruction *target /* undef if write */);
};
}
#endif
