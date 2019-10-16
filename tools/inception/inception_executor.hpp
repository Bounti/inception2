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

#include <string>
#include <vector>
#include <set>
#include <thread>
#include <map>

using namespace llvm;

namespace klee {

extern bool irq_running;

class InceptionExecutor;

void irq_handler(device* io_irq, InceptionExecutor* executor);

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

  Target* io;

  device* io_irq;

  std::stack<uint32_t> pending_interrupts;

  std::map<ExecutionState*, Function*> interrupted_states;

  void serve_pending_interrupt(ExecutionState* state);

  ref<Expr> readAt(ExecutionState &state, ref<Expr> address) const;

  uint64_t min_irq_threshold;
  
  uint64_t instructions_counter;

  std::map<uint32_t, uint32_t> irq_model;
 
  std::thread* irq_handler_thread;

  public:
 
  void shutdown() {
    irq_running = false;
    while(irq_running == false);
  }

  void set_min_irq_threshold(uint64_t _min_irq_threshold) {
    min_irq_threshold = _min_irq_threshold; 
  }

  void push_irq(uint32_t id) {
    pending_interrupts.push(id);
  }

  void add_irq_to_model(uint32_t irq_id, uint32_t frequency) {
    irq_model.insert(std::pair<uint32_t, uint32_t>(irq_id, frequency));
  }

  void add_target(Target* io_device, device* irq_device){
    io     = io_device;
    io_irq = irq_device;

    irq_running = true;
    irq_handler_thread = new std::thread(irq_handler, io_irq, this);
    irq_handler_thread->detach();

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
    io_irq = NULL;
    min_irq_threshold = 0;
    irq_running = false;
  };

	void executeMemoryOperation(ExecutionState &state,
                                      bool isWrite,
                                      ref<Expr> address,
                                      ref<Expr> value /* undef if read */,
                                      KInstruction *target /* undef if write */);
};
}
#endif
