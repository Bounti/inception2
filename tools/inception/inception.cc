#include "inception.hpp"

#include "llvm/IR/IRBuilder.h"

#include <iostream>
#include <string>

#include "inception/CodeInv/Decompiler.h"
#include "inception/CodeInv/Disassembler.h"
#include "passes/ir_merger.h"

#include "utils/collision_solver.h"
#include "helper_functions/functions_helper_writer.h"
#include "utils/interrupt_support.h"
#include "utils/sections_writer.h"
#include "utils/stack_allocator.h"

#include "inception/Transforms/BreakConstantGEP.h"
#include "inception/Transforms/BreakConstantPtrToInt.h"
#include "inception/Utils/Builder.h"
#include "klee/Internal/Support/ErrorHandling.h"

using namespace llvm;

// Load ELF binary
void Inception::load_elf_binary_from_file(const char* _elf_file_name) {

  // File should be stdin or it should exist.
  if (_elf_file_name != "-" && !sys::fs::exists(_elf_file_name)) {
    klee::klee_error("Unable to locate ELF file or directory : %s ", _elf_file_name);
  }

  ErrorOr<object::OwningBinary<object::Binary>> Binary =
      object::createBinary(_elf_file_name);
  if (std::error_code err = Binary.getError()) {
    klee::klee_error("Unknown binary file format : %s ", _elf_file_name);
  } else {
    if (Binary.get().getBinary()->isObject()) {
      std::pair<std::unique_ptr<object::Binary>, std::unique_ptr<MemoryBuffer>>
          res = Binary.get().takeBinary();
      ErrorOr<std::unique_ptr<object::ObjectFile>> ret =
          object::ObjectFile::createObjectFile(
              res.second.release()->getMemBufferRef());
      TempExecutable.swap(ret.get());
    }
  }
}

// Load IRQ Hooks Table from file
void Inception::load_irq_hook_table_from_file(const char* _irq_hook_itable_file_name) {

}

void Inception::load_llvm_bitcode_from_file(const char *_bc_file_name) {

  bc_file_name.assign(_bc_file_name);

  // Load the bytecode...
  std::string errorMsg;
  std::vector<std::unique_ptr<llvm::Module>> loadedModules;

  if (!klee::loadFile(bc_file_name, ctx, loadedModules, errorMsg)) {
    klee::klee_error("error loading program '%s': %s", bc_file_name,
               errorMsg.c_str());
  }

  // Load and link the whole files content. The assumption is that this is the
  // application under test.
  // Nothing gets removed in the first place.
  std::unique_ptr<llvm::Module> M(klee::linkModules(
      loadedModules, "" /* link all mainModules together */, errorMsg));
  if (!M) {
    klee::klee_error("error loading program '%s': %s", bc_file_name,
               errorMsg.c_str());
  }

  mainModule = M.release();

  // mainModule->print(llvm::errs(), nullptr);
};

void Inception::runPasses() {

  // The primary goal of this function is to replace LLVM functions containing ASM lines
  InitializeAllTargetInfos();
  InitializeAllTargetMCs();
  InitializeAllAsmParsers();
  InitializeAllDisassemblers();
  InitializeAllTargets();

  MCDirector *MCD = 0;
  Disassembler *DAS = 0;
  Decompiler *DEC = 0;

  // Initialize the Disassembler
  std::string FeaturesStr;
  SubtargetFeatures Features;
  FeaturesStr = Features.getString();

  Triple TT("thumbv7m-unknown-none-elf");

  mainModule->materializeAll();

  MCD = new MCDirector(TT.str(), "cortex-m3", FeaturesStr, TargetOptions(),
                       Reloc::DynamicNoPIC, CodeModel::Default,
                       CodeGenOpt::Default, outs(), errs());
  DAS = new Disassembler(MCD, TempExecutable.release(), NULL, outs(), outs());
  DEC = new Decompiler(DAS, mainModule, outs(), outs());

  if (!MCD->isValid()) {
    errs() << "Warning: Unable to initialized LLVM MC API!\n";
    return;
  }

  std::set<std::string> asm_functions;
  klee::klee_message("\n");

  klee::klee_message("Detecting all assembly functions ...");
  for (auto iter1 = mainModule->getFunctionList().begin();
       iter1 != mainModule->getFunctionList().end(); iter1++) {
    Function &old_function = *iter1;

    FunctionPassManager FPM(mainModule);
    FPM.add(llvm::createBreakConstantGEPPass());
    FPM.add(llvm::createBreakConstantPtrToIntPass());
    FPM.run(old_function);

    for (auto iter2 = old_function.getBasicBlockList().begin();
         iter2 != old_function.getBasicBlockList().end(); iter2++) {
      BasicBlock &old_bb = *iter2;
      for (auto iter3 = old_bb.begin(); iter3 != old_bb.end(); iter3++) {
        const CallInst *ci = dyn_cast<CallInst>(iter3);

        if (ci != NULL)
          if (isa<InlineAsm>(ci->getCalledValue())) {
            asm_functions.insert(old_function.getName().str());
          }
      }  // END FOR INSTRUCTIOn
    }    // END FOR BB
  }      // END FOR FCT
  klee::klee_message("Done -> %ld functions.\n", asm_functions.size());

  initAPI(mainModule, DEC);

  IRMerger *merger = new IRMerger(DEC);

  for (auto &str : asm_functions) {
    klee::klee_message("Processing function %s...", str.c_str());
    merger->Run(llvm::StringRef(str));
    klee::klee_message("Done\n");
  }
  klee::klee_message("Decompilation stage done\n");

  // Remove all
  asm_functions.clear();

  klee::klee_message("Checking functions dependencies");
  auto fct_begin = mainModule->getFunctionList().begin();
  auto fct_end = mainModule->getFunctionList().end();

  bool hasDependencies = false;
  do {
    for (; fct_begin != fct_end; fct_begin++) {
      Function &function = *fct_begin;

      if (function.hasFnAttribute("DecompileLater")) {
        hasDependencies = true;
        klee::klee_message("Processing function %s...",
                          function.getName().str().c_str());
        merger->Run(llvm::StringRef(function.getName().str()));
        klee::klee_message("Done\n");
      }
    }  // END FOR FCT
    hasDependencies = false;
  } while (hasDependencies);

  klee::klee_message("Allocating and initializing virtual stack...");
  StackAllocator::Allocate(mainModule, DAS);
  StackAllocator::InitSP(mainModule, DAS);
  klee::klee_message("Done\n");

  klee::klee_message("Importing sections ...");
  SectionsWriter::WriteSection(".heap", DAS, mainModule);
  SectionsWriter::WriteSection(".main_stack", DAS, mainModule);
  SectionsWriter::WriteSection(".isr_vector", DAS, mainModule);
  SectionsWriter::WriteSection(".interrupt_vector", DAS, mainModule);
  klee::klee_message("Done\n");

  klee::klee_message("Adding call to functions helper...");
  Function *main = mainModule->getFunction("main");
  FunctionsHelperWriter::Write(FHW_POSITION::NONE, WRITEBACK_SP, mainModule, main);
  FunctionsHelperWriter::Write(FHW_POSITION::NONE, CACHE_SP, mainModule, main);
  FunctionsHelperWriter::Write(FHW_POSITION::NONE, SWITCH_SP, mainModule, main);

  FunctionsHelperWriter::Write(FHW_POSITION::NONE, INTERRUPT_PROLOGUE, mainModule, main);
  FunctionsHelperWriter::Write(FHW_POSITION::NONE, INTERRUPT_EPILOGUE, mainModule, main);
  FunctionsHelperWriter::Write(FHW_POSITION::NONE, INTERRUPT_HANDLER, mainModule, main);
  FunctionsHelperWriter::Write(FHW_POSITION::NONE, ICP, mainModule, main);
  klee::klee_message("Done\n");
}

void Inception::run() {

  char **pEnvp = new char *[1];
  pEnvp[0] = NULL;

  char **pArgv = new char *[1];
  pArgv[0] = NULL;

  if( main_fct == NULL ) {
    // get entry point from ELF symbols table

    // otherwise get main
    main_fct = mainModule->getFunction("main");
  }

  interpreter->runFunctionAsMain(main_fct, 1, pArgv, pEnvp);
}
