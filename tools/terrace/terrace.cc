#include "terrace.hpp"

#include "llvm/IR/IRBuilder.h"

#include "proto/tbb.pb.h"
#include "proto/tbb_parser.hpp"
#include <iostream>
#include <string>

using namespace llvm;

void Terrace::load_llvm_bitcode_from_file(const char *_bc_file_name) {

  bc_file_name.assign(_bc_file_name);

  // Load the bytecode...
  std::string errorMsg;
  std::vector<std::unique_ptr<llvm::Module>> loadedModules;

  if (!klee::loadFile(bc_file_name, ctx, loadedModules, errorMsg)) {
    klee_error("error loading program '%s': %s", bc_file_name,
               errorMsg.c_str());
  }

  // Load and link the whole files content. The assumption is that this is the
  // application under test.
  // Nothing gets removed in the first place.
  std::unique_ptr<llvm::Module> M(klee::linkModules(
      loadedModules, "" /* link all modules together */, errorMsg));
  if (!M) {
    klee_error("error loading program '%s': %s", bc_file_name,
               errorMsg.c_str());
  }

  mainModule = M.release();

  // mainModule->print(llvm::errs(), nullptr);
};

/*
 * It creates a main function and the call tree with respect to the basic_blocks
 * traces we set in input.
 */
void Terrace::flat_control_flow() {

  FunctionType *fct_type = NULL;
  BasicBlock *main_bb = NULL;

  fct_type =
      FunctionType::get(Type::getPrimitiveType(ctx, Type::VoidTyID), false);

  // if main function exists do not overwrite it
  main_fct = mainModule->getFunction("main");
  if(main_fct != NULL)
    return;

  main_fct = cast<Function>(mainModule->getOrInsertFunction("main", fct_type));


  std::cout << "[INFO] Generating main function " << std::endl;

  main_bb = BasicBlock::Create(ctx, "entry_block", main_fct);

  IRBuilder<> *IRB = new IRBuilder<>(main_bb);

  // mainModule->print(llvm::errs(), nullptr);

  StructType *StructTy_struct_CPUARMState =
      mainModule->getTypeByName("struct.CPUARMState");

  AllocaInst *cpu_state_ptr =
      new AllocaInst(StructTy_struct_CPUARMState, 0, "", main_bb);

  TBBParser *tbb_parser = new TBBParser();

  while (tbb_parser->hasNext()) {

    const ::TBBBlock &bb = tbb_parser->getNext();

    Function *target_fct;
    // Resolve function by address
    if( &bb && bb.has_address() ) {

      std::stringstream stream;
      stream << "-" << std::hex << bb.address();

      std::string pattern = stream.str();

      // std::cout << "[INFO] Generating call for " << pattern << std::endl;

      for (auto be = mainModule->begin(); be != mainModule->end(); be++) {
        auto found = (*be).getName().find(pattern);

        if (found != std::string::npos) {
          target_fct = &(*be);

          unsigned int n = 0;
          if( bb.has_n() )
            n = bb.n();
          else
            n = 1;

          // std::cout << "    Repeated " << n << std::endl;

          for (int i = 0; i < n; i++) {
            CallInst *call =
                CallInst::Create(target_fct, cpu_state_ptr, "", main_bb);

            call->setCallingConv(CallingConv::C);
            call->setTailCall(false);
          }
          break;
        }
      }
    } else {
      std::cout << "[ERROR] element tbb has no address field..." << std::endl;
    }
  }
  IRB->CreateRetVoid();

  std::cout << "[INFO] Done " << std::endl;

  // main_fct->print(llvm::errs(), nullptr);
}

void Terrace::runPasses() {
  // LegacyLLVMPassManagerTy pm; -> Klee LLVM Pass manager supports ModulePass
  // Create a function pass manager.
  auto FPM = llvm::make_unique<legacy::FunctionPassManager>(mainModule);

  CleanFunctions *clean_pass = createCleanFunctionsPass();
  clean_pass->setLLVMContext(&ctx);

  // Add some optimizations.
  FPM->add(createBreakIntToPtrPass());
  FPM->add(clean_pass);
  FPM->add(new InstructionCombiningPass());
  FPM->doInitialization();

  for (auto &F : *mainModule) {
    FPM->run(F);
  }

  flat_control_flow();
}

void Terrace::run() {

  char **pEnvp = new char *[1];
  pEnvp[0] = NULL;

  char **pArgv = new char *[1];
  pArgv[0] = NULL;

  interpreter->runFunctionAsMain(main_fct, 1, pArgv, pEnvp);
}
