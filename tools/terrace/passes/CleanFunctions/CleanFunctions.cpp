#include "CleanFunctions.hpp"

#include <iostream>

#include "llvm/IR/Function.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include "../Utils/Utils.h"

#include <string>

using namespace llvm;

static cl::opt<bool>
    WatchValues("watch", cl::desc("Insert printing calls for observing values"),
                cl::init(false));

bool hasConstantOperandEqTo(Instruction *inst, unsigned long int to) {
  for (int i = 0; i < inst->getNumOperands(); ++i) {
    auto op = inst->getOperand(i);
    if (ConstantInt *CE = dyn_cast<ConstantInt>(op)) {
      if (CE->getZExtValue() == to) {
        // std::cout << "Constant Expression with interesting value" << std::endl;
        // inst->print(llvm::errs(), true);
        // std::cout << std::endl;
        return true;
      }
    }
  }
  return false;
}

/*
 * This is the proper way to remove instruction in LLVM
 * First, we need to recursively remove reference to uses
 * So then we can remove user.
 */
void eraseAllUses(Instruction *inst) {

  if (inst->use_empty()) {
    // std::cout << "Removing : " << std::endl;
    // inst->print(llvm::errs(), true);
    // std::cout << "" << std::endl;

    inst->replaceAllUsesWith(UndefValue::get(inst->getType()));
    inst->eraseFromParent();
    // inst->dropAllReferences();
    return;
  } else {

    for (auto U : inst->users()) { // U is of type User*
      if (auto I = dyn_cast<Instruction>(U)) {
        // an instruction uses V

        // std::cout << "Reference : " << std::endl;
        // inst->print(llvm::errs(), true);
        // std::cout << "" << std::endl;

        eraseAllUses(I);
      }
    }

    if (inst->use_empty()) {
      // std::cout << "Removing : " << std::endl;
      // inst->print(llvm::errs(), true);
      // std::cout << "" << std::endl;

      inst->replaceAllUsesWith(UndefValue::get(inst->getType()));
      inst->eraseFromParent();
      // inst->dropAllReferences();
      return;
    } else {
      std::cout << "Error instruction still has reference " << std::endl;
    }
  }
}

int remove_instructions_from_function(Function *F, LLVMContext *ctx) {

  Function::iterator f_it;
  BasicBlock::iterator it;
  Instruction *inst;

  int counter = 0;

  for (f_it = F->begin(); f_it != F->end(); f_it++) {
    for (it = f_it->getInstList().begin(); it != f_it->getInstList().end();
         it++) {

      if (hasConstantOperandEqTo(&(*it), 93918492168992) ||
          hasConstantOperandEqTo(&(*it), 94896629224320) ) {
        eraseAllUses(&(*it));
        counter++;
        // eraseAlluses affect the consistencies of our iterator since
        // some comming instructions may be null
        // We cannot safely use the previous instruction as it could be removed
        // also
        it = f_it->getInstList().begin();
      }
    }
  }

  // Replace branch instruction from entry block
  BasicBlock &BB = F->getEntryBlock();
  for (auto I = BB.rbegin(), E = BB.rend(); I != E; ++I) {
    Instruction &inst = *I;

    if (auto Br = dyn_cast<BranchInst>(&inst)) {
      auto bb_sucessor = Br->getSuccessor(1);
      Instruction *new_br = BranchInst::Create(bb_sucessor);
      ReplaceInstWithInst(&inst, new_br);
      return counter;
    }
  }

  return counter;
}

char CleanFunctions::ID = 0;
static RegisterPass<CleanFunctions> X("cleanFunctions", "StripCode Pass", false,
                                      false);

CleanFunctions *createCleanFunctionsPass() { return new CleanFunctions(); }
