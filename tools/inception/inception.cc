#include "inception.hpp"

#include "llvm/IR/IRBuilder.h"

#include <iostream>
#include <string>

#include "klee/Internal/Support/ErrorHandling.h"
#include <jsoncpp/json/json.h>

using namespace llvm;

uint32_t to_hexa(std::string str) {
  std::stringstream ss;
  uint32_t res;

  ss << std::hex << str;
  ss >> res;
  ss.clear();

  return res;
}


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

  uint64_t addr, size;
  StringRef name;
  std::error_code ec;

  for (object::symbol_iterator I = TempExecutable->symbols().begin(),
                               E = TempExecutable->symbols().end();
       I != E; ++I) {

    if ((ec = I->getName(name))) {
      klee_warning("error while reading ELF symbol  %s", ec.message().c_str());
      continue;
    }

    if ((ec = I->getAddress(addr))) {
      klee_warning("error while reading ELF symbol  %s", ec.message().c_str());
      continue;
    }

    if ((ec = I->getSize(size))) {
      klee_warning("error while reading ELF symbol  %s", ec.message().c_str());
      continue;
    }
    interpreter->addCustomObject(name, addr, size, false, false, false, false);
  }

  for (object::section_iterator I = TempExecutable->sections().begin(),
                                E = TempExecutable->sections().end();
       I != E; ++I) {

    if ((ec = I->getName(name))) {
      klee_warning("error while reading ELF symbol  %s", ec.message().c_str());
      continue;
    }

    addr = I->getAddress();

    size = I->getSize();

    interpreter->addCustomObject(name, addr, size, false, false, false, false);
  }


}

// Load memory configuration from file
void Inception::load_mem_conf_from_file(const char* _mem_conf_file_name) {

  if (_mem_conf_file_name != "-" && !sys::fs::exists(_mem_conf_file_name)) {
    klee::klee_error("unable to load memory configuration : %s ", _mem_conf_file_name);
  }

  std::ifstream config_file(_mem_conf_file_name, std::ifstream::binary);

  if (config_file) {

    // Load json in memory
    Json::Value* json = new Json::Value();

    config_file >> (*json);

    // Parse expected configuration
    auto mem_section = ((*json)["memory_model"]);

    auto it = mem_section.begin();
    auto limit = mem_section.end();

    for(; it!=limit ;it++) {
      bool is_symbolic   = false;
      bool is_forwarded  = false;
      bool is_randomized = false;

      std::string name         = it->get("name", "").asString();
      unsigned int base        = to_hexa(it->get("base", "0").asString());
      unsigned int size        = to_hexa(it->get("size", "0").asString());
      bool is_read_only        = it->get("read_only", false).asBool();
      std::string destination = it->get("destination", "").asString();

      std::string strategy = it->get("strategy", "concrete").asString();

      //Parse strategy
      if(strategy.compare("symbolic") == 0) {
        is_symbolic = true;
      } else if(strategy.compare("randomized") == 0) {
        is_randomized = true;
      } else if(strategy.compare("forwarded") == 0) {
        is_forwarded = true;
      }

      interpreter->addCustomObject(name, base, size, is_read_only, is_symbolic, is_randomized, is_forwarded);
    }
  } else {
    klee::klee_error("unable to read configuration file %s", _mem_conf_file_name);
  }
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

}

void Inception::prepare() {

  char **pEnvp = new char *[1];
  pEnvp[0] = NULL;

  char **pArgv = new char *[1];
  pArgv[0] = NULL;

  if( main_fct == NULL ) {
    // get entry point from ELF symbols table

    // otherwise get main
    main_fct = mainModule->getFunction("main");
  }

  interpreter->initFunctionAsMain(main_fct, 0, pArgv, pEnvp);
}

void Inception::start_analysis() {

  interpreter->start_analysis();
}
