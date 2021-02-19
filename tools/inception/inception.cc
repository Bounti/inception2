#include "inception.hpp"

#include "llvm/IR/IRBuilder.h"
#include "llvm/Object/Binary.h"
#include "llvm/BinaryFormat/Magic.h"
#include "llvm/Object/Archive.h"
#include "llvm/Object/Error.h"
#include "llvm/Object/Binary.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/ErrorOr.h"

#include <iostream>
#include <string>

#include "klee/Support/ErrorHandling.h"
#include <jsoncpp/json/json.h>
#include "target/dummy.hpp"

using namespace llvm;

cl::OptionCategory LinkCat("Linking options",
    "These options control the libraries being linked.");

cl::list<std::string>
LinkLibraries("link-llvm-lib",
    cl::desc("Link the given bitcode library before execution, "
      "e.g. .bca, .bc, .a. Can be used multiple times."),
    cl::value_desc("bitcode library file"), cl::cat(LinkCat));


cl::opt<int>
min_irq_threshold("min_irq_threshold",
          cl::init(100),
          cl::desc("set minimal number of lines to reach before rising irq (default=100)"));

cl::opt<std::string>
EntryPoint("entry-point",
          cl::desc("Function in which to start execution (default=main)"),
          cl::init("main"));
  
cl::opt<std::string> RuntimeBuild(
    "runtime-build",
    cl::desc("Link with versions of the runtime library that were built with "
      "the provided configuration (default=" RUNTIME_CONFIGURATION
      ")."),
    cl::init(RUNTIME_CONFIGURATION), cl::cat(LinkCat));

namespace llvm {

  // Various helper functions.
  LLVM_ATTRIBUTE_NORETURN void reportError(Error Err, StringRef Input);
  void reportWarning(Error Err, StringRef Input);

  template <class T> T unwrapOrError(StringRef Input, Expected<T> EO) {
    if (EO)
      return *EO;
    reportError(EO.takeError(), Input);
  }
} // namespace llvm

uint32_t to_hexa(std::string str) {
  std::stringstream ss;
  uint32_t res;

  ss << std::hex << str;
  ss >> res;
  ss.clear();

  return res;
}

void Inception::load_configuration(char **argv) {

  std::string LibraryDir = KleeHandler::getRunTimeLibraryPath(argv[0]);

  // Push the module as the first entry
  loadedModules.emplace_back(std::move(mainModule));

  std::string errorMsg;
  LLVMContext ctx;
  
  // Add additional user-selected suffix
  std::string opt_suffix = "32"; //_" + RuntimeBuild.getValue();

  Interpreter::ModuleOptions Opts(LibraryDir.c_str(), EntryPoint, opt_suffix,
                                /*Optimize=*/true,
                                /*CheckDivZero=*/true,
                                /*CheckOvershift=*/true);

  for (const auto &library : LinkLibraries) {
    if (!klee::loadFile(library, mainModule->getContext(), loadedModules,
          errorMsg))
      klee_error("error loading bitcode library '%s': %s", library.c_str(),
          errorMsg.c_str());
    else
      klee_warning("loading bitcode library '%s': %s", library.c_str(),
          errorMsg.c_str());
  }

  auto finalModule = interpreter->setModule(loadedModules, Opts);

  mainModule = finalModule;

  // mainModule->print(llvm::errs(), nullptr);
}

// Load ELF binary
void Inception::load_elf_binary_from_file(const char* _elf_file_name) {

  std::unique_ptr<object::ObjectFile> TempExecutable;

  // File should be stdin or it should exist.
  if (_elf_file_name != "-" && !sys::fs::exists(_elf_file_name)) {
    klee::klee_error("Unable to locate ELF file or directory : %s ", _elf_file_name);
  }

  auto obinary = llvm::object::createBinary(_elf_file_name);
  if (obinary) {
    auto executable = std::move(*obinary);

    std::pair<std::unique_ptr<object::Binary>, std::unique_ptr<MemoryBuffer>> res = executable.takeBinary();

    //llvm::ErrorOr<std::unique_ptr<llvm::object::ObjectFile>>
    llvm::Expected<std::unique_ptr<llvm::object::ObjectFile>> ret = object::ObjectFile::createObjectFile(res.second.release()->getMemBufferRef());

    TempExecutable.swap(ret.get());

    interpreter->set_elf(TempExecutable);
    //llvm::object::Binary &Binary = *OBinary.getBinary();
  } else {
    klee::klee_error("Unknown binary file format : %s ", _elf_file_name);
  }

  //Expected<llvm::object::OwningBinary<llvm::object::Binary>> Binary =
  //    object::createBinary(_elf_file_name);
  //OwningBinary<Binary> OBinary = unwrapOrError(createBinary(_elf_file_name), file);
  //if (std::error_code err = Binary.getError()) {
  //  klee::klee_error("Unknown binary file format : %s ", _elf_file_name);
  //} else {
  //  if (Binary.get().getBinary()->isObject()) {
  //    std::pair<std::unique_ptr<object::Binary>, std::unique_ptr<MemoryBuffer>>
  //        res = Binary.get().takeBinary();
  //        llvm::ErrorOr<std::unique_ptr<llvm::object::ObjectFile>> ret =
  //        object::ObjectFile::createObjectFile(
  //            res.second.release()->getMemBufferRef());
  //    TempExecutable.swap(ret.get());
  //  }
  //}

  //interpreter->set_elf(TempExecutable);
}

// Load Targets env
void Inception::load_targets_conf_from_file(const char* _targets_conf_file) {

  if (_targets_conf_file != "-" && !sys::fs::exists(_targets_conf_file)) {
    klee::klee_error("unable to load target configuration : %s ", _targets_conf_file);
  }

  std::ifstream config_file(_targets_conf_file, std::ifstream::binary);

  if (config_file) {

    // Load json in memory
    Json::Value* json = new Json::Value();

    config_file >> (*json);

    // Parse expected configuration
    auto target_section = ((*json)["targets"]);

    auto it = target_section.begin();
    auto limit = target_section.end();

    for(; it!=limit ;it++) {

      std::string name         = it->get("name", "").asString();
      std::string type         = it->get("type", "").asString();
      std::string binary       = it->get("binary", "").asString();
      std::string args         = it->get("args", "").asString();
      bool active              = it->get("active",false).asBool();

      add_target(name, type, binary, args, active);
    }

  } else {
    klee::klee_error("unable to read configuration file %s", _targets_conf_file);
  }
}

// Load interrupt configuration from file
void Inception::load_interrupt_conf_from_file(const char* _interrupt_conf_file_name) {

  if (_interrupt_conf_file_name != "-" && !sys::fs::exists(_interrupt_conf_file_name)) {
    klee::klee_error("unable to load memory configuration : %s ", _interrupt_conf_file_name);
  }

  std::ifstream config_file(_interrupt_conf_file_name, std::ifstream::binary);

  interpreter->set_min_irq_threshold(min_irq_threshold);

  if (config_file) {

    // Load json in memory
    Json::Value* json = new Json::Value();

    config_file >> (*json);

    // Parse expected configuration
    auto irq_section = ((*json)["interrupt_model"]);

    auto it = irq_section.begin();
    auto limit = irq_section.end();

    for(; it!=limit ;it++) {

      unsigned int irq_id      = it->get("id", 0).asInt();
      unsigned int frequency   = it->get("frequency", 0).asInt();

      if(irq_id != 0 && frequency != 0)
        interpreter->add_irq_to_model(irq_id, frequency);
    }
  } else {
    klee::klee_error("unable to read configuration file %s", _interrupt_conf_file_name);
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
      std::string target       = it->get("target", "").asString();

      std::string strategy = it->get("strategy", "concrete").asString();

      //Parse strategy
      if(strategy.compare("symbolic") == 0) {
        is_symbolic = true;
      } else if(strategy.compare("randomized") == 0) {
        is_randomized = true;
      } else if(strategy.compare("forwarded") == 0) {
        is_forwarded = true;
      }

      interpreter->addCustomObject(name, base, size, is_read_only, is_symbolic, is_randomized, is_forwarded, target);
    }
  } else {
    klee::klee_error("unable to read configuration file %s", _mem_conf_file_name);
  }
}

void Inception::load_llvm_bitcode_from_file(const char *_bc_file_name) {

  bc_file_name.assign(_bc_file_name);

  // Load the bytecode...
  std::string errorMsg;

  if (!klee::loadFile(bc_file_name, ctx, loadedModules, errorMsg)) {
    klee::klee_error("error loading program '%s': %s", bc_file_name.c_str(),
               errorMsg.c_str());
  }

  // Load and link the whole files content. The assumption is that this is the
  // application under test.
  // Nothing gets removed in the first place.
  std::unique_ptr<llvm::Module> M(klee::linkModules(
      loadedModules, "" /* link all mainModules together */, errorMsg));
  if (!M) {
    klee::klee_error("error loading program '%s': %s", bc_file_name.c_str(),
               errorMsg.c_str());
  }

  mainModule = M.release();

  // mainModule->print(llvm::errs(), nullptr);
}

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
    main_fct = mainModule->getFunction(EntryPoint);
    if (!main_fct) {
      mainModule->print(llvm::errs(), nullptr);
      klee_error("Entry function '%s' not found in module.", EntryPoint.c_str());
    }
  }

  interpreter->initFunctionAsMain(main_fct, 0, pArgv, pEnvp);
}

void Inception::start_analysis() {

  interpreter->start_analysis();
}

void Inception::add_target(std::string name, std::string type, std::string binary, std::string args, bool active) {

  Target* target = NULL;

  if( resolve_target(name) != NULL )
    return;

  #ifdef TARGET_STEROIDS_ACTIVE
  if( type.compare("usb3_dap") == 0 ) {
    target = new usb3dap();
  }
  #endif
  #ifdef TARGET_JLINK_ACTIVE
  if ( type.compare("jlink") == 0 ) {
    target = new jlink();
    target->setArgs(args);
  }
  #endif
  #ifdef TARGET_VERILATOR_ACTIVE
  if( type.compare("openocd") == 0 ) {
    target = new openocd();
    target->setArgs(args);
  }
  #endif
  #ifdef TARGET_VERILATOR_ACTIVE
  if( type.compare("verilator") == 0 ) {
    target = new verilator();
    target->setBinary(binary);
    target->setArgs(args);
  }
  #endif
  if( type.compare("dummy") == 0 ) {
    target = new dummy();
  }

  if(target == NULL) {
    klee_error("targets configuration does not support %s", type.c_str());
  } else {
    klee_message("adding target %s", type.c_str());
    target->setName(name);
    if(active)
      target->enable();
    target->init();
    targets.push_back(target);
  }
}

