#include "klee-handler.hpp"

#include "klee/Config/Version.h"
#include "ExecutionState.h"
#include "klee/Expr/Expr.h"
#include "klee/ADT/KTest.h"
#include "klee/ADT/TreeStream.h"
#include "klee/Support/Debug.h"
#include "klee/Support/ErrorHandling.h"
#include "klee/Support/FileHandling.h"
#include "klee/Support/ModuleUtil.h"
#include "klee/Support/PrintVersion.h"
#include "klee/System/Time.h"
#include "klee/Core/Interpreter.h"
#include "klee/Support/OptionCategories.h"
#include "klee/Solver/SolverCmdLine.h"
#include "klee/Statistics/Statistics.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Errno.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/Support/Signals.h"
#include "llvm/Support/TargetSelect.h"

#if LLVM_VERSION_CODE < LLVM_VERSION(3, 5)
#include "llvm/Support/system_error.h"
#endif

#if LLVM_VERSION_CODE >= LLVM_VERSION(4, 0)
#include <llvm/Bitcode/BitcodeReader.h>
#else
#include <llvm/Bitcode/ReaderWriter.h>
#endif

#include <dirent.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <sstream>

using namespace llvm;
using namespace klee;

cl::OptionCategory StartCat("Startup options",
                            "These options affect how execution is started.");

cl::opt<std::string> OutputDir(
    "output-dir",
    cl::desc("Directory in which to write results (default=klee-out-<N>)"),
    cl::init(""), cl::cat(StartCat));

cl::OptionCategory TestCaseCat(
    "Test case options",
    "These options select the files to generate for each test case.");

cl::opt<unsigned> MaxTests(
    "max-tests",
    cl::desc("Stop execution after generating the given number of tests. Extra "
             "tests corresponding to partially explored paths will also be "
             "dumped.  Set to 0 to disable (default=0)"),
    cl::init(0), cl::cat(TerminationCat));

cl::opt<bool>
    WriteNone("write-no-tests", cl::init(false),
              cl::desc("Do not generate any test files (default=false)"),
              cl::cat(TestCaseCat));

cl::opt<bool>
    WriteCVCs("write-cvcs",
              cl::desc("Write .cvc files for each test case (default=false)"),
              cl::cat(TestCaseCat));

cl::opt<bool> WriteKQueries(
    "write-kqueries",
    cl::desc("Write .kquery files for each test case (default=false)"),
    cl::cat(TestCaseCat));

cl::opt<bool> WriteSMT2s(
    "write-smt2s",
    cl::desc(
        "Write .smt2 (SMT-LIBv2) files for each test case (default=false)"),
    cl::cat(TestCaseCat));

cl::opt<bool> WriteCov(
    "write-cov",
    cl::desc("Write coverage information for each test case (default=false)"),
    cl::cat(TestCaseCat));

cl::opt<bool> WriteTestInfo(
    "write-test-info",
    cl::desc("Write additional test case information (default=false)"),
    cl::cat(TestCaseCat));

cl::opt<bool>
    WritePaths("write-paths",
               cl::desc("Write .path files for each test case (default=false)"),
               cl::cat(TestCaseCat));

cl::opt<bool> WriteSymPaths(
    "write-sym-paths",
    cl::desc("Write .sym.path files for each test case (default=false)"),
    cl::cat(TestCaseCat));

cl::opt<bool>
    OptExitOnError("exit-on-error",
                   cl::desc("Exit KLEE if an error in the tested application "
                            "has been found (default=false)"),
                   cl::init(false), cl::cat(TerminationCat));

KleeHandler::KleeHandler(int argc, char **argv, std::string InputFile)
    : m_interpreter(0), m_pathWriter(0), m_symPathWriter(0),
      m_outputDirectory(), m_numTotalTests(0), m_numGeneratedTests(0),
      m_pathsExplored(0), m_argc(argc), m_argv(argv) {

  // create output directory (OutputDir or "klee-out-<i>")
  bool dir_given = OutputDir != "";
  SmallString<128> directory(dir_given ? OutputDir : InputFile);

  if (!dir_given)
    sys::path::remove_filename(directory);
#if LLVM_VERSION_CODE < LLVM_VERSION(3, 5)
  error_code ec;
  if ((ec = sys::fs::make_absolute(directory)) != errc::success) {
#else
  if (auto ec = sys::fs::make_absolute(directory)) {
#endif
    klee::klee_error("unable to determine absolute path: %s", ec.message().c_str());
  }

  if (dir_given) {
    // OutputDir
    if (mkdir(directory.c_str(), 0775) < 0)
      klee::klee_error("cannot create \"%s\": %s", directory.c_str(),
                 strerror(errno));

    m_outputDirectory = directory;
  } else {
    // "klee-out-<i>"
    int i = 0;
    for (; i <= INT_MAX; ++i) {
      SmallString<128> d(directory);
      llvm::sys::path::append(d, "klee-out-");
      raw_svector_ostream ds(d);
      ds << i;
// SmallString is always up-to-date, no need to flush. See Support/raw_ostream.h
#if LLVM_VERSION_CODE < LLVM_VERSION(3, 8)
      ds.flush();
#endif

      // create directory and try to link klee-last
      if (mkdir(d.c_str(), 0775) == 0) {
        m_outputDirectory = d;

        SmallString<128> klee_last(directory);
        llvm::sys::path::append(klee_last, "klee-last");

        if (((unlink(klee_last.c_str()) < 0) && (errno != ENOENT)) ||
            symlink(m_outputDirectory.c_str(), klee_last.c_str()) < 0) {

          klee::klee_warning("cannot create klee-last symlink: %s", strerror(errno));
        }

        break;
      }

      // otherwise try again or exit on error
      if (errno != EEXIST)
        klee::klee_error("cannot create \"%s\": %s", m_outputDirectory.c_str(),
                   strerror(errno));
    }
    if (i == INT_MAX && m_outputDirectory.str().equals(""))
      klee::klee_error("cannot create output directory: index out of range");
  }

  klee::klee_message("output directory is \"%s\"", m_outputDirectory.c_str());

  // open warnings.txt
  std::string file_path = getOutputFilename("warnings.txt");
  if ((klee::klee_warning_file = fopen(file_path.c_str(), "w")) == NULL)
    klee::klee_error("cannot open file \"%s\": %s", file_path.c_str(),
               strerror(errno));

  // open messages.txt
  file_path = getOutputFilename("messages.txt");
  if ((klee::klee_message_file = fopen(file_path.c_str(), "w")) == NULL)
    klee::klee_error("cannot open file \"%s\": %s", file_path.c_str(),
               strerror(errno));

  // open info
  m_infoFile = openOutputFile("info");
}

KleeHandler::~KleeHandler() {
  delete m_pathWriter;
  delete m_symPathWriter;
  fclose(klee::klee_warning_file);
  fclose(klee::klee_message_file);
}

void KleeHandler::setInterpreter(Interpreter *i) {
  m_interpreter = i;

  if (WritePaths) {
    m_pathWriter = new TreeStreamWriter(getOutputFilename("paths.ts"));
    assert(m_pathWriter->good());
    m_interpreter->setPathWriter(m_pathWriter);
  }

  if (WriteSymPaths) {
    m_symPathWriter = new TreeStreamWriter(getOutputFilename("symPaths.ts"));
    assert(m_symPathWriter->good());
    m_interpreter->setSymbolicPathWriter(m_symPathWriter);
  }
}

std::string KleeHandler::getOutputFilename(const std::string &filename) {
  SmallString<128> path = m_outputDirectory;
  sys::path::append(path, filename);
  return path.str();
}

std::unique_ptr<llvm::raw_fd_ostream>
KleeHandler::openOutputFile(const std::string &filename) {
  std::string Error;
  std::string path = getOutputFilename(filename);
  auto f = klee_open_output_file(path, Error);
  if (!f) {
    klee::klee_warning("error opening file \"%s\".  KLEE may have run out of file "
                 "descriptors: try to increase the maximum number of open file "
                 "descriptors by using ulimit (%s).",
                 path.c_str(), Error.c_str());
    return nullptr;
  }
  return f;
}

std::string KleeHandler::getTestFilename(const std::string &suffix,
                                         unsigned id) {
  std::stringstream filename;
  filename << "test" << std::setfill('0') << std::setw(6) << id << '.'
           << suffix;
  return filename.str();
}

std::unique_ptr<llvm::raw_fd_ostream>
KleeHandler::openTestFile(const std::string &suffix, unsigned id) {
  return openOutputFile(getTestFilename(suffix, id));
}

/* Outputs all files (.ktest, .kquery, .cov etc.) describing a test case */
void KleeHandler::processTestCase(const ExecutionState &state,
                                  const char *errorMessage,
                                  const char *errorSuffix) {
  if (!WriteNone) {
    std::vector<std::pair<std::string, std::vector<unsigned char>>> out;
    bool success = m_interpreter->getSymbolicSolution(state, out);

    if (!success)
      klee::klee_warning("unable to get symbolic solution, losing test case");

    const auto start_time = time::getWallTime();

    unsigned id = ++m_numTotalTests;

    if (success) {
      KTest b;
      b.numArgs = m_argc;
      b.args = m_argv;
      b.symArgvs = 0;
      b.symArgvLen = 0;
      b.numObjects = out.size();
      b.objects = new KTestObject[b.numObjects];
      assert(b.objects);
      for (unsigned i = 0; i < b.numObjects; i++) {
        KTestObject *o = &b.objects[i];
        o->name = const_cast<char *>(out[i].first.c_str());
        o->numBytes = out[i].second.size();
        o->bytes = new unsigned char[o->numBytes];
        assert(o->bytes);
        std::copy(out[i].second.begin(), out[i].second.end(), o->bytes);
      }

      if (!kTest_toFile(
              &b, getOutputFilename(getTestFilename("ktest", id)).c_str())) {
        klee::klee_warning("unable to write output test case, losing it");
      } else {
        ++m_numGeneratedTests;
      }

      for (unsigned i = 0; i < b.numObjects; i++)
        delete[] b.objects[i].bytes;
      delete[] b.objects;
    }

    if (errorMessage) {
      auto f = openTestFile(errorSuffix, id);
      if (f)
        *f << errorMessage;
    }

    if (m_pathWriter) {
      std::vector<unsigned char> concreteBranches;
      m_pathWriter->readStream(m_interpreter->getPathStreamID(state),
                               concreteBranches);
      auto f = openTestFile("path", id);
      if (f) {
        for (const auto &branch : concreteBranches) {
          *f << branch << '\n';
        }
      }
    }

    if (errorMessage || WriteKQueries) {
      std::string constraints;
      m_interpreter->getConstraintLog(state, constraints, Interpreter::KQUERY);
      auto f = openTestFile("kquery", id);
      if (f)
        *f << constraints;
    }

    if (WriteCVCs) {
      // FIXME: If using Z3 as the core solver the emitted file is actually
      // SMT-LIBv2 not CVC which is a bit confusing
      std::string constraints;
      m_interpreter->getConstraintLog(state, constraints, Interpreter::STP);
      auto f = openTestFile("cvc", id);
      if (f)
        *f << constraints;
    }

    if (WriteSMT2s) {
      std::string constraints;
      m_interpreter->getConstraintLog(state, constraints, Interpreter::SMTLIB2);
      auto f = openTestFile("smt2", id);
      if (f)
        *f << constraints;
    }

    if (m_symPathWriter) {
      std::vector<unsigned char> symbolicBranches;
      m_symPathWriter->readStream(m_interpreter->getSymbolicPathStreamID(state),
                                  symbolicBranches);
      auto f = openTestFile("sym.path", id);
      if (f) {
        for (const auto &branch : symbolicBranches) {
          *f << branch << '\n';
        }
      }
    }

    if (WriteCov) {
      std::map<const std::string *, std::set<unsigned>> cov;
      m_interpreter->getCoveredLines(state, cov);
      auto f = openTestFile("cov", id);
      if (f) {
        for (const auto &entry : cov) {
          for (const auto &line : entry.second) {
            *f << *entry.first << ':' << line << '\n';
          }
        }
      }
    }

    if (m_numGeneratedTests == MaxTests)
      m_interpreter->setHaltExecution(true);

    if (WriteTestInfo) {
      time::Span elapsed_time(time::getWallTime() - start_time);
      auto f = openTestFile("info", id);
      if (f)
        *f << "Time to generate test case: " << elapsed_time << '\n';
    }
  } // if (!WriteNone)

  if (errorMessage && OptExitOnError) {
    m_interpreter->prepareForEarlyExit();
    klee::klee_error("EXITING ON ERROR:\n%s\n", errorMessage);
  }
}

// load a .path file
void KleeHandler::loadPathFile(std::string name, std::vector<bool> &buffer) {
  std::ifstream f(name.c_str(), std::ios::in | std::ios::binary);

  if (!f.good())
    assert(0 && "unable to open path file");

  while (f.good()) {
    unsigned value;
    f >> value;
    buffer.push_back(!!value);
    f.get();
  }
}

void KleeHandler::getKTestFilesInDir(std::string directoryPath,
                                     std::vector<std::string> &results) {
#if LLVM_VERSION_CODE < LLVM_VERSION(3, 5)
  error_code ec;
#else
  std::error_code ec;
#endif
  llvm::sys::fs::directory_iterator i(directoryPath, ec), e;
  for (; i != e && !ec; i.increment(ec)) {
    auto f = i->path();
    if (f.size() >= 6 && f.substr(f.size() - 6, f.size()) == ".ktest") {
      results.push_back(f);
    }
  }

  if (ec) {
    llvm::errs() << "ERROR: unable to read output directory: " << directoryPath
                 << ": " << ec.message() << "\n";
    exit(1);
  }
}

std::string KleeHandler::getRunTimeLibraryPath(const char *argv0) {
  // allow specifying the path to the runtime library
  const char *env = getenv("KLEE_RUNTIME_LIBRARY_PATH");
  if (env)
    return std::string(env);

  // Take any function from the execution binary but not main (as not allowed by
  // C++ standard)
  void *MainExecAddr = (void *)(intptr_t)getRunTimeLibraryPath;
  SmallString<128> toolRoot(
      llvm::sys::fs::getMainExecutable(argv0, MainExecAddr));

  // Strip off executable so we have a directory path
  llvm::sys::path::remove_filename(toolRoot);

  SmallString<128> libDir;

  if (strlen(KLEE_INSTALL_BIN_DIR) != 0 &&
      strlen(KLEE_INSTALL_RUNTIME_DIR) != 0 &&
      toolRoot.str().endswith(KLEE_INSTALL_BIN_DIR)) {
    KLEE_DEBUG_WITH_TYPE("klee_runtime",
                         llvm::dbgs()
                             << "Using installed KLEE library runtime: ");
    libDir = toolRoot.str().substr(0, toolRoot.str().size() -
                                          strlen(KLEE_INSTALL_BIN_DIR));
    llvm::sys::path::append(libDir, KLEE_INSTALL_RUNTIME_DIR);
  } else {
    KLEE_DEBUG_WITH_TYPE("klee_runtime",
                         llvm::dbgs()
                             << "Using build directory KLEE library runtime :");
    libDir = KLEE_DIR;
    llvm::sys::path::append(libDir, RUNTIME_CONFIGURATION);
    llvm::sys::path::append(libDir, "lib");
  }

  KLEE_DEBUG_WITH_TYPE("klee_runtime", llvm::dbgs() << libDir.c_str() << "\n");
  return libDir.str();
}
