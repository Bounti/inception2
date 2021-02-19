#ifndef DUMMY_TARGET
#define DUMMY_TARGET

//#include "klee/Common.h"
#include "klee/Expr/Expr.h"
#include "target.hpp"

using namespace klee;

class dummy : public Target {
  public:

  dummy();

  ~dummy();

  std::string name;

  std::string args;

  std::string binary;

  bool active;

  std::string getArgs();

  void setArgs(std::string _args);

  std::string getBinary();

  void setBinary(std::string _binary);

  std::string getName();

  void setName(std::string _name);

  klee::ref<Expr> read(klee::ref<Expr> address, klee::Expr::Width w);

  void write(klee::ref<Expr>  address, klee::ref<Expr> data, klee::Expr::Width w);

  void init();

  void shutdown();

  uint32_t save(uint32_t id=0);

  void restore(uint32_t id);

  void remove(uint32_t id);

  bool has_pending_irq(uint32_t state_id);

  int32_t get_active_irq(uint32_t state_id);

  void irq_ack();

  void halt();

  void resume();

  void enable();

  void disable();

  bool is_active();
};

#endif
