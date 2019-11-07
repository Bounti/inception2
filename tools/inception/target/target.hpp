#ifndef TARGET
#define TARGET

#include "klee/Common.h"
#include "klee/Expr.h"

using namespace klee;

class Target {
  public:
  std::string name;

  std::string args;

  std::string binary;

  std::string getArgs() { return args;}

  void setArgs(std::string _args) { args = _args;}

  std::string getBinary() { return binary;}

  void setBinary(std::string _binary) { binary = _binary;}

  std::string getName() { return name;}

  void setName(std::string _name) { name = _name;}

  virtual klee::ref<Expr> read(klee::ref<Expr> address, klee::Expr::Width w) = 0;

  virtual void write(klee::ref<Expr>  address, klee::ref<Expr> data, klee::Expr::Width w) = 0;

  virtual void init() = 0;

  virtual void shutdown() = 0;

  virtual uint32_t save(uint32_t id=0) = 0;

  virtual void restore(uint32_t id) = 0;

  virtual void remove(uint32_t id) = 0;

  virtual bool has_pending_irq() = 0;

  virtual int32_t get_active_irq() = 0;

  virtual void irq_ack() = 0;

  virtual void halt() = 0;

  virtual void resume() = 0;

};

#endif
