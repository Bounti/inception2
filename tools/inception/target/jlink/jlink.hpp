#ifndef JLINK
#define JLINK

#include "target.hpp"
#include "klee/Common.h"
#include "klee/Expr.h"

using namespace klee;

class jlink : public Target {
  public:
  std::string name;
  
  klee::ref<Expr> read(klee::ref<Expr> address, klee::Expr::Width w);

  void write(klee::ref<Expr>  address, klee::ref<Expr> data, klee::Expr::Width w);

  void init();

  void close();

  uint32_t save() { return 0;};

  void restore(uint32_t id) {};

  uint32_t read(uint32_t address);

  void write(uint32_t address, uint32_t data);
  
  bool has_pending_irq() { return false;};

  int32_t get_active_irq() { return -1;};

  void irq_ack() {};
};

#endif
