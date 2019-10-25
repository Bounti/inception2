#ifndef VERILATOR
#define VERILATOR 

#include "target.hpp"

class verilator : public Target {
  private:

  public:
  void write(uint32_t address, uint32_t data);

  uint32_t read(uint32_t address);

  klee::ref<Expr> read(klee::ref<Expr> address, klee::Expr::Width w);

  void write(klee::ref<Expr>  address, klee::ref<Expr> data, klee::Expr::Width w);

  void init();

  void close();

  uint32_t save() { return 0;};

  void restore(uint32_t id) {};

};

#endif
