#ifndef JLINK
#define JLINK

#include "target.hpp"
//#include "klee/Common.h"
#include "klee/Expr/Expr.h"
#include <thread>

using namespace klee;

class jlink : public Target {
  public:
  std::string name;
  
  klee::ref<Expr> read(klee::ref<Expr> address, klee::Expr::Width w);

  void write(klee::ref<Expr>  address, klee::ref<Expr> data, klee::Expr::Width w);

  void init();

  void shutdown();

  uint32_t save(uint32_t id=0);

  void restore(uint32_t id);

  uint32_t read(uint32_t address);

  void write(uint32_t address, uint32_t data);
  
  bool has_pending_irq(uint32_t state_id);

  int32_t get_active_irq(uint32_t state_id);

  void irq_ack();

  void remove(uint32_t id) {};

  void resume() {};

  void halt() {};

  private:
  std::thread* irq_handler_thread;

  uint32_t snapshot_length;

  uint32_t snapshot_index;

  uint32_t snp_counter;
};

#endif
