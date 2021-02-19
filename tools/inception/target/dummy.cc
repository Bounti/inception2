#include "dummy.hpp"

dummy::dummy() {}

dummy::~dummy() {}

std::string dummy::getArgs() { return args;}

void dummy::setArgs(std::string _args) { args = _args;}

std::string dummy::getBinary() { return binary;}

void dummy::setBinary(std::string _binary) { binary = _binary;}

std::string dummy::getName() { return name;}

void dummy::setName(std::string _name) { name = _name;}

klee::ref<Expr> dummy::read(klee::ref<Expr> address, klee::Expr::Width w) {

  return klee::ConstantExpr::alloc(0, Expr::Int32);
};

void dummy::write(klee::ref<Expr>  address, klee::ref<Expr> data, klee::Expr::Width w) {}

void dummy::init() {}

void dummy::shutdown() {}

uint32_t dummy::save(uint32_t id) {

  return id;
}

void dummy::restore(uint32_t id) {};

void dummy::remove(uint32_t id) {};

bool dummy::has_pending_irq(uint32_t state_id) { return false;}

int32_t dummy::get_active_irq(uint32_t state_id) { return 0;}

void dummy::irq_ack() {}

void dummy::halt() {}

void dummy::resume() {}

void dummy::enable() { active = true;}

void dummy::disable() { active = false;}

bool dummy::is_active() { return active;}


