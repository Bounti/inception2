#include "verilator.hpp"

#include <sys/mman.h>
#include <sys/stat.h>        /* For mode constants */
#include <fcntl.h>           /* For O_* constants */
#include <signal.h>
#include <sys/wait.h>

#include "klee/Internal/Support/ErrorHandling.h"
#include "klee/Expr.h"

using namespace klee;

typedef struct {
  uint8_t irq_in;
  uint8_t irq_ack;

  uint32_t address;
  uint8_t  type;
  uint32_t value;
  uint8_t  status;
}IPC_MESSAGE;

bool verilator::has_pending_irq() {

  IPC_MESSAGE* ipc = (IPC_MESSAGE*) ipc_ptr;

  if ( ipc->irq_in == 1) {
    ipc->irq_in = 0;
    return true;
  }

  return false;
};

void verilator::write(uint32_t address, uint32_t data) {

  //klee_warning("verilator::write(%08x, %08x)", address, data);

  IPC_MESSAGE* ipc = (IPC_MESSAGE*) ipc_ptr;

  ipc->value    = data;
  ipc->address  = address;
  ipc->type   = 'W';
  ipc->status   = 0x50;
}

uint32_t verilator::read(uint32_t address) {
  
  //klee_warning("verilator::read(%08x, %08x)", address);
  
  IPC_MESSAGE* ipc = (IPC_MESSAGE*) ipc_ptr;

  ipc->address  = address;
  ipc->type   = 'R';
  ipc->status   = 0x50;

  while((ipc->status == 0x50) || (ipc->status == 0x42));

  return ipc->value;
}

void verilator::init() {

  pid = fork();
  if (pid == 0)
  {
      // replace son memory with binary binary
      char *args_execv[] = {(char*)binary.c_str(),NULL};
      execv(binary.c_str(), args_execv);
      _exit(1);
  }
  else if (pid > 0)
  {
       // do nothing here, we are the parent
  }
  else
  {
      perror("fork failed");
      _exit(3);
  }

  int sync_mem = shm_open("/sync_fifo", O_CREAT|O_RDWR, 0777);
  if(sync_mem == -1){
    klee_error("unable to create IPC shared memory (verilator com. channel)");
  }

  ipc_ptr = (u_char *) mmap(NULL, 14, PROT_READ|PROT_WRITE, MAP_SHARED, sync_mem, 0);
  if (ipc_ptr == MAP_FAILED) {
    klee_error("unable to create IPC shared memory (verilator com. channel)");
  }

}

void verilator::close() {
  int status;

  munmap(ipc_ptr, 14);
  
  klee_warning("closing target: verilator...");
  
  kill(pid, SIGKILL);
  if (waitpid (pid, &status, 0) < 0) {
    perror ("waitpid");
  }

}

klee::ref<Expr> verilator::read(klee::ref<Expr> address, klee::Expr::Width w) {

  ConstantExpr *address_ce = dyn_cast<ConstantExpr>(address);
  if(!address_ce)
    klee_error("unable to forward symbolic address");
  uint64_t concrete_address = address_ce->getZExtValue();

  uint32_t b_address = 0;

  switch (w) {
    default: {
      assert(0 && "DebuggerTarget called with an invalid width");
      break;
    }
    case Expr::Bool:
    case Expr::Int8: {
      klee_error("unsupported int8 access");

      b_address = concrete_address - (concrete_address % 4);

      uint32_t res = read(b_address);

      switch ((concrete_address % 4)) {
      case 3:
        res = (res & 0xFF000000) >> 24;
        break;
      case 2:
        res = (res & 0x00FF0000) >> 16;
        break;
      case 1:
        res = (res & 0x0000FF00) >> 8;
        break;
      case 0:
        res = (res & 0x000000FF);
        break;
      }
      return ConstantExpr::alloc(res, Expr::Int8);
      break;
    }
    case Expr::Int16: {
      klee_error("unsupported int16 access");

      b_address = concrete_address - (concrete_address % 4);

      uint32_t res = read(b_address);
      if (concrete_address % 4 == 0)
        res &= 0x0000FFFF;
      else
        res = (res & 0xFFFF0000) >> 16;

      return ConstantExpr::alloc(res, Expr::Int16);
      break;
    }
    case Expr::Int32: {

      // printf("Read  at 0x%08x value 0x%08x \r\n", (uint32_t)address,
      // (uint32_t)*value);
      uint32_t res;
      res = read((uint32_t)concrete_address);
      return ConstantExpr::alloc(res, Expr::Int32);
      break;
    }
    case Expr::Int64: {

      klee_error("unsupported forwarded read of size 64bits");
      break;
    }
  }

}

void verilator::write(klee::ref<Expr> address, klee::ref<Expr> data, klee::Expr::Width w) {
  uint32_t new_val = 0, b_address = 0;

  ConstantExpr *address_ce = dyn_cast<ConstantExpr>(address);
  if(!address_ce)
    klee_error("unable to forward symbolic address");
  uint64_t concrete_address = address_ce->getZExtValue();

  ConstantExpr *value_ce = dyn_cast<ConstantExpr>(data);
  if(!value_ce)
    klee_error("unable to forward symbolic value");
  uint64_t concrete_value = value_ce->getZExtValue();

  // printf("Write at 0x%08x value 0x%08x\r\n", (uint32_t)address,
  // (uint32_t)value);

  switch (w) {
    default: {
      assert(0 && "invalid width");
      break;
    }
    case Expr::Bool:
    case Expr::Int8: {

      klee_error("unsupported int8 access");
      b_address = concrete_address - (concrete_address % 4);

      new_val = read(b_address);

      // Is the access memory alligned
      switch ((concrete_address % 4)) {
      case 3:
        new_val = (new_val & 0x00FFFFFF) | (concrete_value << 24);
        break;
      case 2:
        new_val = (new_val & 0xFF00FFFF) | ((concrete_value & 0x000000FF) << 16);
        break;
      case 1:
        new_val = (new_val & 0xFFFF00FF) | ((concrete_value & 0x000000FF) << 8);
        break;
      case 0:
        new_val = (new_val & 0xFFFFFF00) | (concrete_value & 0x000000FF);
        break;
      }

      write(b_address, new_val);
      return;
      break;
    }
    case Expr::Int16: {
      klee_error("unsupported int16 access");

      b_address = concrete_address - (concrete_address % 4);

      new_val = read(b_address);
      // Is the access memory alligned
      if (concrete_address % 4 == 0)
        new_val = (new_val & 0xFFFF0000) | (concrete_value & 0x0000FFFF);
      else
        new_val = (new_val & 0x0000FFFF) | (concrete_value << 16);

      write(b_address, new_val);
      return;
      break;
    }
    case Expr::Int64: {
      klee_error("Unsupported forwarded write of size 64bits");
    }
    case Expr::Int32: {
      write(concrete_address, concrete_value);
      return;
      break;
    }
  }
}

