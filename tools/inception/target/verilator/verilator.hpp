#ifndef VERILATOR
#define VERILATOR 

#include "target.hpp"

#include "klee/Internal/Support/ErrorHandling.h"
#include <sys/types.h>
#include <unistd.h>
#include "criu.h"

using namespace klee;

typedef struct {
  uint8_t irq_status;
  uint32_t address;
  uint8_t  type;
  uint32_t value;
  uint8_t  status;
  uint8_t  requested_mode;
  uint8_t  mode;
}IPC_MESSAGE;

class verilator : public Target {
  private:
  
    pid_t pid;

    void* ipc_ptr;
  
    std::string directory;

    criu_opts *criu_options;

    uint32_t unique_id;

    std::map<uint32_t, IPC_MESSAGE*> ipc_snapshots;

    void what_error_mean(int ret) {
 
      if(ret < 0) {
      
        switch (ret) {
        case -EBADE:
          perror("RPC has returned fail");
          break;
        case -ECONNREFUSED:
          perror("Unable to connect to CRIU");
          break;
        case -ECOMM:
          perror("Unable to send/recv msg to/from CRIU");
          break;
        case -EINVAL:
          perror(
              "CRIU doesn't support this type of request."
              "You should probably update CRIU");
          break;
        case -EBADMSG:
          perror(
              "Unexpected response from CRIU."
              "You should probably update CRIU");
          break;
        default:
          perror(
              "Unknown error type code."
              "You should probably update CRIU");
        }
      } 
    }

  void snapshot_ipc(uint32_t id) {

    std::map<uint32_t, IPC_MESSAGE*>::iterator it;
    
    IPC_MESSAGE* src = (IPC_MESSAGE*) ipc_ptr;
    IPC_MESSAGE* dst = NULL;

    it = ipc_snapshots.find(id);
    if( it != ipc_snapshots.end())
      dst = it->second;
    else
      dst = (IPC_MESSAGE*) malloc(sizeof(IPC_MESSAGE));

    if(!dst)
      klee_error("unable to snapshot verilator IPC due to memory allocation failed");

    dst->irq_status  = src->irq_status;
    dst->address     = src->address;
    dst->type        = src->type;
    dst->value       = src->value;
    dst->status      = src->status;

    //printf("irq_status    = %c\n", src->irq_status);
    //printf("address       = %08x\n", src->address);
    //printf("type          = %c\n", src->type);
    //printf("value         = %d\n", src->value);
    //printf("status        = %c\n", src->status);


    if( it != ipc_snapshots.end())
      it->second = dst;
    else
      ipc_snapshots.insert(std::pair<uint32_t, IPC_MESSAGE*>(id, dst)); 
    
  }

public:
 
    void write(uint32_t address, uint32_t data);
    
    uint32_t read(uint32_t address);
    
    klee::ref<Expr> read(klee::ref<Expr> address, klee::Expr::Width w);
    
    void write(klee::ref<Expr>  address, klee::ref<Expr> data, klee::Expr::Width w);
    
    void init();
    
    void shutdown();
    
    uint32_t save(uint32_t id=0);
    
    void restore(uint32_t id);

    bool has_pending_irq(uint32_t state_id);

    int32_t get_active_irq(uint32_t state_id);

    void irq_ack();

    void remove(uint32_t id);

    void resume();

    void halt();
};

#endif
