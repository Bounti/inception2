#include "verilator.hpp"

#include <sys/mman.h>
#include <sys/stat.h>        /* For mode constants */
#include <fcntl.h>           /* For O_* constants */
#include <signal.h>
#include <sys/wait.h>
#include <mutex>
#include <thread>
#include "criu.h"
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>

#include "klee/Internal/Support/ErrorHandling.h"
#include "klee/Expr.h"

using namespace klee;

std::mutex io_mutex;

volatile int process_done = 0;

static int notify(char *action, criu_notify_arg_t na) {
  //printf("Notification !!!!\n");
  process_done = 1;
}

static bool is_directory(std::string path) {
  DIR *dir = opendir(path.c_str());
  if (dir) {
    closedir(dir);
    return true;
  } else {
    return false;
  }
}

void verilator::irq_ack() {
  klee_warning("ack...");
  IPC_MESSAGE* ipc = (IPC_MESSAGE*) ipc_ptr;
  ipc->irq_status = 'K';
  klee_warning("done");
}

bool verilator::has_pending_irq() {

  IPC_MESSAGE* ipc = (IPC_MESSAGE*) ipc_ptr;

  if ( ipc->irq_status == 'P') {
    ipc->irq_status = 'A';
    printf("***************************************************IRQ*********************************************************\n");
    return true;
  }
  return false;
}

int32_t verilator::get_active_irq() {
  //TODO: avoid hardwire
  uint32_t address = 0x43c20000;
  uint32_t value = 0;

  io_mutex.lock();
  {
    IPC_MESSAGE* ipc = (IPC_MESSAGE*) ipc_ptr;

    while((ipc->status == 'B') || (ipc->status == 'P'));

    ipc->address  = address;
    ipc->type   = 'R';
    ipc->status   = 'P';

    while((ipc->status != 'K'));

    value = ipc->value;
  }
  io_mutex.unlock();

  klee_warning("verilator::read(%08x, %08x)", address, value);

  return (int32_t)(value & 0x7);
}

void verilator::write(uint32_t address, uint32_t data) {
  klee_warning("verilator::write(%08x, %08x)", address, data);
  
  io_mutex.lock();
  {
    IPC_MESSAGE* ipc = (IPC_MESSAGE*) ipc_ptr;

    while((ipc->status == 'B') || (ipc->status == 'P'));

    ipc->value    = data;
    ipc->address  = address;
    ipc->type   = 'W';
    ipc->status   = 'P'; 
  }
  io_mutex.unlock();
}

uint32_t verilator::read(uint32_t address) {
  uint32_t value = 0;
  
  io_mutex.lock();
  {
    IPC_MESSAGE* ipc = (IPC_MESSAGE*) ipc_ptr;

    while((ipc->status == 'B') || (ipc->status == 'P'));

    ipc->address  = address;
    ipc->type   = 'R';
    ipc->status   = 'P';

    while((ipc->status != 'K')); 

    value = ipc->value; 
  }
  io_mutex.unlock();

  klee_warning("verilator::read(%08x, %08x)", address, value);

  return value;
}

void verilator::init() {

  pid = fork();
  if (pid == 0)
  {
      // replace son memory with binary binary
      char *args_execv[] = {(char*)binary.c_str(),(char*)args.c_str(), NULL};
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

  unique_id = 1;

  /*
   * initialize CRIU: process checkpoint
   */
  directory = "/tmp/img";

  criu_options = criu_my_init_opts();
  if( criu_options == NULL ) {
    klee_error("unable to init criu options\n");
  }
  criu_local_set_pid(criu_options, pid);
  criu_local_set_service_address(criu_options, NULL);
  criu_local_set_shell_job(criu_options, true);
  criu_local_set_leave_running(criu_options, false);
  criu_local_set_log_level(criu_options, 4);
  criu_local_set_service_comm(criu_options, CRIU_COMM_SK);
  criu_local_set_notify_cb(criu_options, notify);
  /*
   * TODO: enable user parameters
   */
  criu_local_set_service_address(criu_options, "/tmp/localhost");

  /*
   * initialize IPC
   */
  int sync_mem = shm_open("/sync_fifo", O_CREAT|O_RDWR, 0777);
  if(sync_mem == -1){
    klee_error("unable to create IPC shared memory (verilator com. channel)");
  }

  ftruncate(sync_mem, 512);

  ipc_ptr = (u_char *) mmap(NULL, 14, PROT_READ|PROT_WRITE, MAP_SHARED, sync_mem, 0);
  if (ipc_ptr == MAP_FAILED) {
    klee_error("unable to create IPC shared memory (verilator com. channel)");
  }

  //std::this_thread::sleep_for (std::chrono::seconds(2)); 

  IPC_MESSAGE* ipc = (IPC_MESSAGE*) ipc_ptr;
  ipc->irq_status  = 0;
  ipc->address     = 0;
  ipc->type        = 0;
  ipc->value       = 0;
  ipc->status      = 0;

}

void verilator::shutdown() {
  int status;

  munmap(ipc_ptr, 14);

  klee_warning("closing target: verilator...");

  kill(pid, SIGINT);
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

void verilator::remove(uint32_t id) {
  
  std::string image_dir = directory + std::to_string(id);
  std::string cmd = "find "+image_dir+"/* ! -name 'simx.vcd' -type f -exec rm -f {} +";
  system(cmd.c_str());
}

uint32_t verilator::save(uint32_t id) { 

  /*
   * This function generate a checkpoint from a running Verilator-based simulator.
   * The checkpoint is stored on a persistent storage in /tmp by default.
   * Each output directory contains a unique identifier to distinguish images.
   */
  if( id == 0 )
    id = unique_id++;
  else
    remove(id);
 
  int fd;
  std::string image_dir = directory + std::to_string(id);
  std::string log_file = std::string("dump.log");

  // 1. Prepare output directory
  if (!is_directory(image_dir)) {
    int check = mkdir(image_dir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    if (check == 0) {
      //printf("[SnapshotPlatform] Directory created\n");
    } else {
      klee_error("unable to create directory %s \n",
             image_dir.c_str());
      exit(0);
    }
  }
  fd = open(image_dir.c_str(), O_DIRECTORY);
  if(!fd)
    klee_error("unable to save verilator snapshot due bad output directory %s", image_dir.c_str());

  // 2. init criu options and connect
  criu_local_set_images_dir_fd(criu_options, fd);
  criu_local_set_log_file(criu_options, (char *)log_file.c_str());
  criu_local_set_pid(criu_options, pid);
  criu_local_set_leave_running(criu_options, false);
  criu_local_set_service_address(criu_options, "/tmp/localhost");
  int criu_fd = criu_connect(criu_options, false);
  criu_local_set_service_fd(criu_options, criu_fd);

  // 3. checkpoint process
  int ret = criu_local_dump(criu_options);

  // 4. checkpoint traces
  std::string cmd = "cp ./logs/simx.vcd " + image_dir;
  system(cmd.c_str());

  // 5. check returned status code
  if( ret < 0 ){
    what_error_mean(ret);
    klee_error("unable to checkpoint verilator process with pid %d ", pid);
  }

  // 6. snapshot shared memory / IPC
  snapshot_ipc(id);

  // 7. close all files before leaving
  close(criu_fd);
  close(fd);

  /*
   * When checkpointing a process while leaving it runnning, inconsistencies
   * may be introduced due to unsynchronised resources such as file system.
   * To avoid this, we suspend the process; checkpoint and then restore
   */
  restore(id);

  return id;
}

void verilator::restore(uint32_t id) {
  int fd, ret;

  std::string log_file = std::string("restore.log");
  std::string image_dir = directory + std::to_string(id);
  if (!is_directory(image_dir)) {
    klee_error("unable to reload snapshot due to unknown image "
        "directory\n");
  }
  fd = open(image_dir.c_str(), O_DIRECTORY);
  if( !fd )
    klee_error("unable create directory for saving hardware snapshot");

  int status;
  kill(pid, SIGINT);
  if (waitpid (pid, &status, 0) < 0) {
      //    perror ("waitpid");
  }

  //XXX: backup verilator traces to avoid inconsistencies
  std::string cmd = "cp " + image_dir + "/simx.vcd ./logs/simx.vcd";
  system(cmd.c_str());

  std::map<uint32_t, IPC_MESSAGE*>::iterator it;

  IPC_MESSAGE* dst = (IPC_MESSAGE*) ipc_ptr;
  IPC_MESSAGE* src = NULL;

  it = ipc_snapshots.find(id);
  if( it != ipc_snapshots.end())
    src = it->second;
  else
    klee_error("unable to restore hw snapshot, verilator ipc snapshot missing");

  dst->irq_status  = src->irq_status  ;
  dst->address     = src->address     ;
  dst->type        = src->type        ;
  dst->value       = src->value       ;
  dst->status      = src->status      ;

  //printf("irq_status    = %c\n", src->irq_status);
  //printf("address       = %08x\n", src->address);
  //printf("type          = %c\n", src->type);
  //printf("value         = %d\n", src->value);
  //printf("status        = %c\n", src->status);

  //ipc_snapshots.insert(std::pair<uint32_t, IPC_MESSAGE*>(id, dst)); 

  int attempt = 1;
  do {
  
    if( attempt == 5)
      klee_error("verilator target failed to restore snapshot... timeout after  %d attempt\n", attempt);

    attempt++;

    criu_local_set_service_address(criu_options, "/tmp/localhost");
    int criu_fd = criu_connect(criu_options, false);
    criu_local_set_service_fd(criu_options, criu_fd); 
    criu_local_set_leave_running(criu_options, false);
    criu_local_set_pid(criu_options, pid);
  
    criu_local_set_images_dir_fd(criu_options, fd);
    criu_local_set_log_file(criu_options, (char *)log_file.c_str());
    ret = criu_local_restore(criu_options);
    close(criu_fd);
   
  } while( ret < 0 );

  while(process_done == 0) { asm("nop"); }
  process_done = 0;

  close(fd);
}


