#ifndef HWTargets_H
#define HWTargets_H

#include <set>
#include <string>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <arpa/inet.h>  //inet_addr
#include <iostream>     //cout
#include <netdb.h>      //hostent
#include <stdio.h>      //printf
#include <string.h>     //strlen
#include <string>       //string
#include <sys/socket.h> //socket

#include <chrono> // std::chrono::seconds
#include <thread> // std::this_thread::sleep_for

#include "klee/Internal/Support/ErrorHandling.h"

enum TargetPlatform { JTAG, FPGA, SIMULATOR };

class Peripheral {
public:
  std::string name;

  TargetPlatform platform;

  std::string command;

  // std::string address;
  //
  // int port;

  pid_t pid;

  int64_t id;

  // int socket;

  int cmd_fifo;

  int data_fifo;

  int sync_mem;

  Peripheral(std::string _n, std::string _c, TargetPlatform _p, int64_t _id,
             int _pid)
      : name(_n), platform(_p), command(_c), pid(_pid), id(_id){};

  bool operator<(const Peripheral &peripheral) const {
    return peripheral.name.compare(name);
  }
};

class HWTargets {
public:
  uint64_t add_new_target(std::string name, std::string command,
                          std::string platform_name, int pid) {
    TargetPlatform enum_platform;

    if (platform_name.compare("FPGA") == 0)
      enum_platform = FPGA;

    if (platform_name.compare("SIMULATOR") == 0)
      enum_platform = SIMULATOR;

    if (platform_name.compare("JTAG") == 0)
      enum_platform = JTAG;

    Peripheral *peripheral =
        new Peripheral(name, command, enum_platform, peripheral_id, pid);

    peripherals.insert(
        std::pair<uint64_t, Peripheral *>(peripheral_id, peripheral));

    uint64_t res = peripheral_id;
    peripheral_id++;

    return res;
  };

  Peripheral *resolve(int64_t peripheral_id) {
    auto res = peripherals.find(peripheral_id);

    if (res != peripherals.end()) {
      Peripheral *per = res->second;
      return per;
    }

    return NULL;
  }

  Peripheral *resolve(std::string name) {
    auto it = peripherals.begin();
    auto end = peripherals.end();

    for (; it != end; it++) {
      Peripheral *peripheral = it->second;
      if (peripheral->name.compare(name) == 0)
        return peripheral;
    }

    return NULL;
  }

  bool start(int64_t peripheral_id) {
    auto res = peripherals.find(peripheral_id);

    if (res != peripherals.end()) {
      Peripheral *per = res->second;

      // pid_t pid = fork(); /* Create a child process */
      //
      // switch (pid) {
      //   case -1: /* Error */
      //     std::cerr
      //         << "[Klee::HWTargets] Unable to start targets... fork() failed.\n";
      //     std::exit(1);
      //   case 0:                              /* Child process */
      //     execl(per->command.c_str(), "\0"); /* Execute the program */
      //     /* execl doesn't return unless there's an error */
      //     std::cerr << "[Klee::HWTargets] Target " << per->name
      //               << " failed to start" << std::endl;
      //     std::cerr << per->command << std::endl;
      //     std::exit(1);
      //   default: /* Parent process */
      //     std::cout << "[Klee::HWTargets] Process created with pid " << pid
      //               << " and id " << per->id << std::endl;
      //     per->pid = getpid();

          // std::this_thread::sleep_for(std::chrono::seconds(3));
          connect_to_target(per);

        return true;
      // }
  }
  else {
    std::cout << "[Klee::HWTargets] Unknown peripheral id " << peripheral_id
              << std::endl;
    return false;
  }
};

bool connect_to_target(Peripheral *peripheral) {

  const char *cmd_fifo_path = "/home/nasm/cmd_fifo";

  const char *data_fifo_path = "/home/nasm/data_fifo";

  const char *sync_path = "/sync_fifo";

  peripheral->cmd_fifo = open(cmd_fifo_path, O_WRONLY);

  peripheral->data_fifo = open(data_fifo_path, O_RDONLY);

  // Create a shared memory object
  peripheral->sync_mem = shm_open(sync_path, O_CREAT|O_RDWR, 0777);
  if(peripheral->sync_mem == -1) {
    perror("Failed to open sync_mem for simulator synchronisation");
    exit(-1);
  }

  // Set the size
	ftruncate(peripheral->sync_mem, 256);

  // Map the shared memory in this process
	sync_mem_ptr = (u_char *) mmap(NULL, 256, PROT_READ|PROT_WRITE, MAP_SHARED, peripheral->sync_mem, 0);
  if (sync_mem_ptr == MAP_FAILED) {
    perror("Failed to map sync_mem for simulator synchronisation");
    exit(-1);
  }

  // peripheral->sync_fifo = open(sync_fifo_path, O_RDONLY);

  // Create socket
  // peripheral->socket = socket(AF_INET, SOCK_STREAM, 0);
  // if (peripheral->socket == -1) {
  //   close_all();
  //   perror("[Klee::HWTargets] Could not create socket");
  // }
  //
  // std::cout << "[Klee::HWTargets] Socket created\n";
  //
  // struct sockaddr_in address;
  // bzero(&address, sizeof(address));
  // address.sin_family = AF_INET;
  // address.sin_port = htons(2017);
  // if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) <= 0) {
  //   std::cout << "[Klee::HWTargets] Bad address for " << peripheral->address
  //             << "\n";
  //   close_all();
  //   exit(0);
  // }
  //
  // socklen_t addr_len = sizeof address;
  // if (connect(peripheral->socket, (struct sockaddr *)&address, addr_len) <
  //     0) {
  //   std::cout << "[Klee::HWTargets] Connection failed\n";
  //   close_all();
  //   exit(0);
  // }
  //
  // std::cout << "[Klee::HWTargets] Connected\n";
  return true;
}

bool send_data(Peripheral *peripheral, char *data) {
  // Send some data
  // if (send(peripheral->socket, data, 12, 0) < 0) {
  //   close_all();
  //   perror("[Klee::HWTargets] Send failed : ");
  //   return false;
  // }

  while(sync_mem_ptr[0] == 1) {printf("blocking write...\n");}
  sync_mem_ptr[0] = 1;

  int res;
  do {
    res = write(peripheral->cmd_fifo, data, 12);
  } while (res <= 0);

  // while (write(peripheral->sync_fifo, "1", 1) == 0)
  //   ;

  sync();

  return true;
}

char *receive(Peripheral *peripheral) {
  char *buffer = new char[5];

  // uint32_t attempt = 0;
  // int n = 0;

  // Receive a reply from the server
  // do {
  //   n = recv(peripheral->socket, buffer, sizeof(buffer), 0);
  //   attempt++;
  //   if(attempt > 3) {
  //     close_all();
  //     puts("[Klee::HWTargets] recv failed");
  //     exit(0);
  //   }
  // } while( n < 0);

  while (read(peripheral->data_fifo, buffer, 5) == 0)
    ;

  sync_mem_ptr[1] = 0;

  sync();

  return buffer;
}

void write_to(int64_t target_id, uint32_t data, uint32_t address) {

  klee::klee_message("[HWTargets] Writing %d at %d to target id %ld", data,
                     address, target_id);

  Peripheral *peripheral = resolve(target_id);
  if (peripheral == NULL) {
    close_all();
    klee::klee_error("[HWTargets] Unknown target id %ld", target_id);
  }
  char *packet = (char *)malloc(sizeof(uint8_t) * 12);
  std::memset(packet, 0, 12);

  uint8_t header[] = {87, 0x00, 0x00, 0x00};

  std::memcpy(&packet[0], (void *)header, sizeof header);
  std::memcpy(&packet[4], (void *)&address, sizeof address);
  std::memcpy(&packet[8], (void *)&data, sizeof data);

  send_data(peripheral, packet);

  free(packet);
}

uint32_t read_from(int64_t target_id, uint32_t address) {
  uint32_t data = 0;

  klee::klee_message("[HWTargets] Reading %d at %d to target id %ld", data,
                     address, target_id);

  Peripheral *peripheral = resolve(target_id);
  if (peripheral == NULL) {
    close_all();
    klee_error("[HWTargets] Unknown target id %ld", target_id);
  }
  char *packet = (char *)malloc(sizeof(uint8_t) * 12);
  std::memset(packet, 0, 12);

  uint8_t header[] = {82, 0x00, 0x00, 0x00};

  std::memcpy(packet, (void *)header, sizeof header);
  std::memcpy(&packet[4], (void *)&address, sizeof address);
  std::memcpy(&packet[8], (void *)&data, sizeof data);

  send_data(peripheral, packet);

  free(packet);

  char *buffer = receive(peripheral);

  // extract first 4 byte
  // data = *((uint32_t *)response);
  data = 0;
  data |= buffer[0] << 24;
  data |= buffer[1] << 16;
  data |= buffer[2] << 8;
  data |= buffer[3];

  std::cout << " decoded value : " << data << std::endl;

  delete buffer;

  return data;
}

void close_all() {
  int status;

  for (auto it = peripherals.begin(); it != peripherals.end(); ++it)
    if ((*it).second->pid == 0)
      continue;
    else {
      // while (!WIFEXITED(status)) {
      waitpid((*it).second->pid, &status,
              0); /* Wait for the process to complete */
      std::cout << "[Klee::HWTargets] Process exited with "
                << WEXITSTATUS(status) << "\n";
      //   break;
      // }
    }
}

private:
std::map<uint64_t, Peripheral *> peripherals;

uint64_t peripheral_id = 0;

u_char *sync_mem_ptr;

}; // namespace inception

#endif

