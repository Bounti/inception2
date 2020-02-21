/*******************************************************************************
@Author: Corteggiani Nassim <Corteggiani>
@Email:  nassim.corteggiani@maximintegrated.com
@Filename: Device.cpp
@Last modified by:   noname
@Last modified time: 16-Mar-2017
@License: GPLv3

Copyright (C) 2017 Maxim Integrated Products, Inc., All Rights Reserved.
Copyright (C) 2017 Corteggiani Nassim <Corteggiani>

*
*    This program is free software: you can redistribute it and/or modify      *
*    it under the terms of the GNU General Public License as published by      *
*    the Free Software Foundation, either version 3 of the License, or         *
*    (at your option) any later version.                                       *
*    This program is distributed in the hope that it will be useful,           *
*    but WITHOUT ANY WARRANTY; without even the implied warranty of            *
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
*    GNU General Public License for more details.                              *
*    You should have received a copy of the GNU General Public License         *
*    along with this program.  If not, see <http://www.gnu.org/licenses/>.     *
*                                                                              *
*                                                                              *
********************************************************************************/
#include "usb3dap.hpp"
#include "usb_device.hpp"

#include "klee/Internal/Support/ErrorHandling.h"
#include "klee/Expr.h"

#include <cassert>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>
#include <stack>

#define SNP_MAX 500

using namespace std;
using namespace klee;

//libusb_device_handle *usb3dap::handle = NULL;

static bool irq_running;

static bool irq_lock;

typedef struct IRQ_MSG{
  uint32_t irq_id;
  uint32_t state_id;
  IRQ_MSG (uint32_t _irq_id, uint32_t _state_id): state_id(_state_id), irq_id(_irq_id){ }
}IRQ_MSG;

static std::vector<IRQ_MSG*> irq_stack;

static void irq_handler(device* io_irq) {

  while(irq_running) {

    if(irq_lock)
      continue;

    uint8_t buffer[8] = {0};
    uint32_t value=0;
    uint32_t error_code;

    io_irq->receive(buffer, 8);

    error_code |= buffer[3] << 24;
    error_code |= buffer[2] << 16;
    error_code |= buffer[1] << 8;
    error_code |= buffer[0];

    value |= buffer[7] << 24;
    value |= buffer[6] << 16;
    value |= buffer[5] << 8;
    value |= buffer[4];

    //if(error_code != value)
    //  klee_error("usb3dap target received an unexpected message %08x - %08x", value, error_code);

    printf("irq code on device %08x with state id %08x raw %08x \n", (value & 7), (value >> 3 ), value);
    irq_stack.push_back(new IRQ_MSG(value&7, (value >> 3)));
 }
}


usb3dap::usb3dap() {
  io_irq = new device(0x04b4, 0x00f1, 0, 0x02, 0x82);
  io = new device(0x04b4, 0x00f1, 0, 0x01, 0x81);

  io_irq->accept_timeout();
  io_irq->set_timeout(0);
}

usb3dap::~usb3dap() {}

void usb3dap::init() {
  io_irq->init();
  io->init();

  snapshot_length = 10752+32+64;

  snapshot_index = 0x00100000;

  snp_counter = 0;

  irq_lock = false;

  irq_running = true;
  irq_handler_thread = new std::thread(irq_handler, io_irq);
  irq_handler_thread->detach();
};

void usb3dap::shutdown() {
  io->close();
  irq_running = false;
  //while(irq_running == false);
  //io_irq->close();
}

int32_t usb3dap::get_active_irq(uint32_t state_id) {

  //uint32_t address = 0x43c20000;
  //uint32_t value = (read(address) & 0x7);
  for(auto it=irq_stack.begin(); it!=irq_stack.end(); it++) {
    IRQ_MSG* irq_msg = *it;
    if( irq_msg->state_id == state_id ) {
      printf("IRQ has id %d and has state id %08x\n", irq_msg->irq_id, irq_msg->state_id);
      irq_stack.erase(it);
      return irq_msg->irq_id;
    }
  }
  return 0;
  //return (int32_t)(value & 0x7) + 1;
}

bool usb3dap::has_pending_irq(uint32_t state_id) {

  for(auto msg : irq_stack)
    if( msg->state_id == state_id )
      return true;
  return false;
}

void usb3dap::write(uint32_t address, uint32_t data) {

  address = address & ((uint32_t)~0x1);

  unsigned int long packet = 0x0000000000000000;
  packet |= ((unsigned long int)data << 32) | (unsigned long int)address;
  uint8_t* i8_packet_w = (uint8_t*) &packet;

  io->send(i8_packet_w, 8);

  //printf("Writing to %08x -> %08x\n", address, data);
}


uint32_t usb3dap::read(uint32_t address) {

  unsigned int long packet = 0x0000000000000000;
  packet |= (unsigned long int)address | (unsigned long int)0x1;
  uint8_t* i8_packet_r = (uint8_t*) &packet;

  uint8_t* out_buffer = new uint8_t[8];
  uint32_t ret = 0;

  io->send(i8_packet_r, 8);

  io->receive(out_buffer, 8);

  ret  |= out_buffer[7] << 24;
  ret  |= out_buffer[6] << 16;
  ret  |= out_buffer[5] << 8;
  ret  |= out_buffer[4];

  //if(address != 0x43c20000)
  //  printf("Reading from %08x -> %08x\n", address, ret);

  return ret;
}

klee::ref<Expr> usb3dap::read(klee::ref<Expr> address, klee::Expr::Width w) {

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

void usb3dap::write(klee::ref<Expr> address, klee::ref<Expr> data, klee::Expr::Width w) {
  uint32_t new_val = 0, b_address = 0;

  ConstantExpr *address_ce = dyn_cast<ConstantExpr>(address);
  if(!address_ce)
    klee_error("unable to forward symbolic address");
  uint64_t concrete_address = address_ce->getZExtValue();

  ConstantExpr *value_ce = dyn_cast<ConstantExpr>(data);
  if(!value_ce)
    klee_error("unable to forward symbolic value");
  uint64_t concrete_value = value_ce->getZExtValue();

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

void usb3dap::irq_ack(){
  write(0x43c20000, 0x4);
}

uint32_t usb3dap::save(uint32_t id) {

  irq_lock = true;

  if(id == 0) {
    id = ++snp_counter;

    // set a watermark on hardware so that we can identify precisely from where the interrupt are coming
    write(0x43c20014, id);

    printf("watermark on device with id %08x\n", read(0x43c20014));
  }
  //return id;

  uint32_t from = snapshot_index+((snapshot_length*SNP_MAX)/8);
  uint32_t to   = snapshot_index+((snapshot_length*id)/8);

  klee_message("        saving snapshot %d - saving snapshot at %08x and loading one at %08x", id, to, from);

  // from
  write(0x43c00000, from);
  // to
  write(0x43c00004, to);
  // size
  write(0x43c00008, snapshot_length);
  // start stop
  write(0x43c0000C, 0);
  write(0x43c0000C, 1);
  write(0x43c0000C, 0);

  while(read(0x43c00010) == 0);
  //sleep(0.2);

  restore(id);

  return id;
}

void usb3dap::restore(uint32_t id) {
  //return;

  irq_lock = true;

  uint32_t from = snapshot_index+((snapshot_length*id)/8);
  uint32_t to   = snapshot_index+((snapshot_length*SNP_MAX)/8);

  klee_message("        restoring snapshot %d - saving snapshot at %08x and loading one at %08x", id, to, from);

  // from
  write(0x43c00000, from);
  // to
  write(0x43c00004, to);
  // size
  write(0x43c00008, snapshot_length);
  // start stop
  write(0x43c0000C, 0);
  write(0x43c0000C, 1);
  write(0x43c0000C, 0);

  while(read(0x43c00010) != 1);
  //sleep(0.2);

  unsigned int state_id = read(0x43c20014);
  if( state_id != id)
    klee_error("hardware state is inconsistent... observed state id %d; expected %d\nclosing analysis", state_id, id);

  irq_lock = false;
}

