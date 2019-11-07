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

using namespace std;
using namespace klee;

//libusb_device_handle *usb3dap::handle = NULL;

usb3dap::usb3dap() {
  io_irq = new device(0x04b4, 0x00f1, 0, 0x02, 0x82);
  io = new device(0x04b4, 0x00f1, 0, 0x01, 0x81);

  io_irq->accept_timeout();
}

usb3dap::~usb3dap() {}

void usb3dap::init() {  
  io_irq->init();
  io->init();
};

void usb3dap::shutdown() {
  //io->close();
  io_irq->close();
}

bool usb3dap::has_pending_irq() {
  uint8_t buffer[8] = {0};
  uint32_t value=0;
  uint32_t error_code;

  io_irq->receive(buffer, 8);

  error_code |= buffer[0] << 24;
  error_code |= buffer[1] << 16;
  error_code |= buffer[2] << 8;
  error_code |= buffer[3];

  value |= buffer[4] << 24;
  value |= buffer[5] << 16;
  value |= buffer[6] << 8;
  value |= buffer[7];

  if(value != 0) {
    printf("[Trace] Interrupt error_code : %08x\n", error_code);
    printf("[Trace] Interrupt ID : %08x\n", value);
    printf("[Trace] Interrupt ID : %08x\n", value);
  }
  return false;
}

void usb3dap::write(uint32_t address, uint32_t data) {

  address = address & ((uint32_t)~0x1);

  unsigned int long packet = 0x0000000000000000;
  packet |= ((unsigned long int)data << 32) | (unsigned long int)address;
  uint8_t* i8_packet_w = (uint8_t*) &packet;

  io->send(i8_packet_w, 8);

  printf("Writing to %08x -> %08x\n", address, data);
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

  printf("Reading from %08x -> %08x\n", address, ret);

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

