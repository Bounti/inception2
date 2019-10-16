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
#include "device/device.hpp"

#include "klee/Internal/Support/ErrorHandling.h"
#include "klee/Expr.h"

#include <cassert>
#include <iomanip>
#include <iostream>
#include <sstream>

using namespace std;
using namespace klee;

libusb_device_handle *device::handle = NULL;

bool device::initialized = false;

device::device(uint16_t p_vid, uint16_t p_pid, uint32_t p_interface,
               uint8_t out, uint8_t in) {

  timeout = 500;

  timeout_is_error = true;

  entrypoint_download = out;
  entrypoint_upload = in;

  vid = p_vid;

  pid = p_pid;

  interface = p_interface;

  buffer_limit = 1024;
}

device::~device() {}

void device::close(void) { device_close(); }

void device::device_open() {

  int cnt, idx, errCode;
  libusb_device **devs;

  if (libusb_init(&context) < 0)
    return;

  cnt = libusb_get_device_list(context, &devs);

  for (idx = 0; idx < cnt; idx++) {

    if (libusb_get_device_descriptor(devs[idx], &descriptor) != 0)
      continue;

    if (descriptor.idVendor != vid || descriptor.idProduct != pid) {
      continue;
    }

    dev = devs[idx];

    errCode = libusb_open(devs[idx], &device::handle);

    if (errCode) {
      device::handle = NULL;
      klee_error("libusb_open() failed with %s", libusb_error_name(errCode));
    }

    break;
  }
  if (cnt >= 0)
    libusb_free_device_list(devs, 1);
}

void device::device_close() {
  klee_message("closing device \n");
  /* Close device */
  libusb_close(device::handle);
  libusb_exit(context);
}

void device::init(void) {

  if (device::initialized)
    return;

  device::initialized = true;

  int32_t retval;

  device_open();

  if (!device::handle) {
    klee_error("unable to find an attached JTAG debugger device");
    return;
  }

  dev = libusb_get_device(device::handle);

  if (vid != descriptor.idVendor) {
    klee_error("unexpected id vendor for JTAG debugger");
  }

  if (pid != descriptor.idProduct) {
    klee_error("unexpected id product for JTAG debugger");
  }

  is_open = 1;

  busnum = libusb_get_bus_number(dev);
  devaddr = libusb_get_device_address(dev);

  retval = libusb_claim_interface(device::handle, interface);
  if (retval == 0) {
    klee_message("driver successfully claimed interface");
  } else {

    switch (retval) {
    case LIBUSB_ERROR_NOT_FOUND:
      klee_error("JTAG debugger is busy");
      break;
    case LIBUSB_ERROR_BUSY:
      klee_error("JTAG debugger detected but busy");
      break;
    case LIBUSB_ERROR_NO_DEVICE:
      klee_error("JTAG debugger is not connected any more");
      break;
    default:
      klee_error("JTAG debugger cannot be attached");
      break;
    }
    device::handle = NULL;
    return;
  }

  // libusb_clear_halt(this->handle, 0x81);
  // libusb_clear_halt(this->handle, 0x01);

  return;
}

uint32_t device::io(uint8_t endpoint, uint8_t *buffer, uint32_t size) {

  int32_t retval;
  int32_t transferred;
  int32_t attempt = 0;

  // do {
  if ((retval = libusb_bulk_transfer(device::handle, endpoint, buffer, size,
                                     &transferred, timeout)) != 0) {
    switch (retval) {
    case LIBUSB_ERROR_TIMEOUT:
      if(timeout_is_error) 
        klee_error("JTAG debugger: timeout error");
      break;
    case LIBUSB_ERROR_PIPE:
      klee_error("JTAG debugger: pipe error");
      break;
    case LIBUSB_ERROR_OVERFLOW:
      klee_error("JTAG debugger: overflow error");
      break;
    case LIBUSB_ERROR_NO_DEVICE:
      klee_error("JTAG debugger: device disconnected");
      break;
    case LIBUSB_ERROR_IO:
      klee_error("JTAG debugger: device io error");
      break;
    default:
      klee_error("JTAG debugger: unexpected error");
      break;
    }
    // sleep(1);
    // attempt++;
    //   } else if (size == 0)
    //     attempt++;
    //   else
    //     break;
    // } while (attempt < 2);

    // if (attempt >= 1) {
    // return 0;
    // cout << termcolor::red
    //      << "driver failed to communicate with device ... endpoint : " <<
    //      hex
    //      << endpoint << endl;
    // throw std::runtime_error(
    //     "driver failed to communicate with device ... endpoint\n");
  }

  return transferred;
}

void device::send(uint8_t *data, uint32_t size) {

  size = io(entrypoint_download, data, size);

  //std::stringstream info;

  //info << "0x" << std::hex << std::setfill('0');
  //for (unsigned int i = 0; i < size; i++) {
  //  info << std::setw(2) << static_cast<unsigned>(data[i]);
  //  info << " ";
  //}
  //cout << termcolor::green << "JTAG > " << info.str() << endl;
}

void device::receive(uint8_t *data, uint32_t size) {

  uint32_t received = 0;
  int32_t attempt = 0;
  uint32_t recv_size = 0;

  do {
    recv_size = io(entrypoint_upload, data + received, size - received);
    if (recv_size == 0) {
      attempt++;
    } else {
      received += recv_size;
      //cout << termcolor::white << "received :" << received << endl;
    }
  } while (received < size && attempt < 1);

  //printf("<%016lx", (unsigned long int)data);
  //cout << termcolor::green << "JTAG < " << info.str() << endl;
}

void device::write(uint32_t address, uint32_t data) {

  //uint8_t* buffer = new uint8_t[12];

  //uint32_t cmd = 0x14000001;

  address = address & ((uint32_t)~0x1);

  unsigned int long packet = 0x0000000000000000;
  packet |= ((unsigned long int)data << 32) | (unsigned long int)address;
  uint8_t* i8_packet_w = (uint8_t*) &packet;

  //buffer[0] = (cmd >> 24);
  //buffer[1] = (cmd >> 16);
  //buffer[2] = (cmd >> 8);
  //buffer[3] = (cmd & 0xFF);

  //buffer[4] = (address >> 24);
  //buffer[5] = (address >> 16);
  //buffer[6] = (address >> 8);
  //buffer[7] = (address & 0xFF);

  //buffer[8] = (data >> 24);
  //buffer[9] = (data >> 16);
  //buffer[10] = (data >> 8);
  //buffer[11] = (data & 0xFF);

  //send(buffer, 12);
  send(i8_packet_w, 8);

  printf("Writing to %08x -> %08x\n", address, data);

  //cmd->push_back((uint32_t) 0x24000001);
  //cmd->push_back((uint32_t) address);
}

void device::write(klee::ref<Expr>  address, klee::ref<Expr> data, klee::Expr::Width w) {
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

uint32_t device::read(uint32_t address) {
  
  unsigned int long packet = 0x0000000000000000;
  packet |= (unsigned long int)address | (unsigned long int)0x1;
  uint8_t* i8_packet_r = (uint8_t*) &packet; 
 
  //uint8_t* buffer = new uint8_t[8];
  uint8_t* out_buffer = new uint8_t[8];
  uint32_t ret = 0;

  //uint32_t cmd = 0x24000001;

  //buffer[0] = (cmd >> 24);
  //buffer[1] = (cmd >> 16);
  //buffer[2] = (cmd >> 8);
  //buffer[3] = (cmd & 0xFF);

  //buffer[4] = (address >> 24);
  //buffer[5] = (address >> 16);
  //buffer[6] = (address >> 8);
  //buffer[7] = (address & 0xFF);
 
  //send(buffer, 8);
  send(i8_packet_r, 8);
 
  receive(out_buffer, 8);

  //free(buffer);

  ret  |= out_buffer[7] << 24;
  ret  |= out_buffer[6] << 16;
  ret  |= out_buffer[5] << 8;
  ret  |= out_buffer[4];
  
  printf("Reading from %08x -> %08x\n", address, ret);

  return ret;
  //cmd->push_back((uint32_t) 0x14000001);
  //cmd->push_back((uint32_t) address);
  //cmd->push_back((uint32_t) data);
}

klee::ref<Expr> device::read(klee::ref<Expr> address, klee::Expr::Width w) {
  
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

