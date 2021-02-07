/*******************************************************************************
    @Author: Corteggiani Nassim <Corteggiani>
    @Email:  nassim.corteggiani@maximintegrated.com
    @Filename: Device.h
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

#ifndef USB3DAP
#define USB3DAP

#include <exception>
#include <libusb-1.0/libusb.h>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "klee/Expr/Expr.h"
#include <thread>

using namespace klee;

#include "target.hpp"
#include "usb_device.hpp"

class usb3dap : public Target{
public:
  usb3dap();

  ~usb3dap();
  
  klee::ref<Expr> read(klee::ref<Expr> address, klee::Expr::Width w);

  void write(klee::ref<Expr>  address, klee::ref<Expr> data, klee::Expr::Width w);

  void init();

  void shutdown(); 
  
  uint32_t save(uint32_t id=0);

  void restore(uint32_t id);
  
  void remove(uint32_t id) {};

  bool has_pending_irq(uint32_t state_id);
  
  int32_t get_active_irq(uint32_t state_id);
  
  void irq_ack();

  void halt() {};
  
  void resume() {};

private:
  std::thread* irq_handler_thread;

  device* io;

  device* io_irq;

  bool initialized;

  void write(uint32_t address, uint32_t data);

  uint32_t read(uint32_t address);

  uint32_t snapshot_length;

  uint32_t snapshot_index;

  uint32_t snp_counter;

};

#endif /* device_hpp */
