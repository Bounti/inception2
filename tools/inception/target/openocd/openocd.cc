#include "openocd.hpp"

#include <stdint.h>
#include <stdlib.h>
#include <chrono>
#include <thread>
#include "klee/Internal/Support/ErrorHandling.h"
#include "klee/Expr.h"

using namespace klee;

static const char openocd_startup_tcl[] = {
#include "openocd/startup_tcl.inc"
0 /* Terminate with zero */
};

struct command_context *global_cmd_ctx;

struct command_context *setup_command_handler(Jim_Interp *interp)
{
        struct command_context *cmd_ctx = command_init(openocd_startup_tcl, interp);

        /* register subsystem commands */
        typedef int (*command_registrant_t)(struct command_context *cmd_ctx_value);
        static const command_registrant_t command_registrants[] = {
                //&openocd_register_commands,
                //&log_register_commands,
                &transport_register_commands,
                &interface_register_commands,
                &target_register_commands,
                //&pld_register_commands,
                //&cti_register_commands,
                &dap_register_commands,
                NULL
        };
        for (unsigned i = 0; NULL != command_registrants[i]; i++) {
                int retval = (*command_registrants[i])(cmd_ctx);
                if (ERROR_OK != retval) {
                  if (NULL == cmd_ctx)
                    return NULL;
                  free(cmd_ctx);
                }
        }

        global_cmd_ctx = cmd_ctx;

        return cmd_ctx;
}

klee::ref<Expr> openocd::read(klee::ref<Expr> address, klee::Expr::Width w) {
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

uint32_t openocd::read(uint32_t address) {

  target_addr_t addr = address; 
 
  //uint8_t buffer[4] = {0};
  uint8_t *buffer = (uint8_t*)calloc(1, 4);
  if (buffer == NULL) {
    klee_error("openocd target: unexpected error during write");
    return 0;
  }
  
  int retval = target_read_memory(target, addr, 4, 1, buffer);
  if (retval != ERROR_OK) {
    klee_error("openocd target: unexpected error during read");
  }

  unsigned int value = target_buffer_get_u32(target, buffer);

  //printf("read at %08x value %08x ret %d\n", addr, value, retval);

  return value;
}

void openocd::write(uint32_t address, uint32_t data) {
  
  target_addr_t addr = address;
  
  uint8_t *buffer = (uint8_t*)calloc(1, 4);
  if (buffer == NULL) {
    klee_error("openocd target: unexpected error during write");
    return;
  }
  //uint8_t buffer[4] = {0};
 
  uint8_t write_buffer[4];
 
  target_buffer_set_u32(target, write_buffer, data);
 
  int retval = target_write_memory(target, addr, 4, 1, write_buffer);
  if (retval != ERROR_OK) {
    printf("Failed to write!");
  }
}

void openocd::write(klee::ref<Expr>  address, klee::ref<Expr> data, klee::Expr::Width w) {
  
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

void openocd::init() {
	int ret;

	cmd_ctx = setup_command_handler(NULL);

	if (util_init(cmd_ctx) != ERROR_OK){
    klee_error("openocd target: util init failed"); 
		return;
  }

	if (ioutil_init(cmd_ctx) != ERROR_OK) {
    klee_error("openocd target: ioutil init failed"); 
		return;
  }

	command_context_mode(cmd_ctx, COMMAND_CONFIG);
	command_set_output_handler(cmd_ctx, configuration_output_handler, NULL);

  log_init();

  char* argv[3] = {"./openocd", "-s", "/home/nasm/Inception2/build/scripts/"};

	/* Start the executable meat that can evolve into thread in future. */
	if (parse_cmdline_args(cmd_ctx, 3, argv) != ERROR_OK) {
    klee_error("openocd target: fail to parse cmdline"); 
		return;
  }

	if (server_preinit() != ERROR_OK) {
    klee_error("openocd target: fail to pre-init server"); 
		return;
  }

  //char *c1 = alloc_printf("script {%s}", "board/lpc1850_spifi_generic.cfg");
  //char *c2 = alloc_printf("script {%s}", "interface/jlink.cfg");
  
  char *c1 = alloc_printf("script {%s}", "target/zynq_7000.cfg");
  char *c2 = alloc_printf("script {%s}", "interface/ftdi/digilent_jtag_hs3.cfg");

  add_config_command(c2);
  add_config_command(c1);

  ret = parse_config_file(cmd_ctx);
	if (ret == ERROR_COMMAND_CLOSE_CONNECTION) {
    klee_error("openocd target: fail to parse config file"); 
		return;
	} else if (ret != ERROR_OK) {
    klee_error("openocd target: fail to parse config file"); 
		return;
	}

	ret = command_run_line(cmd_ctx, "target init");
	if (ERROR_OK != ret) {
    klee_error("openocd target: fail to run command target init"); 
		return;
  }

	ret = adapter_init(cmd_ctx);
	if (ret != ERROR_OK) {
    klee_error("openocd target: fail to setup debug adapter"); 
		return;
	}

	/* "transport init" verifies the expected devices are present;
	 * for JTAG, it checks the list of configured TAPs against
	 * what's discoverable, possibly with help from the platform's
	 * JTAG event handlers.  (which require COMMAND_EXEC)
	 */
	command_context_mode(cmd_ctx, COMMAND_EXEC);

	ret = command_run_line(cmd_ctx, "transport init");
	if (ERROR_OK != ret) {
    klee_error("openocd target: fail to run trasport init");
		return;
  }

	ret = command_run_line(cmd_ctx, "dap init");
	if (ERROR_OK != ret) {
    klee_error("openocd target: fail to run dap init");
		return; 
  }

	if (target_examine() != ERROR_OK) {
    klee_error("openocd target: fail to examine target");
		return; 
  }
  
  target = get_current_target(cmd_ctx);
  if(target == NULL) {
    klee_error("openocd target: fail to get current target");
		return; 
  }
  
  if( target_halt(target) != ERROR_OK) {
    klee_error("openocd target: fail to halt target");
		return; 
  }

  target_wait_state(target, TARGET_HALTED, 5000);

  //std::this_thread::sleep_for(std::chrono::seconds(5));

  return;
}

void openocd::close() {
  int ret;
  
  unregister_all_commands(cmd_ctx, NULL);

  /* free all DAP and CTI objects */
  dap_cleanup_all();
  arm_cti_cleanup_all();

  adapter_quit();

  /* Shutdown commandline interface */
  if (!cmd_ctx)
    return;

  Jim_FreeInterp(cmd_ctx->interp);
  free(cmd_ctx);

  free_config();

  if (ERROR_FAIL == ret)
    return;

}

