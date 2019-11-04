#ifndef OPENOCD_TARGET
#define OPENOCD_TARGET

#include "target.hpp"

extern "C" {

#define ERROR_OK              (0)
#define ERROR_NO_CONFIG_FILE  (-2)
#define ERROR_BUF_TOO_SMALL   (-3)
#define ERROR_FAIL            (-4)
#define ERROR_WAIT            (-5)
#define ERROR_TIMEOUT_REACHED (-6)
#define ERROR_COMMAND_CLOSE_CONNECTION		(-600)
struct command;

extern int unregister_all_commands(struct command_context *cmd_ctx,
                struct command *parent);


struct command_context;

/** The type signature for command context's output handler. */
typedef int (*command_output_handler_t)(struct command_context *context,
                const char *line);

enum target_state {
        TARGET_UNKNOWN = 0,
        TARGET_RUNNING = 1,
        TARGET_HALTED = 2,
        TARGET_RESET = 3,
        TARGET_DEBUG_RUNNING = 4,
};

enum command_mode {
        COMMAND_EXEC,
        COMMAND_CONFIG,
        COMMAND_ANY,
};

struct target;

typedef struct Jim_Interp;

struct command_context {
        Jim_Interp *interp;
        enum command_mode mode;
        struct command *commands;
        struct target *current_target;
                /* The target set by 'targets xx' command or the latest created */
        struct target *current_target_override;
                /* If set overrides current_target
                 * It happens during processing of
                 *      1) a target prefixed command
                 *      2) an event handler
                 * Pay attention to reentrancy when setting override.
                 */
        command_output_handler_t output_handler;
        void *output_handler_priv;
};

typedef uint32_t target_addr_t;

extern struct target *get_current_target(struct command_context *cmd_ctx);

extern int target_read_memory(struct target *target, target_addr_t address, uint32_t size, uint32_t count, uint8_t *buffer);

extern uint32_t target_buffer_get_u32(struct target *target, const uint8_t *buffer);

extern void target_buffer_set_u32(struct target *target, uint8_t *buffer, uint32_t value);

extern int target_write_memory(struct target *target,
                target_addr_t address, uint32_t size, uint32_t count, const uint8_t *buffer);

extern int target_examine_one(struct target *target);

extern void Jim_FreeInterp (Jim_Interp *i);

extern void adapter_quit();

extern void arm_cti_cleanup_all();

extern void dap_cleanup_all();

extern int target_examine();

extern int adapter_init(struct command_context *cmd_ctx);

extern int command_run_line(struct command_context *context, char *line);

extern int parse_config_file(struct command_context *cmd_ctx);

extern void add_config_command(const char *cfg);

extern char *alloc_printf(const char *fmt, ...);

extern int server_preinit(void);

extern int parse_cmdline_args(struct command_context *cmd_ctx,
                int argc, char *argv[]);

extern void command_set_output_handler(struct command_context *context,
                command_output_handler_t output_handler, void *priv);

extern int configuration_output_handler(struct command_context *cmd_ctx,
                const char *line);

extern int command_context_mode(struct command_context *context, enum command_mode mode);

extern int ioutil_init(struct command_context *cmd_ctx);

extern int util_init(struct command_context *cmd_ctx);

extern int target_register_commands(struct command_context *cmd_ctx);

extern int dap_register_commands(struct command_context *cmd_ctx);

extern int interface_register_commands(struct command_context *cmd_ctx);

extern int transport_register_commands(struct command_context *cmd_ctx);

extern struct command_context *command_init(const char *startup_tcl, Jim_Interp *interp);

extern void free_config(void);

extern void log_init(void);

extern int target_halt(struct target *target);

extern int target_wait_state(struct target *target, enum target_state state, int ms);
}

class openocd : public Target {
  private:
  struct command_context *cmd_ctx;

  struct target *target;

  public:
  void write(uint32_t address, uint32_t data);

  uint32_t read(uint32_t address);
  
  klee::ref<Expr> read(klee::ref<Expr> address, klee::Expr::Width w);

  void write(klee::ref<Expr>  address, klee::ref<Expr> data, klee::Expr::Width w);

  void init();

  void shutdown();
  
  uint32_t save(uint32_t id=0) { return 0;};

  void restore(uint32_t id) {};
  
  bool has_pending_irq() { return false;};

  int32_t get_active_irq() { return -1;};

  void irq_ack() {};

  void remove(uint32_t id) {};

  void resume() {};

  void halt() {};

};

#endif
