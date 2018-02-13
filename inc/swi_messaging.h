#ifndef SWI_MESSAGING_H
#define SWI_MESSAGING_H

#include "FreeRTOS.h"

#define ARRAY_SIZE(_a_) (sizeof(_a_) / sizeof(_a_[0]))

typedef struct _swi_m2s_info_t swi_m2s_info_t;

#define LEN_TO_WORD(x)   ((x) / sizeof(uint32_t) + ((x) % sizeof(uint32_t) ? 1 : 0))
#define LEN32_ALIGNED(x) ( \
        ((x) / sizeof(uint32_t) + ((x) % sizeof(uint32_t) ? 1:0)) * sizeof(uint32_t))

typedef enum _mt7697_cmd_grp_e {
    MT7697_CMD_GRP_QUEUE = 0,
    MT7697_CMD_GRP_UART,
    MT7697_CMD_GRP_80211,
    MT7697_CMD_GRP_BT,
} mt7697_cmd_grp_e;

typedef struct __attribute__((__packed__, aligned(4))) _mt7697_cmd_hdr_t {
    uint16_t len;
    uint8_t  grp;
    uint8_t  type;
} mt7697_cmd_hdr_t;

typedef struct __attribute__((__packed__, aligned(4))) _mt7697_rsp_hdr_t {
    mt7697_cmd_hdr_t cmd;
    int32_t          result;
} mt7697_rsp_hdr_t;

enum mt7697_cmd_size_validator_type {
    CMD_SIZE_VALIDATOR_ABSOLUTE,
    CMD_SIZE_VALIDATOR_FUNCTION,
};

struct mt7697_cmd_size_validator {
    enum mt7697_cmd_size_validator_type type;
    union {
        size_t expected_size;
        bool (*is_valid_size)(const mt7697_cmd_hdr_t *);
    } v;
};

struct mt7697_command_entry {
    int enum_value;
    int32_t (*command_handler)(swi_m2s_info_t* m2s_info, mt7697_cmd_hdr_t *cmd);
    const char *command_handler_name;
    const char *enum_name;
    struct mt7697_cmd_size_validator command_size_validator;
};

#define CREATE_VALIDATOR_ABSOLUTE(_size) { \
    .type=CMD_SIZE_VALIDATOR_ABSOLUTE,     \
    .v={.expected_size=_size}              \
}
#define CREATE_VALIDATOR_FUNCTION(_fn) {.type=CMD_SIZE_VALIDATOR_FUNCTION, .v={.is_valid_size=_fn}}


#define CREATE_CMD_ENTRY(_e, _handler, _cmd_size_validator) { \
    .enum_value=_e,                              \
    .command_handler=_handler,                   \
    .command_handler_name=#_handler,             \
    .enum_name=#_e,                              \
    .command_size_validator=_cmd_size_validator, \
}

int swi_process_cmd(swi_m2s_info_t* m2s_info, const struct mt7697_command_entry cmd_defs[],
                    size_t num_cmd_defs, mt7697_cmd_hdr_t *cmd);
#endif // SWI_MESSAGING_H
