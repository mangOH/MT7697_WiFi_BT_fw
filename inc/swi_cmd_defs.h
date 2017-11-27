#ifndef SWI_CMD_DEFS_H
#define SWI_CMD_DEFS_H

#define LEN_TO_WORD(x)			((x) / sizeof(uint32_t) + ((x) % sizeof(uint32_t) ? 1:0))
#define LEN32_ALIGNED(x)		(((x) / sizeof(uint32_t) + \
					 ((x) % sizeof(uint32_t) ? 1:0)) * sizeof(uint32_t))

typedef enum _mt7697_cmd_grp_e {
    MT7697_CMD_GRP_QUEUE = 0,
    MT7697_CMD_GRP_UART,
    MT7697_CMD_GRP_80211,
    MT7697_CMD_GRP_BT,
} mt7697_cmd_grp_e;

typedef struct __attribute__((__packed__, aligned(4))) _mt7697_cmd_hdr_t {
    uint16_t			len;
    uint8_t			grp;
    uint8_t			type;
} mt7697_cmd_hdr_t;

typedef struct __attribute__((__packed__, aligned(4))) _mt7697_rsp_hdr_t {
    mt7697_cmd_hdr_t		cmd;
    int32_t			result;
} mt7697_rsp_hdr_t;

#endif
