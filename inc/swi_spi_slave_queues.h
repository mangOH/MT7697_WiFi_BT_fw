#ifndef SWI_SPI_SLAVE_QUEUES_H
#define SWI_SPI_SLAVE_QUEUES_H

#include <stdint.h>
#include <semphr.h>
#include "event_groups.h"
#include "hal_gpio.h"

#include "swi_s2m.h"
#include "swi_m2s.h"
#include "swi_cmd_defs.h"

#define ARRAY_SIZE(_a_) (sizeof(_a_) / sizeof(_a_[0]))

// --> BEGIN SPI Slave Hardware Defines
// Register pointer macro
#define REG_PTR(_addr_) ((volatile uint32_t*)(_addr_))

// Number based access
#define SPIS_AHB_REG00 REG_PTR(0x21000700)
#define SPIS_AHB_REG01 REG_PTR(0x21000704)
#define SPIS_AHB_REG02 REG_PTR(0x21000708)
#define SPIS_AHB_REG03 REG_PTR(0x2100070C)
#define SPIS_AHB_REG04 REG_PTR(0x21000710)
#define SPIS_AHB_REG05 REG_PTR(0x21000714)
#define SPIS_AHB_REG06 REG_PTR(0x21000718)
#define SPIS_AHB_REG07 REG_PTR(0x2100071C)
#define SPIS_AHB_REG08 REG_PTR(0x21000740)

// Purpose based aliases
#define SPIS_REG_READ_DATA   SPIS_AHB_REG00
#define SPIS_REG_WRITE_DATA  SPIS_AHB_REG01
#define SPIS_REG_BUS_ADDRESS SPIS_AHB_REG02
#define SPIS_REG_COMMAND     SPIS_AHB_REG03
#define SPIS_REG_STATUS      SPIS_AHB_REG04
#define SPIS_REG_IRQ         SPIS_AHB_REG05
#define SPIS_REG_MAILBOX_S2M SPIS_AHB_REG06
#define SPIS_REG_MAILBOX_M2S SPIS_AHB_REG07
#define SPIS_REG_HW_CONFIG   SPIS_AHB_REG08

// Register fields
#define COMMAND_REG_BUS_SIZE_OFFSET     1
#define COMMAND_REG_BUS_SIZE_WIDTH      2
#define COMMAND_REG_BUS_SIZE_VAL_WORD   0x2

#define COMMAND_REG_RW_OFFSET           0
#define COMMAND_REG_RW_WIDTH            1
#define COMMAND_REG_RW_VAL_READ         0
#define COMMAND_REG_RW_VAL_WRITE        1

#define STATUS_REG_BUSY_OFFSET          0
#define STATUS_REG_BUSY_WIDTH           1
#define STATUS_REG_BUSY_VAL_IDLE        0
#define STATUS_REG_BUSY_VAL_BUSY        1

#define IRQ_REG_IRQ_STATUS_OFFSET       0
#define IRQ_REG_IRQ_STATUS_WIDTH        1
#define IRQ_REG_IRQ_STATUS_VAL_INACTIVE 0
#define IRQ_REG_IRQ_STATUS_VAL_ACTIVE   1

#define S2M_MAILBOX_REG_MAILBOX_OFFSET  0
#define S2M_MAILBOX_REG_MAILBOX_WIDTH   6

#define M2S_MAILBOX_REG_MAILBOX_OFFSET  0
#define M2S_MAILBOX_REG_MAILBOX_WIDTH   7
// --> END SPI Slave Hardware Defines

#define NUM_CHANNELS           2

#define FLAGS_IN_USE_OFFSET    0
#define FLAGS_IN_USE_WIDTH     1

#define FLAGS_DIRECTION_OFFSET 1
#define FLAGS_DIRECTION_WIDTH  1

#define FLAGS_NUM_WORDS_OFFSET 16
#define FLAGS_NUM_WORDS_WIDTH  16

#define QUEUE_WORD_SIZE        4096

#define QUEUE_WIFI_M2S         0
#define QUEUE_WIFI_S2M         1

#define mt7697_queue_init_rsp_t  mt7697_rsp_hdr_t
#define mt7697_queue_reset_rsp_t mt7697_rsp_hdr_t

typedef enum _swi_queue_dir_e {
    QUEUE_DIRECTION_M2S = 0,
    QUEUE_DIRECTION_S2M = 1,
} swi_queue_dir_e;

typedef enum _mt7697q_cmd_types_e {
    MT7697_CMD_QUEUE_INIT = 0,
    MT7697_CMD_QUEUE_INIT_RSP,
    MT7697_CMD_QUEUE_UNUSED,
    MT7697_CMD_QUEUE_RESET,
    MT7697_CMD_QUEUE_RESET_RSP,
} mt7697q_cmd_types_e;

typedef struct __attribute__((packed, aligned(4))) _mt7697_queue_init_req_t {
    mt7697_cmd_hdr_t cmd;
    uint32_t         m2s_ch;
    uint32_t         s2m_ch;
} mt7697_queue_init_req_t;

typedef struct __attribute__((packed, aligned(4))) _mt7697_queue_unused_req_t {
    mt7697_cmd_hdr_t cmd;
    uint32_t         m2s_ch;
    uint32_t         s2m_ch;
} mt7697_queue_unused_req_t;

typedef struct __attribute__((packed, aligned(4))) _mt7697_queue_reset_req_t {
    mt7697_cmd_hdr_t cmd;
    uint32_t         m2s_ch;
    uint32_t         s2m_ch;
} mt7697_queue_reset_req_t;

typedef struct _swi_spi_queue_spec_t {
    uint32_t flags;
    uint32_t base_address;
    uint16_t read_offset;
    uint16_t reserved1;
    uint16_t write_offset;
    uint16_t reserved2;
} swi_spi_queue_spec_t;

typedef struct _swi_spi_queue_data_t {
    uint32_t queue[QUEUE_WORD_SIZE];

    union {
        swi_s2m_info_t s2m;
        swi_m2s_info_t m2s;
    } dir;

    swi_spi_queue_spec_t *qs;
    uint32_t              ch;
} swi_spi_queue_data_t;

typedef struct _swi_spi_queue_info_t {
    swi_spi_queue_data_t data[NUM_CHANNELS];
    hal_gpio_data_t      gpio_irq;
} swi_spi_queue_info_t;

int32_t swi_spi_queue_init(swi_spi_queue_info_t*);
size_t swi_spi_queue_read(void*, uint32_t*, size_t);
size_t swi_spi_queue_get_capacity_in_words(const swi_spi_queue_spec_t*);
size_t swi_spi_queue_get_num_words_used(const swi_spi_queue_spec_t*);
size_t swi_spi_queue_get_num_free_words(const swi_spi_queue_spec_t*);

#endif // SWI_SPI_SLAVE_QUEUES_H
