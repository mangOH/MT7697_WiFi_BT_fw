#ifndef SPI_SLAVE_QUEUES_H
#define SPI_SLAVE_QUEUES_H

#include <stdint.h>
#include <semphr.h>
#include "event_groups.h"
#include "hal_gpio.h"

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
#define COMMAND_REG_BUS_SIZE_OFFSET 	1
#define COMMAND_REG_BUS_SIZE_WIDTH 	2
#define COMMAND_REG_BUS_SIZE_VAL_WORD 	0x2

#define COMMAND_REG_RW_OFFSET 		0
#define COMMAND_REG_RW_WIDTH 		1
#define COMMAND_REG_RW_VAL_READ 	0
#define COMMAND_REG_RW_VAL_WRITE 	1

#define STATUS_REG_BUSY_OFFSET 		0
#define STATUS_REG_BUSY_WIDTH 		1
#define STATUS_REG_BUSY_VAL_IDLE 	0
#define STATUS_REG_BUSY_VAL_BUSY 	1

#define IRQ_REG_IRQ_STATUS_OFFSET 	0
#define IRQ_REG_IRQ_STATUS_WIDTH 	1
#define IRQ_REG_IRQ_STATUS_VAL_INACTIVE 0
#define IRQ_REG_IRQ_STATUS_VAL_ACTIVE 	1

#define S2M_MAILBOX_REG_MAILBOX_OFFSET 	0
#define S2M_MAILBOX_REG_MAILBOX_WIDTH 	6

#define M2S_MAILBOX_REG_MAILBOX_OFFSET 	0
#define M2S_MAILBOX_REG_MAILBOX_WIDTH 	7
// --> END SPI Slave Hardware Defines

#define NUM_CHANNELS 			2

#define FLAGS_IN_USE_OFFSET     	0
#define FLAGS_IN_USE_WIDTH      	1

#define FLAGS_DIRECTION_OFFSET  	1
#define FLAGS_DIRECTION_WIDTH   	1

#define FLAGS_NUM_WORDS_OFFSET 		16
#define FLAGS_NUM_WORDS_WIDTH  		16

#define QUEUE_BLOCKED_WRITER		( 1 << 0 )
#define QUEUE_UNBLOCK_WRITER		( 1 << 1 )
#define LEN_TO_WORD(x)			((x) / sizeof(uint32_t) + ((x) % sizeof(uint32_t) ? 1:0))
#define LEN32_ALIGNED(x)		(((x) / sizeof(uint32_t) + \
					 ((x) % sizeof(uint32_t) ? 1:0)) * sizeof(uint32_t))

#define QUEUE_TASK_STACK_SIZE		4096
#define QUEUE_MSG_LO_PRIORITY		0
#define QUEUE_MSG_HI_PRIORITY		1
#define QUEUE_MSG_POOL_LEN		34
#define QUEUE_MSG_POOL_HI_LEN		2
#define QUEUE_SENDQ_LEN			64
#define QUEUE_WORD_SIZE			4096

#define mt7697_queue_init_rsp		mt7697_rsp_hdr
#define mt7697_queue_reset_rsp		mt7697_rsp_hdr

enum QueueDirection {
    QUEUE_DIRECTION_M2S = 0,
    QUEUE_DIRECTION_S2M = 1,
};

enum mt7697q_cmd_grp {
    MT7697_CMD_GRP_QUEUE = 0,
    MT7697_CMD_GRP_80211,
    MT7697_CMD_GRP_BT,
};

enum mt7697q_cmd_types {
    MT7697_CMD_QUEUE_INIT = 0,
    MT7697_CMD_QUEUE_INIT_RSP,
    MT7697_CMD_QUEUE_UNUSED,
    MT7697_CMD_QUEUE_RESET,
    MT7697_CMD_QUEUE_RESET_RSP,
};

struct mt7697_cmd_hdr {
    uint16_t			len;
    uint8_t			grp;
    uint8_t			type;
} __attribute__((__packed__, aligned(4)));

struct mt7697_rsp_hdr {
    struct mt7697_cmd_hdr	cmd;
    int32_t			result;
} __attribute__((__packed__, aligned(4)));

struct mt7697_queue_init_req {
    struct mt7697_cmd_hdr	cmd;
    uint32_t			m2s_ch;
    uint32_t			s2m_ch;
} __attribute__((packed, aligned(4)));

struct mt7697_queue_unused_req {
    struct mt7697_cmd_hdr	cmd;
    uint32_t			m2s_ch;
    uint32_t			s2m_ch;
} __attribute__((packed, aligned(4)));

struct mt7697_queue_reset_req {
    struct mt7697_cmd_hdr	cmd;
    uint32_t			m2s_ch;
    uint32_t			s2m_ch;
} __attribute__((packed, aligned(4)));

struct QueueSpecification {
    uint32_t 			flags;
    uint32_t 			base_address;
    uint16_t 			read_offset;
    uint16_t			reserved1;
    uint16_t 			write_offset;
    uint16_t			reserved2;   
};

struct QueueTask {
    TaskHandle_t 		hndl;
    char 			name[configMAX_TASK_NAME_LEN];
};

struct QueueMemPool {
    SemaphoreHandle_t		lock;
    uint8_t*                    start;
    uint8_t*                    end;
    uint8_t*			alloc_ptr;
    uint8_t*			free_ptr;
};

struct QueueInfo {
    struct QueueTask 		task;
    struct QueueMemPool         msg_pool;
    struct QueueMemPool         hi_msg_pool;
    SemaphoreHandle_t		lock;
    EventGroupHandle_t 		evtGrp;
    QueueHandle_t               sendQ;
};

struct QueueMain {
    struct QueueInfo            info[NUM_CHANNELS];
    uint32_t 			m2s_q[QUEUE_WORD_SIZE];
    uint32_t 			s2m_q[QUEUE_WORD_SIZE];
    struct mt7697_cmd_hdr 	cmd_hdr;
    hal_gpio_data_t 		gpio_irq;
};

int32_t spi_queue_init(void);
uint8_t* spi_queue_pool_alloc_msg(uint8_t, uint8_t, uint16_t);
int32_t spi_queue_send_req(uint8_t, const struct mt7697_rsp_hdr*);
int32_t spi_queue_send_req_from_isr(uint8_t, const struct mt7697_rsp_hdr*);
size_t spi_queue_read(uint8_t, uint32_t*, size_t);
size_t spi_queue_read(uint8_t, uint32_t*, size_t);
size_t spi_queue_get_capacity_in_words(uint8_t);
size_t spi_queue_get_num_words_used(uint8_t);
size_t spi_queue_get_num_free_words(uint8_t);

#endif // SPI_SLAVE_QUEUES_H
