#ifndef SPI_SLAVE_QUEUES_H
#define SPI_SLAVE_QUEUES_H

#include <stdint.h>

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
#define S2M_MAILBOX_REG_MAILBOX_WIDTH 	7

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

#define QUEUE_TASK_STACK_SIZE		4096
#define QUEUE_WORD_SIZE			1024
#define QUEUE_LEN_TO_WORD(x)		((x) / sizeof(uint32_t) + ((x) % sizeof(uint32_t) ? 1:0))
#define QUEUE_LEN32_ALIGNED(x)		(((x) / sizeof(uint32_t) + \
					 ((x) % sizeof(uint32_t) ? 1:0)) * sizeof(uint32_t))
#define QUEUE_WIFI_SLAVE_TO_MASTER	1

enum QueueDirection {
    QUEUE_DIRECTION_MASTER_TO_SLAVE = 0,
    QUEUE_DIRECTION_SLAVE_TO_MASTER = 1,
};

struct QueueSpecification {
    uint32_t 	flags;
    uint32_t 	base_address;
    uint32_t 	read_offset;
    uint32_t 	write_offset;
};

enum mt7697_cmd_grp {
	MT7697_CMD_GRP_QUEUE = 0,
	MT7697_CMD_GRP_80211,
	MT7697_CMD_GRP_BT,
};

enum mt7697_queue_cmd_types {
	MT7697_CMD_INIT = 0,
	MT7697_CMD_UNUSED,
	MT7697_CMD_RESET,
};

int32_t spi_queue_init(void);
size_t spi_queue_read(uint8_t, uint32_t*, size_t);
size_t spi_queue_read(uint8_t, uint32_t*, size_t);
size_t spi_queue_write(uint8_t, const uint32_t*, size_t);
size_t spi_queue_get_capacity_in_words(uint8_t);
size_t spi_queue_get_num_words_used(uint8_t);
size_t spi_queue_get_num_free_words(uint8_t);

#endif // SPI_SLAVE_QUEUES_H
