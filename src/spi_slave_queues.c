// stdlib
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// MTK
#include <hal_gpio.h>
#include <hal_spi_slave.h>

// FreeRTOS
#include <FreeRTOS.h>
#include <task.h>

// SWI
#include "bits.h"

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
#define COMMAND_REG_BUS_SIZE_OFFSET 1
#define COMMAND_REG_BUS_SIZE_WIDTH 2
#define COMMAND_REG_BUS_SIZE_VAL_WORD 0x2

#define COMMAND_REG_RW_OFFSET 0
#define COMMAND_REG_RW_WIDTH 1
#define COMMAND_REG_RW_VAL_READ 0
#define COMMAND_REG_RW_VAL_WRITE 1

#define STATUS_REG_BUSY_OFFSET 0
#define STATUS_REG_BUSY_WIDTH 1
#define STATUS_REG_BUSY_VAL_IDLE 0
#define STATUS_REG_BUSY_VAL_BUSY 1

#define IRQ_REG_IRQ_STATUS_OFFSET 0
#define IRQ_REG_IRQ_STATUS_WIDTH 1
#define IRQ_REG_IRQ_STATUS_VAL_INACTIVE 0
#define IRQ_REG_IRQ_STATUS_VAL_ACTIVE 1

#define S2M_MAILBOX_REG_MAILBOX_OFFSET 0
#define S2M_MAILBOX_REG_MAILBOX_WIDTH 7

#define M2S_MAILBOX_REG_MAILBOX_OFFSET 0
#define M2S_MAILBOX_REG_MAILBOX_WIDTH 7
// --> END SPI Slave Hardware Defines

#define NUM_CHANNELS 2

#define FLAGS_IN_USE_OFFSET     0
#define FLAGS_IN_USE_WIDTH      1

#define FLAGS_DIRECTION_OFFSET  1
#define FLAGS_DIRECTION_WIDTH   1

#define FLAGS_NUM_WORDS_OFFSET 16
#define FLAGS_NUM_WORDS_WIDTH  16

enum QueueDirection
{
    QUEUE_DIRECTION_MASTER_TO_SLAVE = 0,
    QUEUE_DIRECTION_SLAVE_TO_MASTER = 1,
};

struct QueueSpecification
{
    uint32_t flags;
    uint32_t base_address;
    uint32_t read_offset;
    uint32_t write_offset;
};


static ssize_t _circular_buffer_difference(uint32_t buffer_size, uint32_t from, uint32_t to);
static size_t _get_queue_capacity_in_words(const struct QueueSpecification* queue_specification);
static size_t _get_num_words_in_queue(const struct QueueSpecification* queue_specification);
static size_t _get_num_free_words_in_queue(const struct QueueSpecification* queue_specification);
static void _set_slave_to_master_mailbox(uint8_t bits);
static void _clear_master_to_slave_mailbox(uint8_t bits);
static void _notify_spi_master(void);
static struct QueueSpecification* _get_valid_queue(uint8_t channel);
static struct QueueSpecification* _get_valid_directed_queue(
    uint8_t channel, enum QueueDirection direction);
static void _spi_slave_interrupt_handler(void* data);




static uint32_t test_queue_m2s[16];
static uint32_t test_queue_s2m[8];

struct QueueSpecification queues[NUM_CHANNELS] __attribute__((__section__(".spi_slave"), unused)) =
{
    {
        .flags = (
            BF_DEFINE(1, FLAGS_IN_USE_OFFSET, FLAGS_IN_USE_WIDTH) |
            BF_DEFINE(QUEUE_DIRECTION_MASTER_TO_SLAVE, FLAGS_DIRECTION_OFFSET, FLAGS_DIRECTION_WIDTH) |
            BF_DEFINE(ARRAY_SIZE(test_queue_m2s), FLAGS_NUM_WORDS_OFFSET, FLAGS_NUM_WORDS_WIDTH)),
        .base_address = (uint32_t)test_queue_m2s,
        .read_offset = 0,
        .write_offset = 0,
    },
    {
        .flags = (
            BF_DEFINE(1, FLAGS_IN_USE_OFFSET, FLAGS_IN_USE_WIDTH) |
            BF_DEFINE(QUEUE_DIRECTION_SLAVE_TO_MASTER, FLAGS_DIRECTION_OFFSET, FLAGS_DIRECTION_WIDTH) |
            BF_DEFINE(ARRAY_SIZE(test_queue_s2m), FLAGS_NUM_WORDS_OFFSET, FLAGS_NUM_WORDS_WIDTH)),
        .base_address = (uint32_t)test_queue_s2m,
        .read_offset = 0,
        .write_offset = 0,
    },
};

// Stores the task handles associated with each channel.
static TaskHandle_t tasks[NUM_CHANNELS];


void spi_queue_init(void)
{
    // EPT is used for pin muxing, so no need to configure muxing for SPI slave

    hal_spi_slave_status_t slave_status;
    hal_spi_slave_config_t spi_configure = {
        .phase = HAL_SPI_SLAVE_CLOCK_PHASE0,
        .polarity = HAL_SPI_SLAVE_CLOCK_POLARITY0
    };
    slave_status = hal_spi_slave_init(HAL_SPI_SLAVE_0, &spi_configure);
    configASSERT(slave_status == HAL_SPI_SLAVE_STATUS_OK);

    slave_status =
        hal_spi_slave_register_callback(HAL_SPI_SLAVE_0, _spi_slave_interrupt_handler, NULL);
    configASSERT(slave_status == HAL_SPI_SLAVE_STATUS_OK);
}

size_t spi_queue_read(uint8_t channel, uint32_t* buffer, size_t num_words)
{
    struct QueueSpecification* qs = _get_valid_directed_queue(channel, QUEUE_DIRECTION_SLAVE_TO_MASTER);
    const uint32_t buffer_num_words = BF_GET(qs->flags, FLAGS_NUM_WORDS_OFFSET, FLAGS_NUM_WORDS_WIDTH);

    // take a copy of write_offset so it isn't changed as this code executes
    const uint32_t write_offset = qs->write_offset;
    size_t words_read = 0;
    if (qs->read_offset > write_offset)
    {
        const size_t words_until_end =  buffer_num_words - qs->read_offset;
        const uint32_t* read_from = (uint32_t*)(qs->base_address + (qs->read_offset * 4));
        const size_t num_words_to_read = (num_words <= words_until_end) ? num_words : words_until_end;
        memcpy(&buffer[words_read], read_from, num_words_to_read * 4);
        words_read += num_words_to_read;
        qs->read_offset += num_words_to_read;
        if (qs->read_offset == buffer_num_words)
        {
            // If we have read to the end, then set the read pointer to the beginning
            qs->read_offset = 0;
        }
    }

    if (words_read < num_words)
    {
        const size_t words_until_write_ptr = write_offset - qs->read_offset;
        const uint32_t* read_from = (uint32_t*)(qs->base_address + (qs->read_offset * 4));
        const size_t wanted_words = num_words - words_read;
        const size_t num_words_to_read =
            (wanted_words <= words_until_write_ptr) ? wanted_words : words_until_write_ptr;
        memcpy(&buffer[words_read], read_from, num_words_to_read * 4);
        words_read += num_words_to_read;
        qs->read_offset += num_words_to_read;
    }

    if (words_read > 0)
    {
        _set_slave_to_master_mailbox(1 << channel);
        _notify_spi_master();
    }

    return words_read;
}

size_t spi_queue_write(uint8_t channel, const uint32_t* buffer, size_t num_words)
{
    struct QueueSpecification* qs = _get_valid_directed_queue(channel, QUEUE_DIRECTION_MASTER_TO_SLAVE);
    const uint32_t buffer_num_words = BF_GET(qs->flags, FLAGS_NUM_WORDS_OFFSET, FLAGS_NUM_WORDS_WIDTH);

    // take a copy of write_offset so it isn't changed as this code executes
    const uint32_t read_offset = qs->read_offset;
    size_t words_written = 0;

    if (qs->write_offset > read_offset)
    {
        const size_t words_until_end = buffer_num_words - qs->write_offset;
        const size_t words_available_for_write =
            (read_offset == 0) ? (words_until_end - 1) : words_until_end;
        const size_t num_words_to_write =
            (num_words <= words_available_for_write) ? num_words : words_available_for_write;
        uint32_t* const write_to = (uint32_t*)(qs->base_address + (qs->write_offset * 4));
        memcpy(write_to, &buffer[words_written], num_words_to_write);
        words_written += num_words_to_write;
        qs->write_offset += words_written;
        if (qs->write_offset == buffer_num_words)
        {
            qs->write_offset = 0;
        }
    }

    if (qs->write_offset < read_offset && words_written < num_words)
    {
        const size_t words_until_read = (qs->read_offset - qs->write_offset) - 1;
        const size_t num_words_to_write = (num_words <= words_until_read) ? num_words : words_until_read;
        uint32_t* const write_to = (uint32_t*)(qs->base_address + (qs->write_offset * 4));
        memcpy(write_to, &buffer[words_written], num_words_to_write);
        words_written += num_words_to_write;
        qs->write_offset += words_written;
    }

    if (words_written > 0)
    {
        _set_slave_to_master_mailbox(1 << channel);
        _notify_spi_master();
    }

    return words_written;
}

size_t spi_queue_get_capacity_in_words(uint8_t channel)
{
    struct QueueSpecification* qs = _get_valid_queue(channel);
    return _get_queue_capacity_in_words(qs);
}

size_t spi_queue_get_num_words_used(uint8_t channel)
{
    struct QueueSpecification* qs = _get_valid_queue(channel);
    return _get_num_words_in_queue(qs);
}

size_t spi_queue_get_num_free_words(uint8_t channel)
{
    struct QueueSpecification* qs = _get_valid_queue(channel);
    return _get_num_free_words_in_queue(qs);
}

static ssize_t _circular_buffer_difference
(
    uint32_t buffer_size,
    uint32_t from,
    uint32_t to
)
{
    configASSERT(from < buffer_size);
    configASSERT(to < buffer_size);

    if (from <= to)
    {
        return (to - from);
    }
    else
    {
        return ((buffer_size - from) + to);
    }
}

static size_t _get_queue_capacity_in_words(
    const struct QueueSpecification* queue_specification)
{
    return BF_GET(queue_specification->flags, FLAGS_NUM_WORDS_OFFSET, FLAGS_NUM_WORDS_WIDTH) - 1;
}

static size_t _get_num_words_in_queue
(
    const struct QueueSpecification* queue_specification
)
{
    return _circular_buffer_difference(
        BF_GET(queue_specification->flags, FLAGS_NUM_WORDS_OFFSET, FLAGS_NUM_WORDS_WIDTH),
        queue_specification->read_offset,
        queue_specification->write_offset);
}

static size_t _get_num_free_words_in_queue
(
    const struct QueueSpecification* queue_specification
)
{
    return _get_queue_capacity_in_words(queue_specification) - _get_num_words_in_queue(queue_specification);
}

static void _set_slave_to_master_mailbox(uint8_t bits)
{
    *SPIS_REG_MAILBOX_S2M =
        BF_DEFINE(bits, S2M_MAILBOX_REG_MAILBOX_OFFSET, S2M_MAILBOX_REG_MAILBOX_WIDTH);
}

static void _clear_master_to_slave_mailbox(uint8_t bits)
{
    // Write 1 to clear
    *SPIS_REG_MAILBOX_M2S =
        BF_DEFINE(bits, M2S_MAILBOX_REG_MAILBOX_OFFSET, M2S_MAILBOX_REG_MAILBOX_WIDTH);
}

static void _notify_spi_master(void)
{
    const hal_gpio_status_t r = hal_gpio_toggle_pin(HAL_GPIO_6);
    configASSERT(r == HAL_GPIO_STATUS_OK);
}


static struct QueueSpecification* _get_valid_queue
(
    uint8_t channel
)
{
    configASSERT(channel < NUM_CHANNELS);
    struct QueueSpecification* qs = &(queues[channel]);
    configASSERT(BF_GET(qs->flags, FLAGS_IN_USE_OFFSET, FLAGS_IN_USE_WIDTH) == 1);

    return qs;
}

static struct QueueSpecification* _get_valid_directed_queue
(
    uint8_t channel,
    enum QueueDirection direction
)
{
    struct QueueSpecification* qs = GetValidQueue(channel);
    enum QueueDirection actual_direction =
        BF_GET(qs->flags, FLAGS_DIRECTION_OFFSET, FLAGS_DIRECTION_WIDTH);
    configASSERT(actual_direction == direction);

    return qs;
}

static void _spi_slave_interrupt_handler(void* data)
{
    // 1. Read a copy of the master to slave mailbox
    // 2. Clear the bits that were read as being set
    // 3. Perform handling for each of the bits that were set
    // This order of operations ensures that no notifications are lost.
    const uint8_t m2s_mailbox_val = *SPIS_REG_MAILBOX_M2S;
    *SPIS_REG_MAILBOX_M2S = m2s_mailbox_val;

    // Notify the task associated with the channel
    for (int i = 0; i < NUM_CHANNELS; i++)
    {
        if ((m2s_mailbox_val & (1 << i)) && tasks[i] != NULL)
        {
            // TODO: do we need to pass the pxHigherPriorityTaskWoken parameter and make decisions
            // based on its value?
            vTaskNotifyGiveFromISR(tasks[i], NULL);
        }
    }
}
