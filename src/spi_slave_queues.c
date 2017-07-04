// stdlib
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

// MTK
#include <hal_gpio.h>
#include <hal_spi_slave.h>

// FreeRTOS
#include <FreeRTOS.h>
#include <task.h>

// SWI
#include "bits.h"
#include "spi_slave_queues.h"
#include "spi_slave_wifi.h"

static ssize_t _circular_buffer_difference(uint32_t buffer_size, uint32_t from, uint32_t to);
static size_t _get_queue_capacity_in_words(const struct QueueSpecification* queue_specification);
static size_t _get_num_words_in_queue(const struct QueueSpecification* queue_specification);
static size_t _get_num_free_words_in_queue(const struct QueueSpecification* queue_specification);
static int32_t _set_slave_to_master_mailbox(uint8_t bits);
static void _clear_master_to_slave_mailbox(uint8_t bits);
static void _notify_spi_master(void);
static struct QueueSpecification* _get_valid_queue(uint8_t channel);
static struct QueueSpecification* _get_valid_directed_queue(
    uint8_t channel, enum QueueDirection direction);
static void _spi_slave_interrupt_handler(void* data);
static void spi_queue_task(void*);

// Stores the task handles associated with each channel.
static TaskHandle_t tasks[NUM_CHANNELS];
static SemaphoreHandle_t locks[NUM_CHANNELS];
static char taskName[NUM_CHANNELS][4];

static uint32_t test_queue_m2s[QUEUE_WORD_SIZE];
static uint32_t test_queue_s2m[QUEUE_WORD_SIZE];

struct QueueSpecification queues[NUM_CHANNELS] __attribute__((__section__(".spi_slave"), unused)) = {
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
            BF_DEFINE(QUEUE_DIRECTION_SLAVE_TO_MASTER, FLAGS_DIRECTION_OFFSET, FLAGS_DIRECTION_WIDTH) |
            BF_DEFINE(ARRAY_SIZE(test_queue_s2m), FLAGS_NUM_WORDS_OFFSET, FLAGS_NUM_WORDS_WIDTH)),
        .base_address = (uint32_t)test_queue_s2m,
        .read_offset = 0,
        .write_offset = 0,
    },
};

int32_t spi_queue_init(void)
{
    int ret = 0;

    // EPT is used for pin muxing, so no need to configure muxing for SPI slave
    LOG_I(common, "queues init");

    hal_gpio_status_t status = hal_gpio_set_output(HAL_GPIO_59, HAL_GPIO_DATA_LOW);
    if (status != HAL_GPIO_STATUS_OK) {
	LOG_W(common, "hal_gpio_set_output() failed(%d)", status);
	ret = -1;
	goto cleanup;
    }

    for (unsigned int i = 0; i < NUM_CHANNELS; i++) {
	struct QueueSpecification* qs = _get_valid_queue(i);
	configASSERT(qs);	

	LOG_I(common, "q(%d) flags(0x%08x) base(0x%08x) rd/wr offset(%d/%d)", 
		i, qs->flags, qs->base_address, qs->read_offset, qs->write_offset);

    	enum QueueDirection direction = BF_GET(qs->flags, FLAGS_DIRECTION_OFFSET, FLAGS_DIRECTION_WIDTH);
	if (QUEUE_DIRECTION_MASTER_TO_SLAVE == direction) {
	    snprintf(taskName[i], sizeof(taskName[i]), "q%d", i);
            BaseType_t xReturned = xTaskCreate(spi_queue_task,       
                    taskName[i], QUEUE_TASK_STACK_SIZE, (void*)i,
                    tskIDLE_PRIORITY, &tasks[i] );      
            if (xReturned != pdPASS) {
                LOG_W(common, "xTaskCreate(%d) failed(%d)", i, xReturned);
		ret = -1;
		goto cleanup;
            }

	    locks[i] = xSemaphoreCreateMutex();
        }
    }

    *SPIS_REG_MAILBOX_M2S = 0;
    *SPIS_REG_MAILBOX_S2M = 0;

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

cleanup:
    return ret;
}

size_t spi_queue_read(uint8_t channel, uint32_t* buffer, size_t num_words)
{
    struct QueueSpecification* qs = _get_valid_directed_queue(channel, QUEUE_DIRECTION_MASTER_TO_SLAVE);
    configASSERT(qs);
    const uint32_t buffer_num_words = BF_GET(qs->flags, FLAGS_NUM_WORDS_OFFSET, FLAGS_NUM_WORDS_WIDTH);

    // take a copy of write_offset so it isn't changed as this code executes
    const uint32_t write_offset = qs->write_offset;
    size_t words_read = 0;
    if (qs->read_offset > write_offset) {
        const size_t words_until_end =  buffer_num_words - qs->read_offset;
        const uint32_t* read_from = (uint32_t*)(qs->base_address + (qs->read_offset * sizeof(uint32_t)));
        const size_t num_words_to_read = (num_words <= words_until_end) ? num_words : words_until_end;

        memcpy(&buffer[words_read], read_from, num_words_to_read * sizeof(uint32_t));
        words_read += num_words_to_read;
	qs->read_offset += num_words_to_read;
        if (qs->read_offset == buffer_num_words) {
            // If we have read to the end, then set the read pointer to the beginning
            qs->read_offset = 0;
        }
    }

    if (words_read < num_words) {
        const size_t words_until_write_ptr = write_offset - qs->read_offset;
        const uint32_t* read_from = (uint32_t*)(qs->base_address + (qs->read_offset * sizeof(uint32_t)));
        const size_t wanted_words = num_words - words_read;
        const size_t num_words_to_read =
            (wanted_words <= words_until_write_ptr) ? wanted_words : words_until_write_ptr;

        memcpy(&buffer[words_read], read_from, num_words_to_read * sizeof(uint32_t));
        words_read += num_words_to_read;
        qs->read_offset += num_words_to_read;
    }

    return words_read;
}

size_t spi_queue_write(uint8_t channel, const uint32_t* buffer, size_t num_words)
{
    struct QueueSpecification* qs = _get_valid_directed_queue(channel, QUEUE_DIRECTION_SLAVE_TO_MASTER);
    configASSERT(qs);
    const uint32_t buffer_num_words = BF_GET(qs->flags, FLAGS_NUM_WORDS_OFFSET, FLAGS_NUM_WORDS_WIDTH);
    size_t words_written = 0;

    if (!BF_GET(qs->flags, FLAGS_IN_USE_OFFSET, FLAGS_IN_USE_WIDTH)) goto cleanup;
    if (spi_queue_get_num_free_words(channel) < num_words) goto cleanup;

    // take a copy of write_offset so it isn't changed as this code executes
    const uint32_t read_offset = qs->read_offset;

    if (qs->write_offset >= read_offset) {
        const size_t words_until_end = buffer_num_words - qs->write_offset;
        const size_t words_available_for_write =
            (read_offset == 0) ? (words_until_end - 1) : words_until_end;
        const size_t num_words_to_write =
            (num_words <= words_available_for_write) ? num_words : words_available_for_write;
        uint32_t* const write_to = (uint32_t*)(qs->base_address + (qs->write_offset * sizeof(uint32_t)));

        memcpy(write_to, &buffer[words_written], num_words_to_write * sizeof(uint32_t));
        words_written += num_words_to_write;
        qs->write_offset += num_words_to_write;
	num_words -= num_words_to_write;
        if (qs->write_offset == buffer_num_words) {
            qs->write_offset = 0;
        }
    }

    if ((qs->write_offset < read_offset) && (num_words > 0)) {
        const size_t words_until_read = (read_offset - qs->write_offset) - 1;
        const size_t num_words_to_write = (num_words <= words_until_read) ? num_words : words_until_read;
        uint32_t* const write_to = (uint32_t*)(qs->base_address + (qs->write_offset * sizeof(uint32_t)));

        memcpy(write_to, &buffer[words_written], num_words_to_write * sizeof(uint32_t));
        words_written += num_words_to_write;
	num_words -= num_words_to_write;
        qs->write_offset += num_words_to_write;
    }

    if (words_written > 0) {
        int32_t err = _set_slave_to_master_mailbox(1 << channel);
	if (err) {
	    LOG_E(common, "_set_slave_to_master_mailbox() failed(%d)", err);
	    words_written = -1;
	    goto cleanup;
  	}

        _notify_spi_master();
    }

cleanup:
    return words_written;
}

size_t spi_queue_get_capacity_in_words(uint8_t channel)
{
    struct QueueSpecification* qs = _get_valid_queue(channel);
    configASSERT(qs);
    return _get_queue_capacity_in_words(qs);
}

size_t spi_queue_get_num_words_used(uint8_t channel)
{
    struct QueueSpecification* qs = _get_valid_queue(channel);
    configASSERT(qs);
    return _get_num_words_in_queue(qs);
}

size_t spi_queue_get_num_free_words(uint8_t channel)
{
    struct QueueSpecification* qs = _get_valid_queue(channel);
    configASSERT(qs);
    return _get_num_free_words_in_queue(qs);
}

static ssize_t _circular_buffer_difference(uint32_t buffer_size, uint32_t from, uint32_t to)
{
    if (from >= buffer_size) {
	LOG_E(common, "invalid from(%u) >= size(%u)", from, buffer_size);
        configASSERT(from < buffer_size);
    }

    if (to >= buffer_size) {
        LOG_E(common, "invalid to(%u) >= size(%u)", to, buffer_size);
        configASSERT(to < buffer_size);
    }

    if (from <= to) {
        return (to - from);
    }
    else {
        return ((buffer_size - from) + to);
    }
}

static size_t _get_queue_capacity_in_words(
    const struct QueueSpecification* queue_specification)
{
    return BF_GET(queue_specification->flags, FLAGS_NUM_WORDS_OFFSET, FLAGS_NUM_WORDS_WIDTH) - 1;
}

static size_t _get_num_words_in_queue(const struct QueueSpecification* queue_specification)
{
    return _circular_buffer_difference(
        BF_GET(queue_specification->flags, FLAGS_NUM_WORDS_OFFSET, FLAGS_NUM_WORDS_WIDTH),
        queue_specification->read_offset,
        queue_specification->write_offset);
}

static size_t _get_num_free_words_in_queue(const struct QueueSpecification* queue_specification)
{
    return _get_queue_capacity_in_words(queue_specification) - _get_num_words_in_queue(queue_specification);
}

static int32_t _set_slave_to_master_mailbox(uint8_t bits)
{
    *SPIS_REG_MAILBOX_S2M =
        BF_DEFINE(bits, S2M_MAILBOX_REG_MAILBOX_OFFSET, S2M_MAILBOX_REG_MAILBOX_WIDTH);

    hal_gpio_status_t status = hal_gpio_set_output(HAL_GPIO_59, HAL_GPIO_DATA_HIGH);
    if (status != HAL_GPIO_STATUS_OK) {
	LOG_W(common, "hal_gpio_set_output() failed(%d)", status);
    }

    return status;
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

static struct QueueSpecification* _get_valid_queue(uint8_t channel)
{
    configASSERT(channel < NUM_CHANNELS);
    struct QueueSpecification* qs = &queues[channel];
    return qs;
}

static struct QueueSpecification* _get_valid_directed_queue(uint8_t channel, enum QueueDirection direction)
{
    struct QueueSpecification* qs = _get_valid_queue(channel);
    enum QueueDirection actual_direction =
        BF_GET(qs->flags, FLAGS_DIRECTION_OFFSET, FLAGS_DIRECTION_WIDTH);
    configASSERT(actual_direction == direction);

    return qs;
}

static void proc_queue_init_cmd(uint8_t channel)
{
    struct QueueSpecification* qs;

    LOG_I(common, "init queue(%u)", channel);
    qs = _get_valid_queue(channel + 1);
    configASSERT(qs);
    qs->flags |= BF_DEFINE(1, FLAGS_IN_USE_OFFSET, FLAGS_IN_USE_WIDTH);
}

static int32_t proc_queue_clr_intr_cmd(uint8_t channel)
{
    struct QueueSpecification* qs;
    int32_t ret = 0;

    LOG_I(common, "clear interrupt queue(%u) 22m mbx(0x%08x)", channel, *SPIS_REG_MAILBOX_S2M);
    qs = _get_valid_queue(channel + 1);
    configASSERT(qs);

    hal_gpio_status_t status = hal_gpio_set_output(HAL_GPIO_59, HAL_GPIO_DATA_LOW);
    if (status != HAL_GPIO_STATUS_OK) {
	LOG_W(common, "hal_gpio_set_output() failed(%d)", status);
	ret = -1;
	goto cleanup;
    }

cleanup:
    return ret;
}

static void proc_queue_unused_cmd(uint8_t channel)
{
    struct QueueSpecification* qs;

    LOG_I(common, "init queue(%u)", channel);
    qs = _get_valid_queue(channel + 1);
    configASSERT(qs);
    qs->flags &= ~BF_DEFINE(1, FLAGS_IN_USE_OFFSET, FLAGS_IN_USE_WIDTH);
}

static void proc_queue_reset_cmd(uint8_t channel)
{
    struct QueueSpecification* qs;

    LOG_I(common, "reset queue(%u)", channel);
    qs = _get_valid_queue(channel);
    configASSERT(qs);

    qs->read_offset = 0;
    qs->write_offset = 0;
	
    qs = _get_valid_queue(channel + 1);
    configASSERT(qs);

    qs->read_offset = 0;
    qs->write_offset = 0;
}

static int32_t proc_queue_cmd(uint8_t channel, uint16_t len, uint8_t type)
{   
    int32_t ret = 0;

    switch (type) {
    case MT7697_CMD_QUEUE_INIT:
	proc_queue_init_cmd(channel);
	break;

    case MT7697_CMD_QUEUE_CLR_INTR:
	ret = proc_queue_clr_intr_cmd(channel);
	if (ret < 0) {
	    LOG_W(common, "proc_queue_clr_intr_cmd() failed(%d)", ret);
	    goto cleanup;
        }

	break;

    case MT7697_CMD_QUEUE_UNUSED:
  	proc_queue_unused_cmd(channel);
	break;

    case MT7697_CMD_QUEUE_RESET:
	proc_queue_reset_cmd(channel);
	break;

    default:
	LOG_W(common, "unhandled cmd(%d)", type);
	ret = -1;
	goto cleanup;
    }

cleanup:
    return ret;
}

static void spi_queue_task(void *pvParameters)
{
    uint32_t channel = (uint32_t)pvParameters;

    struct QueueSpecification* qs = _get_valid_directed_queue(channel, QUEUE_DIRECTION_MASTER_TO_SLAVE);
    configASSERT(qs);

    while (1) {
	struct mt7697_cmd_hdr cmd_hdr;
	int32_t ret;

	ulTaskNotifyTake(pdTRUE, portMAX_DELAY);

	if (xSemaphoreTake(locks[channel], portMAX_DELAY) == pdTRUE) {
	    size_t avail = _get_num_words_in_queue(qs);
	    while (avail >= QUEUE_LEN_TO_WORD(sizeof(struct mt7697_cmd_hdr))) {
	        size_t words_read = spi_queue_read(channel, (uint32_t*)&cmd_hdr, QUEUE_LEN_TO_WORD(sizeof(struct mt7697_cmd_hdr)));
	        if (words_read == QUEUE_LEN_TO_WORD(sizeof(struct mt7697_cmd_hdr))) {
	            switch (cmd_hdr.grp) {
		    case MT7697_CMD_GRP_QUEUE:
		        ret = proc_queue_cmd(channel, cmd_hdr.len, cmd_hdr.type);
		        if (ret < 0) {
			    LOG_W(common, "proc_queue_cmd() failed(%d)", ret);
		        }
		        break;

	            case MT7697_CMD_GRP_80211:
		        ret = wifi_proc_cmd(channel, cmd_hdr.len, cmd_hdr.type);
		        if (ret < 0) {
	   		    LOG_W(common, "wifi_proc_cmd() failed(%d)", ret);
		        }
		        break;

	            case MT7697_CMD_GRP_BT:
		        break;

	            default:
		        LOG_W(common, "invalid cmd grp(%d)", cmd_hdr.grp);
		        break;
	            }
	        }
	        else {
	            LOG_W(common, "spi_queue_read() failed(%d)", words_read);
	        }

	        avail = _get_num_words_in_queue(qs);
	    }

	    xSemaphoreGive(locks[channel]);
        }
	else {
	    LOG_W(common, "xSemaphoreTake() failed");
	}
    }

    LOG_W(common, "end task(%u)", channel);
}

static void _spi_slave_interrupt_handler(void* data)
{
    // 1. Read a copy of the master to slave mailbox
    // 2. Clear the bits that were read as being set
    // 3. Perform handling for each of the bits that were set
    // This order of operations ensures that no notifications are lost.
    const uint8_t m2s_mailbox_bits = BF_GET(*SPIS_REG_MAILBOX_M2S, M2S_MAILBOX_REG_MAILBOX_OFFSET, M2S_MAILBOX_REG_MAILBOX_WIDTH);
    _clear_master_to_slave_mailbox(m2s_mailbox_bits);

    // Notify the task associated with the channel
    for (uint16_t i = 0; i < NUM_CHANNELS; i++) {
        if ((m2s_mailbox_bits & (1 << i)) && tasks[i] != NULL) {
	    BaseType_t xHigherPriorityTaskWoken;
	    vTaskNotifyGiveFromISR(tasks[i], &xHigherPriorityTaskWoken);
	    portYIELD_FROM_ISR(xHigherPriorityTaskWoken);
        }
    }
}
