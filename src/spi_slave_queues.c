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

static ssize_t _circular_buffer_difference(uint32_t, uint32_t, uint32_t);
static size_t _get_queue_capacity_in_words(const struct QueueSpecification*);
static size_t _get_num_words_in_queue(const struct QueueSpecification*);
static size_t _get_num_free_words_in_queue(const struct QueueSpecification*);
static void _set_slave_to_master_mailbox(uint8_t);
static void _clear_master_to_slave_mailbox(uint8_t);
static int32_t _notify_spi_master(void);
static struct QueueSpecification* _get_queue(uint8_t);
static struct QueueSpecification* _get_valid_queue(uint8_t);
static struct QueueSpecification* _get_valid_directed_queue(uint8_t, enum QueueDirection);
static void _spi_slave_interrupt_handler(void*);
static void spi_queue_m2s_task(void*);
static void spi_queue_s2m_task(void*);

struct QueueMain queueMain;

struct QueueSpecification queues[NUM_CHANNELS] __attribute__((__section__(".spi_slave"), unused)) = {
    {
        .flags = (
            BF_DEFINE(QUEUE_DIRECTION_M2S, FLAGS_DIRECTION_OFFSET, FLAGS_DIRECTION_WIDTH) |
            BF_DEFINE(ARRAY_SIZE(queueMain.m2s_q), FLAGS_NUM_WORDS_OFFSET, FLAGS_NUM_WORDS_WIDTH)),
        .base_address = (uint32_t)queueMain.m2s_q,
        .read_offset = 0,
        .write_offset = 0,
    },
    {
        .flags = (
            BF_DEFINE(QUEUE_DIRECTION_S2M, FLAGS_DIRECTION_OFFSET, FLAGS_DIRECTION_WIDTH) |
            BF_DEFINE(ARRAY_SIZE(queueMain.s2m_q), FLAGS_NUM_WORDS_OFFSET, FLAGS_NUM_WORDS_WIDTH)),
        .base_address = (uint32_t)queueMain.s2m_q,
        .read_offset = 0,
        .write_offset = 0,
    },
};

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

static size_t _get_queue_capacity_in_words(const struct QueueSpecification* queue_specification)
{
    return BF_GET(queue_specification->flags, FLAGS_NUM_WORDS_OFFSET, FLAGS_NUM_WORDS_WIDTH) - 1;
}

static size_t _get_num_words_in_queue(const struct QueueSpecification* queue_specification)
{
    return _circular_buffer_difference(
        BF_GET(queue_specification->flags, FLAGS_NUM_WORDS_OFFSET, FLAGS_NUM_WORDS_WIDTH), 
	       queue_specification->read_offset, queue_specification->write_offset);
}

static size_t _get_num_free_words_in_queue(const struct QueueSpecification* queue_specification)
{
    return _get_queue_capacity_in_words(queue_specification) - _get_num_words_in_queue(queue_specification);
}

static void _set_slave_to_master_mailbox(uint8_t bits)
{
    *SPIS_REG_MAILBOX_S2M =
        BF_DEFINE(bits, S2M_MAILBOX_REG_MAILBOX_OFFSET, S2M_MAILBOX_REG_MAILBOX_WIDTH);
//    LOG_I(common, "bits(0x%02x) S2M mbox(0x%02x)", bits, *SPIS_REG_MAILBOX_S2M);
}

static void _clear_master_to_slave_mailbox(uint8_t bits)
{
    // Write 1 to clear
    *SPIS_REG_MAILBOX_M2S =
        BF_DEFINE(bits, M2S_MAILBOX_REG_MAILBOX_OFFSET, M2S_MAILBOX_REG_MAILBOX_WIDTH);
//    LOG_I(common, "bits(0x%02x) M2S mbox(0x%02x)", bits, *SPIS_REG_MAILBOX_M2S);
}

static int32_t _notify_spi_master(void)
{
    queueMain.gpio_irq = (queueMain.gpio_irq == HAL_GPIO_DATA_LOW) ? HAL_GPIO_DATA_HIGH:HAL_GPIO_DATA_LOW;
    hal_gpio_status_t status = hal_gpio_set_output(HAL_GPIO_59, queueMain.gpio_irq);
    if (status != HAL_GPIO_STATUS_OK) {
	LOG_W(common, "hal_gpio_set_output() failed(%d)", status);
    }

    return status;
}

static struct QueueSpecification* _get_queue(uint8_t channel)
{
    if (channel >= NUM_CHANNELS) {
	LOG_W(common, "invalid channel(%u >= %u)", channel, NUM_CHANNELS);
        configASSERT(channel < NUM_CHANNELS);
    }

    struct QueueSpecification* qs = &queues[channel];
    return qs;
}

static struct QueueSpecification* _get_valid_queue(uint8_t channel)
{
    struct QueueSpecification* qs = _get_queue(channel);
    configASSERT(BF_GET(qs->flags, FLAGS_IN_USE_OFFSET, FLAGS_IN_USE_WIDTH));
    return qs;
}

static struct QueueSpecification* _get_directed_queue(uint8_t channel, enum QueueDirection direction)
{
    struct QueueSpecification* qs = _get_queue(channel);
    enum QueueDirection actual_direction =
        BF_GET(qs->flags, FLAGS_DIRECTION_OFFSET, FLAGS_DIRECTION_WIDTH);
    if (actual_direction != direction) {
        LOG_W(common, "invalid direction(%u != %u)", direction, actual_direction);
        configASSERT(actual_direction == direction);
    }

    return qs;
}

static struct QueueSpecification* _get_valid_directed_queue(uint8_t channel, enum QueueDirection direction)
{
    struct QueueSpecification* qs = _get_valid_queue(channel);
    enum QueueDirection actual_direction =
        BF_GET(qs->flags, FLAGS_DIRECTION_OFFSET, FLAGS_DIRECTION_WIDTH);
    if (actual_direction != direction) {
        LOG_W(common, "invalid direction(%u != %u)", direction, actual_direction);
        configASSERT(actual_direction == direction);
    }

    return qs;
}

static int32_t proc_queue_init_cmd(uint8_t channel)
{
    uint32_t m2s_ch, s2m_ch;
    int32_t ret = 0;

    struct mt7697_queue_init_rsp* rsp = malloc(LEN32_ALIGNED(sizeof(struct mt7697_queue_init_rsp)));
    if (!rsp) {
	LOG_W(common, "malloc() failed");
        ret = -1;
	goto cleanup;
    }

    rsp->cmd.len = sizeof(struct mt7697_queue_init_rsp);
    rsp->cmd.grp = MT7697_CMD_GRP_QUEUE;
    rsp->cmd.type = MT7697_CMD_QUEUE_INIT_RSP; 

    LOG_I(common, "--> INIT QUEUE");
    size_t words_read = spi_queue_read(channel, (uint32_t*)&m2s_ch, LEN_TO_WORD(sizeof(uint32_t)));
    if (words_read != LEN_TO_WORD(sizeof(uint32_t))) {
        LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, LEN_TO_WORD(sizeof(uint32_t)));
	ret = -1;
	goto cleanup;
    }

    words_read = spi_queue_read(channel, (uint32_t*)&s2m_ch, LEN_TO_WORD(sizeof(uint32_t)));
    if (words_read != LEN_TO_WORD(sizeof(uint32_t))) {
        LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, LEN_TO_WORD(sizeof(uint32_t)));
	ret = -1;
	goto cleanup;
    }

    LOG_I(common, "init queue(%u/%u)", m2s_ch, s2m_ch);
    struct QueueSpecification* qsM2S = _get_queue(m2s_ch);
    struct QueueSpecification* qsS2M = _get_queue(s2m_ch);
    qsM2S->flags |= BF_DEFINE(1, FLAGS_IN_USE_OFFSET, FLAGS_IN_USE_WIDTH);
    qsS2M->flags |= BF_DEFINE(1, FLAGS_IN_USE_OFFSET, FLAGS_IN_USE_WIDTH);

cleanup:
    rsp->result = ret;
    LOG_I(common, "<-- INIT QUEUE(%u/%u) RSP len(%u) result(%d)", m2s_ch, s2m_ch, rsp->cmd.len, ret);
    ret = spi_queue_send_req(s2m_ch, (struct mt7697_rsp_hdr*)rsp);
    if (ret < 0) {
        LOG_W(common, "spi_queue_send_req_from_isr() failed(%d)", ret);
        goto cleanup;
    }

    return ret;
}

static int32_t proc_queue_unused_cmd(uint8_t channel)
{
    uint32_t m2s_ch, s2m_ch;
    int32_t ret = 0;

    struct mt7697_queue_unused_rsp* rsp = malloc(LEN32_ALIGNED(sizeof(struct mt7697_queue_init_rsp)));
    if (!rsp) {
	LOG_W(common, "malloc() failed");
        ret = -1;
	goto cleanup;
    }

    rsp->cmd.len = sizeof(struct mt7697_queue_unused_rsp);
    rsp->cmd.grp = MT7697_CMD_GRP_QUEUE;
    rsp->cmd.type = MT7697_CMD_QUEUE_UNUSED_RSP;

    LOG_I(common, "--> UNUSED QUEUE(%u)", channel);
    size_t words_read = spi_queue_read(channel, (uint32_t*)&m2s_ch, LEN_TO_WORD(sizeof(uint32_t)));
    if (words_read != LEN_TO_WORD(sizeof(uint32_t))) {
        LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, LEN_TO_WORD(sizeof(uint32_t)));
	ret = -1;
	goto cleanup;
    }

    words_read = spi_queue_read(channel, (uint32_t*)&s2m_ch, LEN_TO_WORD(sizeof(uint32_t)));
    if (words_read != LEN_TO_WORD(sizeof(uint32_t))) {
        LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, LEN_TO_WORD(sizeof(uint32_t)));
	ret = -1;
	goto cleanup;
    }

    LOG_I(common, "unused queue(%u/%u)", m2s_ch, s2m_ch);
    struct QueueSpecification* qsM2S = _get_valid_queue(m2s_ch);
    struct QueueSpecification* qsS2M = _get_valid_queue(s2m_ch);
    qsM2S->flags &= ~BF_DEFINE(1, FLAGS_IN_USE_OFFSET, FLAGS_IN_USE_WIDTH);
    qsS2M->flags &= ~BF_DEFINE(1, FLAGS_IN_USE_OFFSET, FLAGS_IN_USE_WIDTH);

cleanup:
    rsp->result = ret;
    LOG_I(common, "<-- UNUSED QUEUE(%u/%u) RSP len(%u) result(%d)", m2s_ch, s2m_ch, rsp->cmd.len, ret);
    ret = spi_queue_send_req(s2m_ch, (struct mt7697_rsp_hdr*)rsp);
    if (ret < 0) {
        LOG_W(common, "spi_queue_send_req_from_isr() failed(%d)", ret);
        goto cleanup;
    }

    return ret;
}

static int32_t proc_queue_reset_cmd(uint8_t channel)
{
    uint32_t m2s_ch, s2m_ch;
    int32_t ret = 0;

    struct mt7697_queue_reset_rsp* rsp = malloc(LEN32_ALIGNED(sizeof(struct mt7697_queue_reset_rsp)));
    if (!rsp) {
	LOG_W(common, "malloc() failed");
        ret = -1;
	goto cleanup;
    }

    rsp->cmd.len = sizeof(struct mt7697_queue_reset_rsp);
    rsp->cmd.grp = MT7697_CMD_GRP_QUEUE;
    rsp->cmd.type = MT7697_CMD_QUEUE_RESET_RSP;

    LOG_I(common, "--> RESET QUEUE(%u)", channel);
    size_t words_read = spi_queue_read(channel, (uint32_t*)&m2s_ch, LEN_TO_WORD(sizeof(uint32_t)));
    if (words_read != LEN_TO_WORD(sizeof(uint32_t))) {
        LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, LEN_TO_WORD(sizeof(uint32_t)));
	ret = -1;
	goto cleanup;
    }

    words_read = spi_queue_read(channel, (uint32_t*)&s2m_ch, LEN_TO_WORD(sizeof(uint32_t)));
    if (words_read != LEN_TO_WORD(sizeof(uint32_t))) {
        LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, LEN_TO_WORD(sizeof(uint32_t)));
	ret = -1;
	goto cleanup;
    }

    LOG_I(common, "reset queue(%u/%u)", m2s_ch, s2m_ch);
    struct QueueSpecification* qsM2S = _get_valid_queue(m2s_ch);
    struct QueueSpecification* qsS2M = _get_valid_queue(s2m_ch);

    qsM2S->read_offset = 0;
    qsM2S->write_offset = 0;

    qsS2M->read_offset = 0;
    qsS2M->write_offset = 0;;

cleanup:
    rsp->result = ret;
    LOG_I(common, "<-- RESET QUEUE(%u/%u) RSP len(%u) result(%d)", m2s_ch, s2m_ch, rsp->cmd.len, ret);
    ret = spi_queue_send_req(s2m_ch, (struct mt7697_rsp_hdr*)rsp);
    if (ret < 0) {
        LOG_W(common, "spi_queue_send_req_from_isr() failed(%d)", ret);
        goto cleanup;
    }

    return ret;
}

static int32_t proc_queue_cmd(uint8_t channel, uint8_t type)
{   
    int32_t ret = 0;

    switch (type) {
    case MT7697_CMD_QUEUE_INIT:
	ret = proc_queue_init_cmd(channel);
	if (ret < 0) {
	    LOG_W(common, "proc_queue_init_cmd() failed(%d)", ret);
	    goto cleanup;
        }

	break;

    case MT7697_CMD_QUEUE_UNUSED:
  	ret = proc_queue_unused_cmd(channel);
	if (ret < 0) {
	    LOG_W(common, "proc_queue_unused_cmd() failed(%d)", ret);
	    goto cleanup;
        }

	break;

    case MT7697_CMD_QUEUE_RESET:
	ret = proc_queue_reset_cmd(channel);
	if (ret < 0) {
	    LOG_W(common, "proc_queue_reset_cmd() failed(%d)", ret);
	    goto cleanup;
        }

	break;

    default:
	LOG_W(common, "unhandled cmd(%d)", type);
	ret = -1;
	goto cleanup;
    }

cleanup:
    return ret;
}

static size_t spi_queue_write(uint8_t channel, const uint32_t* buffer, size_t num_words)
{
    struct QueueSpecification* qs = _get_valid_directed_queue(channel, QUEUE_DIRECTION_S2M);
    configASSERT(qs);
    const uint32_t buffer_num_words = BF_GET(qs->flags, FLAGS_NUM_WORDS_OFFSET, FLAGS_NUM_WORDS_WIDTH);
    uint16_t read_offset;
    uint16_t write_offset;
    size_t words_written = 0;
    int32_t err;

    if (xSemaphoreTake(queueMain.info[channel].lock, portMAX_DELAY) != pdTRUE) {
	LOG_E(common, "xSemaphoreTake() failed");
        goto cleanup;
    }

    if (spi_queue_get_num_free_words(channel) < num_words) {
	LOG_W(common, "no space free(%u) < req(%u)", spi_queue_get_num_free_words(channel), num_words);
	goto cleanup;
    }

    read_offset = qs->read_offset;
    write_offset = qs->write_offset;
    if (write_offset >= read_offset) {
        const size_t words_until_end = buffer_num_words - write_offset;
        const size_t words_available_for_write =
            (read_offset == 0) ? (words_until_end - 1) : words_until_end;
        const size_t num_words_to_write =
            (num_words <= words_available_for_write) ? num_words : words_available_for_write;
        uint32_t* const write_to = (uint32_t*)(qs->base_address + (write_offset * sizeof(uint32_t)));

        memcpy(write_to, &buffer[words_written], num_words_to_write * sizeof(uint32_t));
        words_written += num_words_to_write;
        write_offset += num_words_to_write;
	num_words -= num_words_to_write;
        if (write_offset == buffer_num_words) {
            write_offset = 0;
        }
    }

    if ((write_offset < read_offset) && (num_words > 0)) {
        const size_t words_until_read = (read_offset - write_offset) - 1;
        const size_t num_words_to_write = (num_words <= words_until_read) ? num_words : words_until_read;
        uint32_t* const write_to = (uint32_t*)(qs->base_address + (write_offset * sizeof(uint32_t)));

        memcpy(write_to, &buffer[words_written], num_words_to_write * sizeof(uint32_t));
        words_written += num_words_to_write;
	num_words -= num_words_to_write;
        write_offset += num_words_to_write;
    }

    if (write_offset >= buffer_num_words) {
	LOG_E(common, "invalid write offset(%u) >= size(%u)", write_offset, buffer_num_words);
        configASSERT(write_offset < buffer_num_words);
    }

    qs->write_offset = write_offset;

    if (words_written > 0) {
        _set_slave_to_master_mailbox(1 << channel);
        err = _notify_spi_master();
	if (err < 0) {
	    LOG_E(common, "_notify_spi_master() failed(%d)", err);
	    words_written = err;
	    goto cleanup;
	}
    }

cleanup:
//    LOG_I(common, "q(%d) words written/offset(%d/%u)", channel, words_written, write_offset);

    if (xSemaphoreGive(queueMain.info[channel].lock) != pdTRUE) {
	LOG_E(common, "xSemaphoreGive() failed");
        goto cleanup;
    }

    return words_written;
}

static void spi_queue_s2m_task(void *pvParameters)
{
    uint32_t channel = (uint32_t)pvParameters;

    queueMain.info[channel].sendQ = xQueueCreate(QUEUE_SENDQ_LEN, sizeof(struct mt7697_rsp_hdr*));
    if (!queueMain.info[channel].sendQ) {
	LOG_W(common, "xQueueCreate() failed");
	goto cleanup;
    }

    while (1) {
	struct mt7697_rsp_hdr* req;
	if (xQueueReceive(queueMain.info[channel].sendQ, &req, portMAX_DELAY)) {
            LOG_I(common, "<-- q(%u) CMD(%u) len(%u)", channel, req->cmd.type, req->cmd.len);
    	    size_t bWrite = spi_queue_write(channel, (const uint32_t*)req, LEN_TO_WORD(LEN32_ALIGNED(req->cmd.len)));
    	    if (bWrite != LEN_TO_WORD(LEN32_ALIGNED(req->cmd.len))) {
		LOG_W(common, "spi_queue_write() failed(%d != %d)", bWrite, LEN_TO_WORD(LEN32_ALIGNED(req->cmd.len)));
    	    }

	    free(req);
        }
    }

cleanup:
    LOG_W(common, "end S2M task(%u)", channel);
}

static void spi_queue_m2s_task(void *pvParameters)
{
    uint32_t channel = (uint32_t)pvParameters;

    struct QueueSpecification* qs = _get_directed_queue(channel, QUEUE_DIRECTION_M2S);
    while (1) {
	int32_t ret;

	ulTaskNotifyTake(pdTRUE, portMAX_DELAY);

	size_t avail = _get_num_words_in_queue(qs);
//        LOG_I(common, "avail(%u)", avail);
	while (((queueMain.cmd_hdr.len) &&
                (avail >= LEN_TO_WORD(queueMain.cmd_hdr.len - sizeof(struct mt7697_cmd_hdr)))) ||
	       ((!queueMain.cmd_hdr.len) && 
	        (avail >= LEN_TO_WORD(sizeof(struct mt7697_cmd_hdr))))) {
	    if (!queueMain.cmd_hdr.len) {
	    	size_t words_read = spi_queue_read(channel, (uint32_t*)&queueMain.cmd_hdr, LEN_TO_WORD(sizeof(struct mt7697_cmd_hdr)));
	    	if (words_read != LEN_TO_WORD(sizeof(struct mt7697_cmd_hdr))) {
	        	LOG_W(common, "spi_queue_read() failed(%d)", words_read);
	        	break;
	    	}

		avail = _get_num_words_in_queue(qs);
//		LOG_I(common, "avail(%u)", avail);
	    }

//	    LOG_I(common, "len(%u)", queueMain.cmd_hdr.len);
	    if (avail < LEN_TO_WORD(queueMain.cmd_hdr.len - sizeof(struct mt7697_cmd_hdr))) {
		LOG_W(common, "queue need more data");
		break;
	    }

	    switch (queueMain.cmd_hdr.grp) {
            case MT7697_CMD_GRP_QUEUE:
	        ret = proc_queue_cmd(channel, queueMain.cmd_hdr.type);
	        if (ret < 0) {
                    LOG_W(common, "proc_queue_cmd() failed(%d)", ret);
	        }
	        break;

	    case MT7697_CMD_GRP_80211:
	        ret = wifi_proc_cmd(channel, queueMain.cmd_hdr.len, queueMain.cmd_hdr.type);
	        if (ret < 0) {
	            LOG_W(common, "wifi_proc_cmd() failed(%d)", ret);
	        }
	        break;

	    case MT7697_CMD_GRP_BT:
	    default:
	        LOG_W(common, "invalid cmd grp(%d)", queueMain.cmd_hdr.grp);
                break;
	    }

	    queueMain.cmd_hdr.len = 0;
	    avail = _get_num_words_in_queue(qs);
//            LOG_I(common, "avail(%u)", avail);
        }
    }

    LOG_W(common, "end M2S task(%u)", channel);
}

static void _spi_slave_interrupt_handler(void* data)
{
    // 1. Read a copy of the master to slave mailbox
    // 2. Clear the bits that were read as being set
    // 3. Perform handling for each of the bits that were set
    // This order of operations ensures that no notifications are lost.
    const uint8_t m2s_mailbox_bits = BF_GET(*SPIS_REG_MAILBOX_M2S, M2S_MAILBOX_REG_MAILBOX_OFFSET, M2S_MAILBOX_REG_MAILBOX_WIDTH);
    _clear_master_to_slave_mailbox(m2s_mailbox_bits);

//    LOG_I(common, "M2S mbox(0x%02x)", m2s_mailbox_bits);
    if (m2s_mailbox_bits) {
        for (uint16_t i = 0; i < NUM_CHANNELS; i++) {
            if ((m2s_mailbox_bits & (1 << i)) && queueMain.info[i].task.hndl != NULL) {
	        BaseType_t xHigherPriorityTaskWoken;
	        vTaskNotifyGiveFromISR(queueMain.info[i].task.hndl, &xHigherPriorityTaskWoken);
	        portYIELD_FROM_ISR(xHigherPriorityTaskWoken);
            }
        }
    }
}

int32_t spi_queue_init(void)
{
    int ret = 0;

    // EPT is used for pin muxing, so no need to configure muxing for SPI slave
    LOG_I(common, "queues init");

    queueMain.gpio_irq = HAL_GPIO_DATA_LOW;
    hal_gpio_status_t status = hal_gpio_set_output(HAL_GPIO_59, queueMain.gpio_irq);
    if (status != HAL_GPIO_STATUS_OK) {
	LOG_W(common, "hal_gpio_set_output() failed(%d)", status);
	ret = -1;
	goto cleanup;
    }

    for (unsigned int i = 0; i < NUM_CHANNELS; i++) {
	struct QueueSpecification* qs = _get_queue(i);
	configASSERT(qs);	

	LOG_I(common, "q(%d) flags(0x%08x) base(0x%08x) rd/wr offset(%d/%d)", 
		i, qs->flags, qs->base_address, qs->read_offset, qs->write_offset);

	queueMain.info[i].lock = xSemaphoreCreateMutex();
	if (!queueMain.info[i].lock) {
	    LOG_W(common, "xSemaphoreCreateMutex(%d) failed", i);
	    ret = -1;
	    goto cleanup;
	}

    	enum QueueDirection direction = BF_GET(qs->flags, FLAGS_DIRECTION_OFFSET, FLAGS_DIRECTION_WIDTH);
	if (QUEUE_DIRECTION_M2S == direction) {
	    snprintf(queueMain.info[i].task.name, sizeof(queueMain.info[i].task.name), "qM2S%d", i);
            BaseType_t xReturned = xTaskCreate(spi_queue_m2s_task,       
                    queueMain.info[i].task.name, QUEUE_TASK_STACK_SIZE, (void*)i,
                    tskIDLE_PRIORITY, &queueMain.info[i].task.hndl);      
            if (xReturned != pdPASS) {
                LOG_W(common, "M2S xTaskCreate(%d) failed(%d)", i, xReturned);
		ret = -1;
		goto cleanup;
            }
        }
	else if (QUEUE_DIRECTION_S2M == direction) {
	    snprintf(queueMain.info[i].task.name, sizeof(queueMain.info[i].task.name), "qS2M%d", i);
            BaseType_t xReturned = xTaskCreate(spi_queue_s2m_task,       
                    queueMain.info[i].task.name, QUEUE_TASK_STACK_SIZE, (void*)i,
                    tskIDLE_PRIORITY, &queueMain.info[i].task.hndl);      
            if (xReturned != pdPASS) {
                LOG_W(common, "S2M xTaskCreate(%d) failed(%d)", i, xReturned);
		ret = -1;
		goto cleanup;
            }
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

    slave_status = hal_spi_slave_register_callback(HAL_SPI_SLAVE_0, _spi_slave_interrupt_handler, NULL);
    configASSERT(slave_status == HAL_SPI_SLAVE_STATUS_OK);

cleanup:
    return ret;
}

int32_t spi_queue_send_req(uint8_t ch, const struct mt7697_rsp_hdr* req)
{
    int32_t ret = 0;

    if (xQueueSendToBack(queueMain.info[ch].sendQ, &req, 0) != pdPASS) {
	LOG_W(common, "xQueueSendToBack() failed");
	ret = -1;
	goto cleanup;
    }

cleanup:
    return ret;
}

int32_t spi_queue_send_req_from_isr(uint8_t ch, const struct mt7697_rsp_hdr* req)
{
    BaseType_t xHigherPriorityTaskWoken;
    int32_t ret = 0;

    if (xQueueSendToBackFromISR(queueMain.info[ch].sendQ, &req, &xHigherPriorityTaskWoken) != pdPASS) {
	LOG_W(common, "xQueueSendToBackFromISR() failed");
	ret = -1;
	goto cleanup;
    }

    portYIELD_FROM_ISR(xHigherPriorityTaskWoken);

cleanup:
    return ret;
}

size_t spi_queue_read(uint8_t channel, uint32_t* buffer, size_t num_words)
{
    struct QueueSpecification* qs = _get_directed_queue(channel, QUEUE_DIRECTION_M2S);
    configASSERT(qs);
    const uint32_t buffer_num_words = BF_GET(qs->flags, FLAGS_NUM_WORDS_OFFSET, FLAGS_NUM_WORDS_WIDTH);
    uint16_t write_offset;
    uint16_t read_offset;
    size_t words_read = 0;

    if (xSemaphoreTake(queueMain.info[channel].lock, portMAX_DELAY) != pdTRUE) {
	LOG_E(common, "xSemaphoreTake() failed");
        goto cleanup;
    }

    write_offset = qs->write_offset;
    read_offset = qs->read_offset;
    if (read_offset > write_offset) {
        const size_t words_until_end = buffer_num_words - read_offset;
        const uint32_t* read_from = (uint32_t*)(qs->base_address + (read_offset * sizeof(uint32_t)));
        const size_t num_words_to_read = (num_words <= words_until_end) ? num_words : words_until_end;

        memcpy(&buffer[words_read], read_from, num_words_to_read * sizeof(uint32_t));
        words_read += num_words_to_read;
	read_offset += num_words_to_read;
        if (read_offset == buffer_num_words) {
            // If we have read to the end, then set the read pointer to the beginning
            read_offset = 0;
        }
    }

    if (words_read < num_words) {
        const size_t words_until_write_ptr = write_offset - read_offset;
        const uint32_t* read_from = (uint32_t*)(qs->base_address + (read_offset * sizeof(uint32_t)));
        const size_t wanted_words = num_words - words_read;
        const size_t num_words_to_read =
            (wanted_words <= words_until_write_ptr) ? wanted_words : words_until_write_ptr;

        memcpy(&buffer[words_read], read_from, num_words_to_read * sizeof(uint32_t));
        words_read += num_words_to_read;
        read_offset += num_words_to_read;
    }

    if (read_offset >= buffer_num_words) {
	LOG_E(common, "invalid read offset(%u) >= size(%u)", read_offset, buffer_num_words);
        configASSERT(read_offset < buffer_num_words);
	goto cleanup;
    }

    qs->read_offset = read_offset;

cleanup:
//    LOG_I(common, "q(%d) words read/offset(%d/%u)", channel, words_read, read_offset);

    if (xSemaphoreGive(queueMain.info[channel].lock) != pdTRUE) {
	LOG_E(common, "xSemaphoreGive() failed");
        goto cleanup;
    }

    return words_read;
}

size_t spi_queue_get_capacity_in_words(uint8_t channel)
{
    struct QueueSpecification* qs = _get_queue(channel);
    configASSERT(qs);
    return _get_queue_capacity_in_words(qs);
}

size_t spi_queue_get_num_words_used(uint8_t channel)
{
    struct QueueSpecification* qs = _get_queue(channel);
    configASSERT(qs);
    return _get_num_words_in_queue(qs);
}

size_t spi_queue_get_num_free_words(uint8_t channel)
{
    struct QueueSpecification* qs = _get_queue(channel);
    configASSERT(qs);
    return _get_num_free_words_in_queue(qs);
}
