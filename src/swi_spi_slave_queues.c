// stdlib
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

// MTK
#include <hal_spi_slave.h>

// FreeRTOS
#include <FreeRTOS.h>
#include <task.h>

// SWI
#include "bits.h"
#include "swi_wifi.h"
#include "swi_spi_slave_queues.h"

static ssize_t swi_spi_circular_buffer_difference(uint32_t, uint32_t, uint32_t);
static size_t swi_spi_get_queue_capacity_in_words(const swi_spi_queue_spec_t*);
static size_t swi_spi_get_num_words_in_queue(const swi_spi_queue_spec_t*);
static size_t swi_spi_get_num_free_words_in_queue(const swi_spi_queue_spec_t*);

static int32_t swi_spi_queue_notify_master(void);
static void swi_spi_set_slave_to_master_mailbox(uint8_t);
static void swi_spi_clear_master_to_slave_mailbox(uint8_t);

static int32_t swi_spi_proc_queue_init_cmd(swi_m2s_info_t*);
static int32_t swi_spi_proc_queue_unused_cmd(swi_m2s_info_t*);
static int32_t swi_spi_proc_queue_reset_cmd(swi_m2s_info_t*);
static int32_t swi_spi_proc_queue_cmd(swi_m2s_info_t*);

static void swi_spi_slave_interrupt_handler(void*);
static void swi_spi_queue_m2s_task(void*);

swi_spi_queue_info_t* spi_queue_info = NULL;
swi_spi_queue_spec_t queues[NUM_CHANNELS] __attribute__((__section__(".spi_slave"), unused)) = {
    {
        .flags = (
            BF_DEFINE(QUEUE_DIRECTION_M2S, FLAGS_DIRECTION_OFFSET, FLAGS_DIRECTION_WIDTH) |
            BF_DEFINE(QUEUE_WORD_SIZE, FLAGS_NUM_WORDS_OFFSET, FLAGS_NUM_WORDS_WIDTH)),
        .base_address = 0,
        .read_offset = 0,
        .write_offset = 0,
    },
    {
        .flags = (
            BF_DEFINE(QUEUE_DIRECTION_S2M, FLAGS_DIRECTION_OFFSET, FLAGS_DIRECTION_WIDTH) |
            BF_DEFINE(QUEUE_WORD_SIZE, FLAGS_NUM_WORDS_OFFSET, FLAGS_NUM_WORDS_WIDTH)),
        .base_address = 0,
        .read_offset = 0,
        .write_offset = 0,
    },
};

static ssize_t swi_spi_circular_buffer_difference(uint32_t buffer_size, uint32_t from, uint32_t to)
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

static size_t swi_spi_get_queue_capacity_in_words(const swi_spi_queue_spec_t* qs)
{
    return BF_GET(qs->flags, FLAGS_NUM_WORDS_OFFSET, FLAGS_NUM_WORDS_WIDTH) - 1;
}

static size_t swi_spi_get_num_words_in_queue(const swi_spi_queue_spec_t* qs)
{
    return swi_spi_circular_buffer_difference(
        BF_GET(qs->flags, FLAGS_NUM_WORDS_OFFSET, FLAGS_NUM_WORDS_WIDTH),
        qs->read_offset, qs->write_offset);
}

static size_t swi_spi_get_num_free_words_in_queue(const swi_spi_queue_spec_t* qs)
{
    return swi_spi_get_queue_capacity_in_words(qs) - swi_spi_get_num_words_in_queue(qs);
}

static void swi_spi_set_slave_to_master_mailbox(uint8_t bits)
{
    *SPIS_REG_MAILBOX_S2M =
        BF_DEFINE(bits, S2M_MAILBOX_REG_MAILBOX_OFFSET, S2M_MAILBOX_REG_MAILBOX_WIDTH);
//    LOG_I(common, "bits(0x%02x) S2M mbox(0x%02x)", bits, *SPIS_REG_MAILBOX_S2M);
}

static void swi_spi_clear_master_to_slave_mailbox(uint8_t bits)
{
    // Write 1 to clear
    *SPIS_REG_MAILBOX_M2S =
        BF_DEFINE(bits, M2S_MAILBOX_REG_MAILBOX_OFFSET, M2S_MAILBOX_REG_MAILBOX_WIDTH);
//    LOG_I(common, "bits(0x%02x) M2S mbox(0x%02x)", bits, *SPIS_REG_MAILBOX_M2S);
}

static int32_t swi_spi_proc_queue_init_cmd(swi_m2s_info_t* m2s_info)
{
    mt7697_queue_init_rsp_t* rsp = NULL;
    uint32_t m2s_ch, s2m_ch;
    int32_t ret = 0;

    LOG_I(common, "--> INIT QUEUE");
    size_t words_read = m2s_info->hw_read(m2s_info->rd_hndl, (uint32_t*)&m2s_ch,
                                          LEN_TO_WORD(sizeof(uint32_t)));
    if (words_read != LEN_TO_WORD(sizeof(uint32_t))) {
        LOG_W(common, "hw_read() failed(%d != %d)", words_read, LEN_TO_WORD(sizeof(uint32_t)));
        ret = -1;
        goto cleanup;
    }

    words_read = m2s_info->hw_read(m2s_info->rd_hndl, (uint32_t*)&s2m_ch,
                                   LEN_TO_WORD(sizeof(uint32_t)));
    if (words_read != LEN_TO_WORD(sizeof(uint32_t))) {
        LOG_W(common, "hw_read() failed(%d != %d)", words_read, LEN_TO_WORD(sizeof(uint32_t)));
        ret = -1;
        goto cleanup;
    }

    ret = swi_mem_pool_init(&spi_queue_info->data[s2m_ch].dir.s2m.msg_pool_info.lo,
                            SWI_MSG_POOL_LEN, MT7697_IEEE80211_FRAME_LEN);
    if (ret < 0) {
        LOG_W(common, "swi_mem_pool_init() failed(%d)", ret);
        goto cleanup;
    }

    ret = swi_mem_pool_init(&spi_queue_info->data[s2m_ch].dir.s2m.msg_pool_info.hi,
                            SWI_MSG_POOL_HI_LEN, MT7697_IEEE80211_FRAME_LEN);
    if (ret < 0) {
        LOG_W(common, "swi_mem_pool_init() failed(%d)", ret);
        goto cleanup;
    }

    rsp = (mt7697_queue_init_rsp_t*)swi_mem_pool_alloc_msg(
        &spi_queue_info->data[s2m_ch].dir.s2m.msg_pool_info, SWI_MEM_POOL_MSG_HI_PRIORITY,
        spi_queue_info->data[s2m_ch].dir.s2m.sendQ, LEN32_ALIGNED(sizeof(mt7697_queue_init_rsp_t)));
    if (!rsp) {
        LOG_W(common, "swi_mem_pool_alloc_msg() failed");
        ret = -1;
        goto cleanup;
    }

    rsp->cmd.len = sizeof(mt7697_queue_init_rsp_t);
    rsp->cmd.grp = MT7697_CMD_GRP_QUEUE;
    rsp->cmd.type = MT7697_CMD_QUEUE_INIT_RSP;

    LOG_I(common, "init queue(%u/%u)", m2s_ch, s2m_ch);
    spi_queue_info->data[s2m_ch].qs->flags |= BF_DEFINE(1, FLAGS_IN_USE_OFFSET, FLAGS_IN_USE_WIDTH);
    spi_queue_info->data[m2s_ch].qs->flags |= BF_DEFINE(1, FLAGS_IN_USE_OFFSET, FLAGS_IN_USE_WIDTH);

cleanup:
    if (rsp) {
        rsp->result = ret;
        LOG_I(common, "<-- INIT QUEUE(%u/%u) RSP len(%u) result(%d)", m2s_ch, s2m_ch, rsp->cmd.len,
              ret);
        ret = swi_s2m_send_req(&spi_queue_info->data[s2m_ch].dir.s2m, (mt7697_rsp_hdr_t*)rsp);
        if (ret < 0) {
            LOG_W(common, "swi_s2m_send_req() failed(%d)", ret);
            goto cleanup;
        }
    }

    return ret;
}

static int32_t swi_spi_proc_queue_unused_cmd(swi_m2s_info_t* m2s_info)
{
    uint32_t m2s_ch, s2m_ch;
    int32_t ret = 0;

    LOG_I(common, "--> UNUSED QUEUE");
    size_t words_read = m2s_info->hw_read(m2s_info->rd_hndl, (uint32_t*)&m2s_ch,
                                          LEN_TO_WORD(sizeof(uint32_t)));
    if (words_read != LEN_TO_WORD(sizeof(uint32_t))) {
        LOG_W(common, "hw_read() failed(%d != %d)", words_read, LEN_TO_WORD(sizeof(uint32_t)));
        ret = -1;
        goto cleanup;
    }

    words_read = m2s_info->hw_read(m2s_info->rd_hndl, (uint32_t*)&s2m_ch,
                                   LEN_TO_WORD(sizeof(uint32_t)));
    if (words_read != LEN_TO_WORD(sizeof(uint32_t))) {
        LOG_W(common, "hw_read() failed(%d != %d)", words_read, LEN_TO_WORD(sizeof(uint32_t)));
        ret = -1;
        goto cleanup;
    }

    LOG_I(common, "unused queue(%u/%u)", m2s_ch, s2m_ch);
    spi_queue_info->data[m2s_ch].qs->flags &= ~BF_DEFINE(1, FLAGS_IN_USE_OFFSET,
                                                         FLAGS_IN_USE_WIDTH);
    spi_queue_info->data[s2m_ch].qs->flags &= ~BF_DEFINE(1, FLAGS_IN_USE_OFFSET,
                                                         FLAGS_IN_USE_WIDTH);

cleanup:
    return ret;
}

static int32_t swi_spi_proc_queue_reset_cmd(swi_m2s_info_t* m2s_info)
{
    mt7697_queue_reset_rsp_t* rsp = NULL;
    uint32_t m2s_ch, s2m_ch;
    int32_t ret = 0;

    LOG_I(common, "--> RESET QUEUE");
    size_t words_read = m2s_info->hw_read(m2s_info->rd_hndl, (uint32_t*)&m2s_ch,
                                          LEN_TO_WORD(sizeof(uint32_t)));
    if (words_read != LEN_TO_WORD(sizeof(uint32_t))) {
        LOG_W(common, "hw_read() failed(%d != %d)", words_read, LEN_TO_WORD(sizeof(uint32_t)));
        ret = -1;
        goto cleanup;
    }

    words_read = m2s_info->hw_read(m2s_info->rd_hndl, (uint32_t*)&s2m_ch,
                                   LEN_TO_WORD(sizeof(uint32_t)));
    if (words_read != LEN_TO_WORD(sizeof(uint32_t))) {
        LOG_W(common, "hw_read() failed(%d != %d)", words_read, LEN_TO_WORD(sizeof(uint32_t)));
        ret = -1;
        goto cleanup;
    }

    rsp = (mt7697_queue_reset_rsp_t*)swi_mem_pool_alloc_msg(
        &spi_queue_info->data[s2m_ch].dir.s2m.msg_pool_info, SWI_MEM_POOL_MSG_HI_PRIORITY,
        spi_queue_info->data[s2m_ch].dir.s2m.sendQ,
        LEN32_ALIGNED(sizeof(mt7697_queue_reset_rsp_t)));
    if (!rsp) {
        LOG_W(common, "swi_mem_pool_alloc_msg() failed");
        ret = -1;
        goto cleanup;
    }

    rsp->cmd.len = sizeof(mt7697_queue_reset_rsp_t);
    rsp->cmd.grp = MT7697_CMD_GRP_QUEUE;
    rsp->cmd.type = MT7697_CMD_QUEUE_RESET_RSP;

    LOG_I(common, "reset queue(%u/%u)", m2s_ch, s2m_ch);

    spi_queue_info->data[m2s_ch].qs->read_offset = 0;
    spi_queue_info->data[m2s_ch].qs->write_offset = 0;

    spi_queue_info->data[s2m_ch].qs->read_offset = 0;
    spi_queue_info->data[s2m_ch].qs->write_offset = 0;;

    swi_mem_pool_reset(&spi_queue_info->data[s2m_ch].dir.s2m.msg_pool_info.lo);
    swi_mem_pool_reset(&spi_queue_info->data[s2m_ch].dir.s2m.msg_pool_info.hi);

    if (xQueueReset(spi_queue_info->data[s2m_ch].dir.s2m.sendQ) != pdPASS) {
        LOG_W(common, "xQueueReset() failed");
        ret = -1;
        goto cleanup;
    }

cleanup:
    if (rsp) {
        rsp->result = ret;
        LOG_I(common, "<-- RESET QUEUE(%u/%u) RSP len(%u) result(%d)", m2s_ch, s2m_ch, rsp->cmd.len,
              ret);
        ret = swi_s2m_send_req(&spi_queue_info->data[s2m_ch].dir.s2m, (mt7697_rsp_hdr_t*)rsp);
        if (ret < 0) {
            LOG_W(common, "swi_s2m_send_req() failed(%d)", ret);
            goto cleanup;
        }
    }

    return ret;
}

static int32_t swi_spi_proc_queue_cmd(swi_m2s_info_t* m2s_info)
{
    int32_t ret = 0;

    switch (m2s_info->cmd_hdr.type) {
    case MT7697_CMD_QUEUE_INIT:
        ret = swi_spi_proc_queue_init_cmd(m2s_info);
        if (ret < 0) {
            LOG_W(common, "swi_spi_proc_queue_init_cmd() failed(%d)", ret);
            goto cleanup;
        }
        break;

    case MT7697_CMD_QUEUE_UNUSED:
        ret = swi_spi_proc_queue_unused_cmd(m2s_info);
        if (ret < 0) {
            LOG_W(common, "swi_spi_proc_queue_unused_cmd() failed(%d)", ret);
            goto cleanup;
        }
        break;

    case MT7697_CMD_QUEUE_RESET:
        ret = swi_spi_proc_queue_reset_cmd(m2s_info);
        if (ret < 0) {
            LOG_W(common, "swi_spi_proc_queue_reset_cmd() failed(%d)", ret);
            goto cleanup;
        }
        break;

    default:
        LOG_W(common, "unhandled cmd(%d)", m2s_info->cmd_hdr.type);
        ret = -1;
        goto cleanup;
    }

cleanup:
    return ret;
}

static size_t swi_spi_queue_write(void* wr_hndl, const uint32_t* buffer, size_t num_words)
{
    swi_spi_queue_data_t* spi_queue_data = (swi_spi_queue_data_t*)wr_hndl;
    const uint32_t buffer_num_words = BF_GET(spi_queue_data->qs->flags, FLAGS_NUM_WORDS_OFFSET,
                                             FLAGS_NUM_WORDS_WIDTH);
    uint16_t read_offset;
    uint16_t write_offset;
    size_t words_written = 0;
    int32_t err;

    if (!BF_GET(spi_queue_data->qs->flags, FLAGS_IN_USE_OFFSET, FLAGS_IN_USE_WIDTH)) {
        LOG_W(common, "queue unused");
        goto cleanup;
    }

    if (swi_spi_queue_get_num_free_words(spi_queue_data->qs) < num_words) {
//        LOG_W(common, "no space free(%u) < req(%u)",
//              swi_spi_queue_get_num_free_words(spi_queue_data->qs), num_words);
        goto cleanup;
    }

    read_offset = spi_queue_data->qs->read_offset;
    write_offset = spi_queue_data->qs->write_offset;
    if (write_offset >= read_offset) {
        const size_t words_until_end = buffer_num_words - write_offset;
        const size_t words_available_for_write =
            (read_offset == 0) ? (words_until_end - 1) : words_until_end;
        const size_t num_words_to_write =
            (num_words <= words_available_for_write) ? num_words : words_available_for_write;
        uint32_t* const write_to =
            (uint32_t*)(spi_queue_data->qs->base_address + (write_offset * sizeof(uint32_t)));

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
        const size_t num_words_to_write =
            (num_words <= words_until_read) ? num_words : words_until_read;
        uint32_t* const write_to =
            (uint32_t*)(spi_queue_data->qs->base_address + (write_offset * sizeof(uint32_t)));

        memcpy(write_to, &buffer[words_written], num_words_to_write * sizeof(uint32_t));
        words_written += num_words_to_write;
        num_words -= num_words_to_write;
        write_offset += num_words_to_write;
    }

    if (write_offset >= buffer_num_words) {
        LOG_E(common, "invalid write offset(%u) >= size(%u)", write_offset, buffer_num_words);
        configASSERT(write_offset < buffer_num_words);
    }

    spi_queue_data->qs->write_offset = write_offset;

    if (words_written > 0) {
        swi_spi_set_slave_to_master_mailbox(1 << spi_queue_data->ch);
        err = swi_spi_queue_notify_master();
        if (err < 0) {
            LOG_E(common, "swi_spi_queue_notify_master() failed(%d)", err);
            words_written = err;
            goto cleanup;
        }
    }

cleanup:
//    LOG_I(common, "q(%d) words written/offset(%d/%u)", spi_queue_data->ch, words_written, write_offset);
    return words_written;
}

static int32_t swi_spi_queue_notify_master(void)
{
    spi_queue_info->gpio_irq =
        (spi_queue_info->gpio_irq == HAL_GPIO_DATA_LOW) ? HAL_GPIO_DATA_HIGH : HAL_GPIO_DATA_LOW;
    hal_gpio_status_t status = hal_gpio_set_output(HAL_GPIO_59, spi_queue_info->gpio_irq);
    if (status != HAL_GPIO_STATUS_OK) {
        LOG_W(common, "hal_gpio_set_output() failed(%d)", status);
    }

    return status;
}

static void swi_spi_queue_m2s_task(void *pvParameters)
{
    swi_m2s_info_t* m2s_info = (swi_m2s_info_t*)pvParameters;
    swi_spi_queue_data_t* spi_queue_data = (swi_spi_queue_data_t*)m2s_info->rd_hndl;

    LOG_I(common, "start task('%s')", m2s_info->task.name);
    while (1) {
        int32_t ret;

        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);

        size_t avail = swi_spi_get_num_words_in_queue(spi_queue_data->qs);
//        LOG_I(common, "avail(%u)", avail);
        while (((m2s_info->cmd_hdr.len) &&
                (avail >= LEN_TO_WORD(m2s_info->cmd_hdr.len - sizeof(mt7697_cmd_hdr_t)))) ||
               ((!m2s_info->cmd_hdr.len) &&
                (avail >= LEN_TO_WORD(sizeof(mt7697_cmd_hdr_t))))) {
            if (!m2s_info->cmd_hdr.len) {
                size_t words_read = m2s_info->hw_read(
                    spi_queue_data, (uint32_t*)&m2s_info->cmd_hdr,
                    LEN_TO_WORD(sizeof(mt7697_cmd_hdr_t)));
                if (words_read != LEN_TO_WORD(sizeof(mt7697_cmd_hdr_t))) {
                    LOG_W(common, "hw_read() failed(%d)", words_read);
                    break;
                }

                avail = swi_spi_get_num_words_in_queue(spi_queue_data->qs);
//                LOG_I(common, "avail(%u)", avail);
            }

//            LOG_I(common, "len(%u)", m2s_info->cmd_hdr.len);
            if (avail < LEN_TO_WORD(m2s_info->cmd_hdr.len - sizeof(mt7697_cmd_hdr_t))) {
                LOG_W(common, "queue need more data");
                break;
            }

            switch (m2s_info->cmd_hdr.grp) {
            case MT7697_CMD_GRP_QUEUE:
                ret = swi_spi_proc_queue_cmd(m2s_info);
                if (ret < 0) {
                    LOG_W(common, "swi_spi_proc_queue_cmd() failed(%d)", ret);
                }
                break;

            case MT7697_CMD_GRP_80211:
                ret = swi_wifi_proc_cmd(m2s_info);
                if (ret < 0) {
                    LOG_W(common, "swi_wifi_proc_cmd() failed(%d)", ret);
                }
                break;

            case MT7697_CMD_GRP_BT:
            default:
                LOG_W(common, "invalid cmd grp(%d)", m2s_info->cmd_hdr.grp);
                break;
            }

            m2s_info->cmd_hdr.len = 0;
            avail = swi_spi_get_num_words_in_queue(spi_queue_data->qs);
//            LOG_I(common, "avail(%u)", avail);
        }
    }

    LOG_W(common, "end task('%s')", m2s_info->task.name);
}

static void swi_spi_slave_interrupt_handler(void* data)
{
    swi_spi_queue_info_t* spi_queue_info = (swi_spi_queue_info_t*)data;

    // 1. Read a copy of the master to slave mailbox
    // 2. Clear the bits that were read as being set
    // 3. Perform handling for each of the bits that were set
    // This order of operations ensures that no notifications are lost.
    const uint8_t m2s_mailbox_bits = BF_GET(*SPIS_REG_MAILBOX_M2S, M2S_MAILBOX_REG_MAILBOX_OFFSET,
                                            M2S_MAILBOX_REG_MAILBOX_WIDTH);
    swi_spi_clear_master_to_slave_mailbox(m2s_mailbox_bits);

//    LOG_I(common, "M2S mbox(0x%02x)", m2s_mailbox_bits);
    if (m2s_mailbox_bits) {
        for (uint16_t i = 0; i < NUM_CHANNELS; i++) {
            if (m2s_mailbox_bits & (1 << i)) {
                BaseType_t xHigherPriorityTaskWoken;

                swi_queue_dir_e direction = BF_GET(spi_queue_info->data[i].qs->flags,
                                                   FLAGS_DIRECTION_OFFSET, FLAGS_DIRECTION_WIDTH);
                if (QUEUE_DIRECTION_M2S == direction) {
                    vTaskNotifyGiveFromISR(spi_queue_info->data[i].dir.m2s.task.hndl,
                                           &xHigherPriorityTaskWoken);
                    if (xHigherPriorityTaskWoken)
                        portYIELD_FROM_ISR(xHigherPriorityTaskWoken);
                }
                else if (QUEUE_DIRECTION_S2M == direction) {
                    EventBits_t uxBits =
                        xEventGroupGetBitsFromISR(spi_queue_info->data[i].dir.s2m.evt_grp);
                    if (uxBits & SWI_S2M_BLOCKED_WRITER) {
                        mt7697_rsp_hdr_t* req;

                        BaseType_t ret =
                            xQueuePeekFromISR(spi_queue_info->data[i].dir.s2m.sendQ, &req);
                        configASSERT(ret == pdTRUE);
                        if (swi_spi_queue_get_num_free_words(spi_queue_info->data[i].qs) >=
                            LEN_TO_WORD(LEN32_ALIGNED(req->cmd.len))) {
//                            LOG_I(common, "channel(%u) unblocked writer", i);
                            uxBits = xEventGroupSetBitsFromISR(
                                spi_queue_info->data[i].dir.s2m.evt_grp, SWI_S2M_UNBLOCK_WRITER,
                                &xHigherPriorityTaskWoken);
                            if (xHigherPriorityTaskWoken)
                                portYIELD_FROM_ISR(xHigherPriorityTaskWoken);
                        }
                    }
                }
            }
        }
    }
}

int32_t swi_spi_queue_init(swi_spi_queue_info_t* queue_info)
{
    int ret = 0;

    // EPT is used for pin muxing, so no need to configure muxing for SPI slave
    LOG_I(common, "SPI queues init");
    spi_queue_info = queue_info;

    spi_queue_info->gpio_irq = HAL_GPIO_DATA_LOW;
    hal_gpio_status_t status = hal_gpio_set_output(HAL_GPIO_59, spi_queue_info->gpio_irq);
    if (status != HAL_GPIO_STATUS_OK) {
        LOG_W(common, "hal_gpio_set_output() failed(%d)", status);
        ret = -1;
        goto cleanup;
    }

    for (unsigned int i = 0; i < NUM_CHANNELS; i++) {
        spi_queue_info->data[i].ch = i;
        spi_queue_info->data[i].qs = &queues[i];
        spi_queue_info->data[i].qs->base_address = (uint32_t)&spi_queue_info->data[i].queue;

        swi_queue_dir_e direction = BF_GET(spi_queue_info->data[i].qs->flags,
                                           FLAGS_DIRECTION_OFFSET, FLAGS_DIRECTION_WIDTH);
        LOG_I(common, "Channel(%u) direction('%s')", i,
              (QUEUE_DIRECTION_M2S == direction) ? "M2S" : "S2M");
        if (QUEUE_DIRECTION_M2S == direction) {
            ret = swi_m2s_init(&spi_queue_info->data[i].dir.m2s, swi_spi_queue_read,
                               swi_spi_queue_m2s_task, &spi_queue_info->data[i], i);
            if (ret < 0) {
                LOG_W(common, "swi_m2s_init() failed(%d)", ret);
                goto cleanup;
            }
        }
        else if (QUEUE_DIRECTION_S2M == direction) {
            ret = swi_s2m_init(&spi_queue_info->data[i].dir.s2m, swi_spi_queue_write,
                               &spi_queue_info->data[i], i);
            if (ret < 0) {
                LOG_W(common, "swi_s2m_init() failed(%d)", ret);
                goto cleanup;
            }
        }
    }

    ret = swi_wifi_init(&spi_queue_info->data[QUEUE_WIFI_S2M].dir.s2m);
    if (ret < 0) {
        LOG_E(common, "swi_wifi_init() failed(%d)", ret);
        goto cleanup;
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

    slave_status = hal_spi_slave_register_callback(HAL_SPI_SLAVE_0, swi_spi_slave_interrupt_handler,
                                                   spi_queue_info);
    configASSERT(slave_status == HAL_SPI_SLAVE_STATUS_OK);

cleanup:
    return ret;
}

size_t swi_spi_queue_read(void* rd_hndl, uint32_t* buffer, size_t num_words)
{
    swi_spi_queue_data_t* spi_queue_data = (swi_spi_queue_data_t*)rd_hndl;
    const uint32_t buffer_num_words = BF_GET(spi_queue_data->qs->flags, FLAGS_NUM_WORDS_OFFSET,
                                             FLAGS_NUM_WORDS_WIDTH);
    uint16_t write_offset;
    uint16_t read_offset;
    size_t words_read = 0;
    int32_t err;

    write_offset = spi_queue_data->qs->write_offset;
    read_offset = spi_queue_data->qs->read_offset;
    if (read_offset > write_offset) {
        const size_t words_until_end = buffer_num_words - read_offset;
        const uint32_t* read_from =
            (uint32_t*)(spi_queue_data->qs->base_address + (read_offset * sizeof(uint32_t)));
        const size_t num_words_to_read =
            (num_words <= words_until_end) ? num_words : words_until_end;

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
        const uint32_t* read_from =
            (uint32_t*)(spi_queue_data->qs->base_address + (read_offset * sizeof(uint32_t)));
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

    spi_queue_data->qs->read_offset = read_offset;

    if (words_read > 0) {
        swi_spi_set_slave_to_master_mailbox(1 << spi_queue_data->ch);
        err = swi_spi_queue_notify_master();
        if (err < 0) {
            LOG_E(common, "swi_spi_queue_notify_master() failed(%d)", err);
            words_read = err;
            goto cleanup;
        }
    }

cleanup:
//    LOG_I(common, "q(%d) words read/offset(%d/%u)", channel, words_read, read_offset);
    return words_read;
}

size_t swi_spi_queue_get_capacity_in_words(const swi_spi_queue_spec_t* qs)
{
    return swi_spi_get_queue_capacity_in_words(qs);
}

size_t swi_spi_queue_get_num_words_used(const swi_spi_queue_spec_t* qs)
{
    return swi_spi_get_num_words_in_queue(qs);
}

size_t swi_spi_queue_get_num_free_words(const swi_spi_queue_spec_t* qs)
{
    return swi_spi_get_num_free_words_in_queue(qs);
}
