#include <syslog.h>
#include <hal_gpio.h>

#include "swi_wifi.h"
#include "swi_uart.h"

static void swi_uart_callback(hal_uart_callback_event_t, void*);
static void swi_uart_m2s_task(void*);

static uint8_t rx_vfifo_buffer[SWI_UART_RX_VFIFO_SIZE] __attribute__ ((aligned(4), section(".noncached_zidata")));
static uint8_t tx_vfifo_buffer[SWI_UART_TX_VFIFO_SIZE] __attribute__ ((aligned(4), section(".noncached_zidata")));

static void swi_uart_callback(hal_uart_callback_event_t status, void *user_data)
{
     swi_uart_info_t* uart_info = (swi_uart_info_t*)user_data;
     BaseType_t xHigherPriorityTaskWoken;

//     LOG_I(common, "UART event(%u)", status);
     if (status == HAL_UART_EVENT_READY_TO_WRITE) {
//	LOG_I(common, "UART ready to WRITE");
	EventBits_t uxBits = xEventGroupGetBitsFromISR(uart_info->s2m.evt_grp);
        if (uxBits & SWI_S2M_BLOCKED_WRITER) {
//	    LOG_I(common, "S2M unblock Tx");
            uxBits = xEventGroupSetBitsFromISR(uart_info->s2m.evt_grp, SWI_S2M_UNBLOCK_WRITER, &xHigherPriorityTaskWoken);
            if (xHigherPriorityTaskWoken)
                portYIELD_FROM_ISR(xHigherPriorityTaskWoken);
        }
    }
    else if (status == HAL_UART_EVENT_READY_TO_READ) {
//	LOG_I(common, "UART ready to READ");
        EventBits_t uxBits = xEventGroupGetBitsFromISR(uart_info->m2s.evt_grp);
        if (uxBits & SWI_M2S_BLOCKED_READER) {
//	    LOG_I(common, "M2S unblock Rx");
            uxBits = xEventGroupSetBitsFromISR(uart_info->m2s.evt_grp, SWI_M2S_UNBLOCK_READER, &xHigherPriorityTaskWoken);
            if (xHigherPriorityTaskWoken)
                portYIELD_FROM_ISR(xHigherPriorityTaskWoken);
        }
    }
    else if (status == HAL_UART_EVENT_TRANSACTION_ERROR) {
        LOG_W(common, "Transaction Error");
    }
}

static int32_t swi_uart_proc_shutdown_req(swi_m2s_info_t* m2s_info)
{
    swi_uart_info_t* uart_info = container_of(m2s_info, swi_uart_info_t, m2s);
    int32_t ret = 0;

    mt7697_uart_shutdown_rsp_t* rsp = (mt7697_uart_shutdown_rsp_t*)swi_mem_pool_alloc_msg(&uart_info->s2m.msg_pool_info,
                                                                                          SWI_MEM_POOL_MSG_HI_PRIORITY,
                                                                                          uart_info->s2m.sendQ,
                                                                                          LEN32_ALIGNED(sizeof(mt7697_uart_shutdown_rsp_t)));
    if (!rsp) {
	LOG_W(common, "swi_mem_pool_alloc_msg() failed");
        ret = -1;
	goto cleanup;
    }

    rsp->cmd.len = sizeof(mt7697_uart_shutdown_rsp_t);
    rsp->cmd.grp = MT7697_CMD_GRP_UART;
    rsp->cmd.type = MT7697_CMD_UART_SHUTDOWN_RSP;

    LOG_I(common, "--> UART SHUTDOWN(%d)", m2s_info->cmd_hdr.len);
    if (m2s_info->cmd_hdr.len != sizeof(mt7697_uart_shutdown_req_t)) {
	LOG_W(common, "invalid UART SHUTDOWN req len(%d != %d)", m2s_info->cmd_hdr.len, sizeof(mt7697_uart_shutdown_req_t));
	ret = -1;
	goto cleanup;
    }

cleanup:
    if (rsp) {
        rsp->result = ret;
        LOG_I(common, "<-- UART SHUTDOWN rsp len(%u) result(%d)", rsp->cmd.len, ret);
        int32_t err = swi_s2m_send_req(&uart_info->s2m, (mt7697_rsp_hdr_t*)rsp);
        if (err < 0) {
            LOG_W(common, "swi_s2m_send_req() failed(%d)", err);
            ret = ret ? ret:err;
        }
    }

    return ret;
}

static int32_t swi_uart_proc_cmd(swi_m2s_info_t* m2s_info)
{
    int32_t ret = 0;

    switch (m2s_info->cmd_hdr.type) {
    case MT7697_CMD_UART_SHUTDOWN_REQ:
        ret = swi_uart_proc_shutdown_req(m2s_info);
	if (ret) {
	    LOG_W(common, "swi_uart_proc_shutdown_req() failed(%d)", ret);
	}
        break;

    default:
	LOG_W(common, "invalid cmd type(%d)", m2s_info->cmd_hdr.type);
	ret = -1;
	break;
    }

    return ret;
}

static void swi_uart_m2s_task(void* param)
{
    swi_m2s_info_t* m2s_info = (swi_m2s_info_t*)param;
    int32_t ret;

    LOG_I(common, "start task('%s')", m2s_info->task.name);
    while (1) {
	size_t words_read = m2s_info->hw_read(m2s_info->rd_hndl, (uint32_t*)&m2s_info->cmd_hdr, LEN_TO_WORD(sizeof(mt7697_cmd_hdr_t)));
	if (words_read != LEN_TO_WORD(sizeof(mt7697_cmd_hdr_t))) {
	    LOG_W(common, "hw_read() failed(%d)", words_read);
	    break;
	}

        switch (m2s_info->cmd_hdr.grp) {
	    case MT7697_CMD_GRP_UART:
		ret = swi_uart_proc_cmd(m2s_info);
	        if (ret < 0) {
	            LOG_W(common, "swi_uart_proc_cmd() failed(%d)", ret);
	        }
		break;

	    case MT7697_CMD_GRP_80211:
	        ret = swi_wifi_proc_cmd(m2s_info);
	        if (ret < 0) {
	            LOG_W(common, "swi_wifi_proc_cmd() failed(%d)", ret);
	        }
	        break;

            case MT7697_CMD_GRP_QUEUE:
	    case MT7697_CMD_GRP_BT:
	    default:
	        LOG_W(common, "invalid cmd grp(%d)", m2s_info->cmd_hdr.grp);
                break;
	    }

	    m2s_info->cmd_hdr.len = 0;
    }

    LOG_W(common, "end task('%s')", m2s_info->task.name);
}

size_t swi_uart_send(void* wr_hndl, const uint32_t* buff, size_t len)
{
    swi_uart_info_t* uart_info = (swi_uart_info_t*)wr_hndl;
    uint8_t *pbuf = (uint8_t*)buff;
    size_t snd_cnt;
    size_t left = len * sizeof(uint32_t);

//    LOG_W(common, "S2M Tx(%u)", len);		
    while (1) {
        snd_cnt = hal_uart_send_dma(uart_info->port, pbuf, left);
//        LOG_W(common, "S2M Tx sent(%u)", snd_cnt);	
        left -= snd_cnt;
        pbuf += snd_cnt;
        if (!left) break;

//	LOG_W(common, "S2M blocked Tx");
        EventBits_t uxBits = xEventGroupSetBits(uart_info->s2m.evt_grp, SWI_S2M_BLOCKED_WRITER);
//        configASSERT(uxBits & SWI_S2M_BLOCKED_WRITER);

	uxBits = xEventGroupWaitBits(uart_info->s2m.evt_grp, SWI_S2M_UNBLOCK_WRITER, pdTRUE, pdTRUE, portMAX_DELAY);
//	configASSERT(uxBits & SWI_S2M_BLOCKED_WRITER);

	uxBits = xEventGroupClearBits(uart_info->s2m.evt_grp, SWI_S2M_BLOCKED_WRITER);
//	configASSERT(!(uxBits & SWI_S2M_UNBLOCK_WRITER));
    }

    return len;
}

size_t swi_uart_recv(void* rd_hndl, uint32_t* buff, size_t len)
{
    swi_uart_info_t* uart_info = (swi_uart_info_t*)rd_hndl;
    uint8_t *pbuf = (uint8_t*)buff;
    size_t left = len * sizeof(uint32_t);
    uint32_t rcv_cnt;

//    LOG_W(common, "M2S Rx(%u)", len);
    while (1) {
        rcv_cnt = hal_uart_receive_dma(uart_info->port, pbuf, left);
//        LOG_W(common, "M2S Rx received(%u)", rcv_cnt);
        left -= rcv_cnt;
        pbuf += rcv_cnt;
        if (!left) break;

//	LOG_W(common, "M2S blocked Rx");
        EventBits_t uxBits = xEventGroupSetBits(uart_info->m2s.evt_grp, SWI_M2S_BLOCKED_READER);
//        configASSERT(uxBits & SWI_M2S_BLOCKED_READER);

	uxBits = xEventGroupWaitBits(uart_info->m2s.evt_grp, SWI_M2S_UNBLOCK_READER, pdTRUE, pdTRUE, portMAX_DELAY);
//	configASSERT(uxBits & SWI_M2S_BLOCKED_READER);

	uxBits = xEventGroupClearBits(uart_info->m2s.evt_grp, SWI_M2S_BLOCKED_READER);
//	configASSERT(!(uxBits & SWI_M2S_UNBLOCK_READER));
    }

    return len;
}

int32_t swi_uart_init(swi_uart_info_t* uart_info)
{
    hal_uart_status_t ret;

    LOG_I(common, "uart init port(%d)", HAL_UART_1);

    uart_info->port = HAL_UART_1;
   
    ret = swi_m2s_init(&uart_info->m2s, swi_uart_recv, swi_uart_m2s_task, uart_info, 0);
    if (ret < 0) {
	LOG_W(common, "swi_m2s_init() failed(%d)", ret);
	goto cleanup;
    }	
        
    ret = swi_s2m_init(&uart_info->s2m, swi_uart_send, uart_info, 0);
    if (ret < 0) {
        LOG_W(common, "swi_s2m_init() failed(%d)", ret);
	goto cleanup;
    }

    uart_info->uart_config.baudrate = HAL_UART_BAUDRATE_921600;
    uart_info->uart_config.parity = HAL_UART_PARITY_NONE;
    uart_info->uart_config.stop_bit = HAL_UART_STOP_BIT_1;
    uart_info->uart_config.word_length = HAL_UART_WORD_LENGTH_8;
    ret = hal_uart_init(uart_info->port, &uart_info->uart_config);
    if (ret != HAL_UART_STATUS_OK) {
        LOG_W(common, "hal_uart_init() failed(%d)", ret);
        goto cleanup;
    }

    ret = hal_uart_set_hardware_flowcontrol(uart_info->port);
    if (ret != HAL_UART_STATUS_OK) {
        LOG_W(common, "hal_uart_set_hardware_flowcontrol() failed(%d)", ret);
        goto cleanup;
    }

    uart_info->dma_config.receive_vfifo_alert_size = SWI_UART_RX_VFIFO_ALERT_SIZE;
    uart_info->dma_config.receive_vfifo_buffer = rx_vfifo_buffer;
    uart_info->dma_config.receive_vfifo_buffer_size = SWI_UART_RX_VFIFO_SIZE;
    uart_info->dma_config.receive_vfifo_threshold_size = SWI_UART_RX_VFIFO_THREASHOLD_SIZE;

    uart_info->dma_config.send_vfifo_buffer = tx_vfifo_buffer;
    uart_info->dma_config.send_vfifo_buffer_size = SWI_UART_TX_VFIFO_SIZE;
    uart_info->dma_config.send_vfifo_threshold_size = SWI_UART_TX_VFIFO_THREASHOLD_SIZE;
    ret = hal_uart_set_dma(uart_info->port, &uart_info->dma_config);
    if (ret != HAL_UART_STATUS_OK) {
        LOG_W(common, "hal_uart_set_dma() failed(%d)", ret);
        goto cleanup;
    }

    ret = hal_uart_register_callback(uart_info->port, swi_uart_callback, (void*)uart_info);
    if (ret != HAL_UART_STATUS_OK) {
        LOG_W(common, "hal_uart_register_callback() failed(%d)", ret);
        goto cleanup;
    }

    ret = swi_mem_pool_init(&uart_info->s2m.msg_pool_info.lo, SWI_MSG_POOL_LEN, MT7697_IEEE80211_FRAME_LEN);
    if (ret < 0) {
        LOG_W(common, "swi_mem_pool_init() failed(%d)", ret);
	goto cleanup;
    }

    ret = swi_mem_pool_init(&uart_info->s2m.msg_pool_info.hi, SWI_MSG_POOL_HI_LEN, MT7697_IEEE80211_FRAME_LEN);
    if (ret < 0) {
        LOG_W(common, "swi_mem_pool_init() failed(%d)", ret);
	goto cleanup;
    }

    ret = swi_wifi_init(&uart_info->s2m);
    if (ret < 0) {
	LOG_E(common, "swi_wifi_init() failed(%d)", ret);
	goto cleanup;
    }

cleanup:
    return ret;
}

