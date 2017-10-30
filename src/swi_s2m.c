#include "swi_s2m.h"

static void swi_s2m_task(void*);

static void swi_s2m_task(void *pvParameters)
{
    swi_s2m_info_t* s2m_info = (swi_s2m_info_t*)pvParameters;

    LOG_I(common, "start task('%s')", s2m_info->task.name);
    while (1) {
	mt7697_rsp_hdr_t* req;
	if (xQueuePeek(s2m_info->sendQ, &req, portMAX_DELAY)) {
//            LOG_I(common, "<-- CMD(%u) len(%u)", channel, req->cmd.type, req->cmd.len);
    	    size_t bWrite = s2m_info->hw_write(s2m_info->wr_hndl, (const uint32_t*)req, LEN_TO_WORD(LEN32_ALIGNED(req->cmd.len)));
    	    if (bWrite != LEN_TO_WORD(LEN32_ALIGNED(req->cmd.len))) {
//		LOG_W(common, "channel(%u) blocked writer", channel);
		EventBits_t uxBits = xEventGroupSetBits(s2m_info->evt_grp, SWI_S2M_BLOCKED_WRITER);
		configASSERT(uxBits & SWI_S2M_BLOCKED_WRITER);

		uxBits = xEventGroupWaitBits(s2m_info->evt_grp, SWI_S2M_UNBLOCK_WRITER, pdTRUE, pdTRUE, portMAX_DELAY);
		configASSERT(uxBits & SWI_S2M_BLOCKED_WRITER);

		uxBits = xEventGroupClearBits(s2m_info->evt_grp, SWI_S2M_BLOCKED_WRITER);
		configASSERT(!(uxBits & SWI_S2M_UNBLOCK_WRITER));
    	    }
	    else {
	        int ret = swi_mem_pool_free_msg(&s2m_info->msg_pool_info, (uint8_t*)req);
		if (ret < 0) {
		    LOG_W(common, "swi_mem_pool_free_msg() failed(%d)", ret);
		    goto cleanup;
		}

	        configASSERT(xQueueReceive(s2m_info->sendQ, &req, 0) == pdTRUE);
	    }
        }
    }

cleanup:
    LOG_W(common, "end task('%s')", s2m_info->task.name);
}

int32_t swi_s2m_send_req(swi_s2m_info_t* s2m_info, const mt7697_rsp_hdr_t* req)
{
    int32_t ret = 0;

    if (xQueueSendToBack(s2m_info->sendQ, &req, portMAX_DELAY) != pdPASS) {
	LOG_W(common, "xQueueSendToBack() failed");
	ret = -1;
	goto cleanup;
    }

cleanup:
    return ret;
}

int32_t swi_s2m_send_req_from_isr(swi_s2m_info_t* s2m_info, const mt7697_rsp_hdr_t* req)
{
    BaseType_t xHigherPriorityTaskWoken;
    int32_t ret = 0;

    if (xQueueSendToBackFromISR(s2m_info->sendQ, &req, &xHigherPriorityTaskWoken) != pdPASS) {
	LOG_W(common, "xQueueSendToBackFromISR() failed");
	ret = -1;
	goto cleanup;
    }

    if (xHigherPriorityTaskWoken)
        portYIELD_FROM_ISR(xHigherPriorityTaskWoken);

cleanup:
    return ret;
}

int32_t swi_s2m_init(swi_s2m_info_t* s2m_info, write_op hw_write, void* wr_hndl, unsigned int idx)
{
    int32_t ret = 0;

    LOG_I(common, "S2M(%u) init", idx);
    s2m_info->hw_write = hw_write;
    s2m_info->wr_hndl = wr_hndl;

    s2m_info->sendQ = xQueueCreate(SWI_S2M_SENDQ_LEN, sizeof(mt7697_rsp_hdr_t*));
    if (!s2m_info->sendQ) {
	LOG_W(common, "xQueueCreate() failed");
	goto cleanup;
    }

    s2m_info->evt_grp = xEventGroupCreate();
    if (!s2m_info->evt_grp) {
	LOG_W(common, "xEventGroupCreate() failed");
	ret = -1;
	goto cleanup;
    }

    EventBits_t uxBits = xEventGroupClearBits(s2m_info->evt_grp, SWI_S2M_BLOCKED_WRITER | SWI_S2M_UNBLOCK_WRITER);
    configASSERT(!(uxBits & SWI_S2M_BLOCKED_WRITER) && !(uxBits & SWI_S2M_UNBLOCK_WRITER));

    snprintf(s2m_info->task.name, sizeof(s2m_info->task.name), "S2M-%u", idx);
    LOG_I(common, "create task('%s')", s2m_info->task.name);
    BaseType_t xReturned = xTaskCreate(swi_s2m_task, s2m_info->task.name, 
                                       SWI_TASK_STACK_SIZE, s2m_info,
                                       tskIDLE_PRIORITY, &s2m_info->task.hndl);      
    if (xReturned != pdPASS) {
        LOG_W(common, "'%s' xTaskCreate() failed(%d)", s2m_info->task.name, xReturned);
        ret = -1;
        goto cleanup;
    }

cleanup:
    return ret;
}

