#include "swi_m2s.h"

int32_t swi_m2s_init(swi_m2s_info_t* m2s_info, read_op hw_read, rx_op hw_rx, void* rd_hndl, unsigned int idx)
{
    int32_t ret = 0;

    LOG_I(common, "M2S(%u) init", idx);
    m2s_info->hw_read = hw_read;
    m2s_info->hw_rx = hw_rx;
    m2s_info->rd_hndl = rd_hndl;

    m2s_info->evt_grp = xEventGroupCreate();
    if (!m2s_info->evt_grp) {
	LOG_W(common, "xEventGroupCreate() failed");
	ret = -1;
	goto cleanup;
    }

    EventBits_t uxBits = xEventGroupClearBits(m2s_info->evt_grp, SWI_M2S_BLOCKED_READER | SWI_M2S_UNBLOCK_READER);
    configASSERT(!(uxBits & SWI_M2S_BLOCKED_READER) && !(uxBits & SWI_M2S_UNBLOCK_READER));

    snprintf(m2s_info->task.name, sizeof(m2s_info->task.name), "M2S-%u", idx);
    LOG_I(common, "create task('%s')", m2s_info->task.name);
    BaseType_t xReturned = xTaskCreate(m2s_info->hw_rx, m2s_info->task.name, 
                                       SWI_TASK_STACK_SIZE, m2s_info,
                                       tskIDLE_PRIORITY, &m2s_info->task.hndl);      
    if (xReturned != pdPASS) {
        LOG_W(common, "'%s' xTaskCreate() failed(%d)", m2s_info->task.name, xReturned);
        ret = -1;
        goto cleanup;
    }

cleanup:
    return ret;
}

