#include <stdlib.h>
#include "swi_mem_pool.h"

int32_t swi_mem_pool_free_msg(swi_mem_pool_info_t* mem_pool_info, uint8_t* ptr)
{
    swi_mem_pool_t* msg_pool = ((ptr >= mem_pool_info->lo.start) && 
				(ptr < mem_pool_info->lo.end)) ? &mem_pool_info->lo : &mem_pool_info->hi;
    int ret = 0;

    if (xSemaphoreTake(msg_pool->lock, portMAX_DELAY) != pdTRUE) {
	LOG_E(common, "xSemaphoreTake() failed");
	ret = -1;
        goto cleanup;
    }

    configASSERT(msg_pool->free_ptr != NULL);
    configASSERT(ptr >= msg_pool->start);
    configASSERT(ptr < msg_pool->end);
//    LOG_I(common, "ptr(%p)", ptr);
    msg_pool->free_ptr = ptr;

    if (xSemaphoreGive(msg_pool->lock) != pdTRUE) {
	LOG_E(common, "xSemaphoreGive() failed");
	ret = -1;
        goto cleanup;
    }

cleanup:
    return ret;
}

uint8_t* swi_mem_pool_alloc_msg(swi_mem_pool_info_t* mem_pool_info, uint16_t priority, QueueHandle_t sendQ, uint16_t len)
{
    swi_mem_pool_t* msg_pool = priority ? &mem_pool_info->hi : &mem_pool_info->lo;
    uint8_t* ret = NULL;

    if (msg_pool->start != NULL) {
	if (!uxQueueSpacesAvailable(sendQ)) {
	    LOG_E(common, "RTOS send queue no space");
            goto cleanup;
	}
	else if (!priority && (uxQueueSpacesAvailable(sendQ) < SWI_MEM_POOL_SENDQ_HIGH_WATER_MARK)) {
	    LOG_E(common, "low priority message - RTOS send queue high water mark");
            goto cleanup;
	}

	if (xSemaphoreTake(msg_pool->lock, portMAX_DELAY) != pdTRUE) {
	    LOG_E(common, "xSemaphoreTake() failed");
            goto cleanup;
        }

	configASSERT(msg_pool->end);
	configASSERT(msg_pool->alloc_ptr);
	configASSERT(msg_pool->free_ptr);

        if ((msg_pool->alloc_ptr + len) >= msg_pool->end)
	    msg_pool->alloc_ptr = msg_pool->start;

//	LOG_I(common, "alloc(%u: %p -> %p) free(%p) start/end(%p/%p)", 
//	    len, msg_pool->alloc_ptr, msg_pool->alloc_ptr + len, msg_pool->free_ptr, msg_pool->start, msg_pool->end);
	if ((msg_pool->alloc_ptr >= msg_pool->free_ptr) || ((msg_pool->alloc_ptr + len) < msg_pool->free_ptr)) {
//            LOG_I(common, "ret(%p/%u)", msg_pool->alloc_ptr, len);
            ret = msg_pool->alloc_ptr;

	    msg_pool->alloc_ptr += len;
	    configASSERT(msg_pool->alloc_ptr >= msg_pool->start);
	    configASSERT(msg_pool->alloc_ptr < msg_pool->end);   
        }
	else {
	    LOG_W(common, "msg dropped");
	}

	if (xSemaphoreGive(msg_pool->lock) != pdTRUE) {
	    LOG_E(common, "xSemaphoreGive() failed");
            goto cleanup;
        }
    }
    else {
        LOG_W(common, "no msg pool");
    }

cleanup:
    return ret;
}

void swi_mem_pool_reset(swi_mem_pool_t* msg_pool)
{
    msg_pool->alloc_ptr = msg_pool->start;
    msg_pool->free_ptr = msg_pool->end;
}

int32_t swi_mem_pool_init(swi_mem_pool_t* msg_pool, uint32_t num_items, uint32_t len)
{
    int ret = 0;

    if (msg_pool->start == NULL) {
//        LOG_I(common, "init msg pool/len(%u)", len);

        msg_pool->start = malloc(num_items * len);
	if (!msg_pool->start) {
            LOG_W(common, "malloc() failed");
            ret = -1;
	    goto cleanup;
        }

	msg_pool->lock = xSemaphoreCreateMutex();
	if (!msg_pool->lock) {
	    LOG_W(common, "xSemaphoreCreateMutex() failed");
	    ret = -1;
	    goto cleanup;
	}        
    }

    msg_pool->end = msg_pool->start + num_items * len;
    msg_pool->alloc_ptr = msg_pool->start;
    msg_pool->free_ptr = msg_pool->end;
//    LOG_I(common, "alloc/free(%p/%p) start/end(%p/%p)", 
//	msg_pool->alloc_ptr, msg_pool->free_ptr, msg_pool->start, msg_pool->end);

cleanup:
    return ret;
}
