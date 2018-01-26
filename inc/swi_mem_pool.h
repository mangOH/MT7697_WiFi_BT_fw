#ifndef SWI_MEM_POOL_H
#define SWI_MEM_POOL_H

#include "FreeRTOS.h"
#include "semphr.h"

#define SWI_MEM_POOL_MSG_LO_PRIORITY       0
#define SWI_MEM_POOL_MSG_HI_PRIORITY       1

#define SWI_MEM_POOL_SENDQ_HIGH_WATER_MARK 8

#define SWI_MSG_POOL_LEN                   34
#define SWI_MSG_POOL_HI_LEN                2

typedef struct _swi_mem_pool_t {
    SemaphoreHandle_t lock;
    uint8_t*          start;
    uint8_t*          end;
    uint8_t*          alloc_ptr;
    uint8_t*          free_ptr;
} swi_mem_pool_t;

typedef struct _swi_mem_pool_info_t {
    swi_mem_pool_t lo;
    swi_mem_pool_t hi;
} swi_mem_pool_info_t;

void swi_mem_pool_reset(swi_mem_pool_t*);
int32_t swi_mem_pool_init(swi_mem_pool_t*, uint32_t, uint32_t);
uint8_t* swi_mem_pool_alloc_msg(swi_mem_pool_info_t*, uint16_t, QueueHandle_t, uint16_t);
int32_t swi_mem_pool_free_msg(swi_mem_pool_info_t*, uint8_t*);

#endif // SWI_MEM_POOL_H
