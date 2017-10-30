#ifndef SWI_M2S_H
#define SWI_M2S_H

#include "FreeRTOS.h"
#include "event_groups.h"

#include "swi_task_info.h"
#include "swi_cmd_defs.h"

#define SWI_M2S_BLOCKED_READER		( 1 << 0 )
#define SWI_M2S_UNBLOCK_READER		( 1 << 1 )

typedef size_t (*read_op)(void*, uint32_t*, size_t);
typedef void (*rx_op)(void*);

typedef struct _swi_m2s_info_t {
    swi_queue_task_t 		task;
    mt7697_cmd_hdr_t 		cmd_hdr;
    EventGroupHandle_t 		evt_grp;
    read_op		        hw_read;
    rx_op			hw_rx;
    void* 			rd_hndl;
} swi_m2s_info_t;

int32_t swi_m2s_init(swi_m2s_info_t*, read_op, rx_op, void*, unsigned int);

#endif
