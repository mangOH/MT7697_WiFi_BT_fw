#ifndef SWI_S2M_H
#define SWI_S2M_H

#include "FreeRTOS.h"
#include "event_groups.h"

#include "swi_task_info.h"
#include "swi_cmd_defs.h"
#include "swi_mem_pool.h"

#define SWI_S2M_BLOCKED_WRITER		( 1 << 0 )
#define SWI_S2M_UNBLOCK_WRITER		( 1 << 1 )

#define SWI_S2M_SENDQ_LEN		128

typedef size_t (*write_op)(void*, const uint32_t*, size_t);
typedef void (*interrupt_op)(void*);

typedef struct _swi_s2m_info_t {
    swi_queue_task_t 		task;
    swi_mem_pool_info_t         msg_pool_info;
    QueueHandle_t               sendQ;
    EventGroupHandle_t 		evt_grp;
    write_op		        hw_write;
    void* 			wr_hndl;
} swi_s2m_info_t;

int32_t swi_s2m_notify_master(swi_s2m_info_t*);
int32_t swi_s2m_send_req(swi_s2m_info_t*, const mt7697_rsp_hdr_t*);
int32_t swi_s2m_send_req_from_isr(swi_s2m_info_t*, const mt7697_rsp_hdr_t*);
int32_t swi_s2m_init(swi_s2m_info_t*, write_op, void*, unsigned int);

#endif
