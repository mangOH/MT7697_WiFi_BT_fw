#ifndef SWI_TASK_INFO_H
#define SWI_TASK_INFO_H

#include "FreeRTOS.h"
#include "task.h"

#define SWI_TASK_STACK_SIZE 4096

typedef struct _swi_queue_task_t {
    TaskHandle_t hndl;
    char         name[configMAX_TASK_NAME_LEN];
} swi_queue_task_t;

#endif // SWI_TASK_INFO_H
