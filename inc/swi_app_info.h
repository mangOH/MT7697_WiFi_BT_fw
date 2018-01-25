#ifndef SWI_APP_INFO_H
#define SWI_APP_INFO_H

#include "swi_spi_slave_queues.h"
#include "swi_uart.h"

typedef struct _swi_app_info_t {
    union {
        swi_spi_queue_info_t spi;
        swi_uart_info_t      uart;
    } itf;
} swi_app_info_t;

#endif // SWI_APP_INFO_H
