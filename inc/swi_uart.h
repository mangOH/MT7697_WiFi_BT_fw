#ifndef SWI_UART_H
#define SWI_UART_H

#include "hal_uart.h"

#include "swi_s2m.h"
#include "swi_m2s.h"

#define container_of(ptr, type, member) ({ 				\
                const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
                (type *)( (char *)__mptr - offsetof(type,member) );})

#define SWI_UART_TX_VFIFO_SIZE			2048		
#define SWI_UART_TX_VFIFO_THREASHOLD_SIZE	(sizeof(mt7697_rsp_hdr_t))

#define SWI_UART_RX_VFIFO_SIZE			2048
#define SWI_UART_RX_VFIFO_ALERT_SIZE		(sizeof(mt7697_cmd_hdr_t))
#define SWI_UART_RX_VFIFO_THREASHOLD_SIZE	(sizeof(mt7697_cmd_hdr_t) - 1)	

#define mt7697_uart_shutdown_req_t		mt7697_cmd_hdr_t
#define mt7697_uart_shutdown_rsp_t		mt7697_rsp_hdr_t

typedef enum _swi_uart_cmd_types {
	MT7697_CMD_UART_SHUTDOWN_REQ = 0,
	MT7697_CMD_UART_SHUTDOWN_RSP,
} swi_uart_cmd_types;

typedef struct _swi_uart_info_t {
    swi_s2m_info_t          	s2m;
    swi_m2s_info_t		m2s;
    hal_uart_config_t 		uart_config;
    hal_uart_dma_config_t 	dma_config;
    hal_uart_port_t 		port;
} swi_uart_info_t;

size_t swi_uart_send(void*, const uint32_t*, size_t);
size_t swi_uart_recv(void*, uint32_t*, size_t);
int32_t swi_uart_init(swi_uart_info_t*);

#endif // SWI_UART_H
