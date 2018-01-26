#ifndef SWI_WIFI_H
#define SWI_WIFI_H

// WIFI
#include <wifi_api.h>

#include "swi_cmd_defs.h"
#include "swi_mem_pool.h"
#include "swi_m2s.h"
#include "swi_s2m.h"

#define MT7697_MAX_SCAN_RESULTS			32
#define MT7697_IEEE80211_FRAME_LEN		2352
#define MT7697_PIN_LEN				8

#define mt7697_cfg_req_t			mt7697_cmd_hdr_t
#define mt7697_get_rx_filter_req_t		mt7697_cmd_hdr_t
#define mt7697_get_listen_interval_req_t	mt7697_cmd_hdr_t
#define mt7697_scan_stop_t			mt7697_cmd_hdr_t

#define mt7697_set_wireless_mode_rsp_t		mt7697_rsp_hdr_t
#define mt7697_set_op_mode_rsp_t		mt7697_rsp_hdr_t
#define mt7697_set_listen_interval_rsp_t	mt7697_rsp_hdr_t
#define mt7697_set_pmk_rsp_t			mt7697_rsp_hdr_t
#define mt7697_set_channel_rsp_t		mt7697_rsp_hdr_t
#define mt7697_set_bssid_rsp_t			mt7697_rsp_hdr_t
#define mt7697_set_ssid_rsp_t			mt7697_rsp_hdr_t
#define mt7697_set_security_mode_rsp_t		mt7697_rsp_hdr_t
#define mt7697_scan_stop_rsp_t			mt7697_rsp_hdr_t
#define mt7697_reload_settings_rsp_t		mt7697_rsp_hdr_t
#define mt7697_disconnect_rsp_t			mt7697_rsp_hdr_t

typedef enum _mt7697_wifi_cmd_types_e {
	MT7697_CMD_MAC_ADDR_REQ = 0,
	MT7697_CMD_MAC_ADDR_RSP,
	MT7697_CMD_GET_CFG_REQ,
	MT7697_CMD_GET_CFG_RSP,
	MT7697_CMD_GET_WIRELESS_MODE_REQ,
	MT7697_CMD_GET_WIRELESS_MODE_RSP,
	MT7697_CMD_SET_WIRELESS_MODE_REQ,
	MT7697_CMD_SET_WIRELESS_MODE_RSP,
	MT7697_CMD_SET_OP_MODE_REQ,
	MT7697_CMD_SET_OP_MODE_RSP,
	MT7697_CMD_GET_LISTEN_INTERVAL_REQ,
	MT7697_CMD_GET_LISTEN_INTERVAL_RSP,
	MT7697_CMD_SET_LISTEN_INTERVAL_REQ,
	MT7697_CMD_SET_LISTEN_INTERVAL_RSP,
	MT7697_CMD_SET_SECURITY_MODE_REQ,
	MT7697_CMD_SET_SECURITY_MODE_RSP,
	MT7697_CMD_GET_SECURITY_MODE_REQ,
	MT7697_CMD_GET_SECURITY_MODE_RSP,
        MT7697_CMD_SCAN_IND,
	MT7697_CMD_SCAN_REQ,
	MT7697_CMD_SCAN_RSP,
	MT7697_CMD_SCAN_COMPLETE_IND,
	MT7697_CMD_SCAN_STOP,
	MT7697_CMD_SCAN_STOP_RSP,
	MT7697_CMD_SET_PMK_REQ,
	MT7697_CMD_SET_PMK_RSP,
	MT7697_CMD_SET_CHANNEL_REQ,
	MT7697_CMD_SET_CHANNEL_RSP,
	MT7697_CMD_SET_BSSID_REQ,
	MT7697_CMD_SET_BSSID_RSP,
	MT7697_CMD_SET_SSID_REQ,
	MT7697_CMD_SET_SSID_RSP,
	MT7697_CMD_RELOAD_SETTINGS_REQ,
	MT7697_CMD_RELOAD_SETTINGS_RSP,
	MT7697_CMD_CONNECT_IND,
	MT7697_CMD_DISCONNECT_IND,
	MT7697_CMD_DISCONNECT_REQ,
	MT7697_CMD_DISCONNECT_RSP,
	MT7697_CMD_TX_RAW,
	MT7697_CMD_RX_RAW,
} mt7697_wifi_cmd_types_e;

typedef struct __attribute__((packed, aligned(4))) _mt7697_mac_addr_req_t {
	mt7697_cmd_hdr_t		cmd;
	uint32_t			port;
} mt7697_mac_addr_req_t;

typedef struct __attribute__((packed, aligned(4))) _mt7697_mac_addr_rsp_t {
	mt7697_rsp_hdr_t		rsp;
	uint8_t 			addr[LEN32_ALIGNED(WIFI_MAC_ADDRESS_LENGTH)];
} mt7697_mac_addr_rsp_t;

typedef struct __attribute__((packed, aligned(4))) _mt7697_get_wireless_mode_req_t {
	mt7697_cmd_hdr_t		cmd;
	uint32_t			port;
} mt7697_get_wireless_mode_req_t;

typedef struct __attribute__((packed, aligned(4))) _mt7697_get_wireless_mode_rsp_t {
	mt7697_rsp_hdr_t		rsp;
	uint32_t			mode;
} mt7697_get_wireless_mode_rsp_t;

typedef struct __attribute__((packed, aligned(4))) _mt7697_set_wireless_mode_req_t {
	mt7697_cmd_hdr_t		cmd;
	uint32_t			port;
	uint32_t			mode;
} mt7697_set_wireless_mode_req_t;

typedef struct __attribute__((packed, aligned(4))) _mt7697_cfg_rsp_t {
	mt7697_rsp_hdr_t		rsp;
	wifi_config_t			cfg;
} mt7697_cfg_rsp_t;

typedef struct __attribute__((packed, aligned(4))) _mt7697_set_op_mode_req_t {
	mt7697_cmd_hdr_t		cmd;
	uint32_t			opmode;
} mt7697_set_op_mode_req_t;

typedef struct __attribute__((packed, aligned(4))) _mt7697_get_radio_state_rsp_t {
	mt7697_rsp_hdr_t		rsp;
	uint32_t			state;
} mt7697_get_radio_state_rsp_t;

typedef struct __attribute__((packed, aligned(4))) _mt7697_set_radio_state_req_t {
	mt7697_cmd_hdr_t		cmd;
	uint32_t			state;
} mt7697_set_radio_state_req_t;

typedef struct __attribute__((packed, aligned(4))) _mt7697_get_listen_interval_rsp_t {
	mt7697_rsp_hdr_t		rsp;
	uint32_t			interval;
} mt7697_get_listen_interval_rsp_t;

typedef struct __attribute__((packed, aligned(4))) _mt7697_set_listen_interval_req_t {
	mt7697_cmd_hdr_t		cmd;
	uint32_t			interval;
} mt7697_set_listen_interval_req_t;

typedef struct __attribute__((packed, aligned(4))) _mt7697_reload_settings_req_t {
	mt7697_cmd_hdr_t		cmd;
	uint32_t			if_idx;
} mt7697_reload_settings_req_t;

typedef struct __attribute__((packed, aligned(4))) _mt7697_scan_req_t {
	mt7697_cmd_hdr_t		cmd;
	uint32_t 			if_idx;
	uint32_t			mode;
	uint32_t			option;
	uint32_t			bssid_len;
	uint8_t				bssid[LEN32_ALIGNED(WIFI_MAC_ADDRESS_LENGTH)];
	uint32_t			ssid_len;
	uint8_t				ssid[LEN32_ALIGNED(WIFI_MAX_LENGTH_OF_SSID)];
} mt7697_scan_req_t;

typedef struct __attribute__((packed, aligned(4))) _mt7697_scan_rsp_t {
	mt7697_rsp_hdr_t		rsp;
	uint32_t 			if_idx;
} mt7697_scan_rsp_t;

typedef struct __attribute__((packed, aligned(4))) _mt7697_scan_ind_t {
	mt7697_rsp_hdr_t		rsp;
	int32_t 			rssi;
	uint32_t 			channel;
	uint8_t				probe_rsp[];
} mt7697_scan_ind_t;

typedef struct __attribute__((packed, aligned(4))) _mt7697_scan_complete_ind_t {
	mt7697_rsp_hdr_t		rsp;
	uint32_t 			if_idx;
} mt7697_scan_complete_ind_t;

typedef struct __attribute__((packed, aligned(4))) _mt7697_set_pmk_req_t {
	mt7697_cmd_hdr_t		cmd;
	uint32_t			port;
	uint8_t				pmk[LEN32_ALIGNED(WIFI_LENGTH_PASSPHRASE)];
} mt7697_set_pmk_req_t;

typedef struct __attribute__((packed, aligned(4))) _mt7697_set_channel_req_t {
	mt7697_cmd_hdr_t		cmd;
	uint32_t			port;
	uint32_t			ch;
} mt7697_set_channel_req_t;

typedef struct __attribute__((packed, aligned(4))) _mt7697_set_bssid_req_t {
	mt7697_cmd_hdr_t		cmd;
	uint8_t				bssid[LEN32_ALIGNED(WIFI_MAC_ADDRESS_LENGTH)];
} mt7697_set_bssid_req_t;

typedef struct __attribute__((packed, aligned(4))) _mt7697_set_ssid_req_t {
	mt7697_cmd_hdr_t		cmd;
	uint32_t			port;
	uint32_t			len;
	uint8_t				ssid[LEN32_ALIGNED(WIFI_MAX_LENGTH_OF_SSID)];
} mt7697_set_ssid_req_t;

typedef struct __attribute__((packed, aligned(4))) _mt7697_set_security_mode_req_t {
	mt7697_cmd_hdr_t		cmd;
	uint32_t			port;
	uint32_t			auth_mode;
	uint32_t			encrypt_type;
} mt7697_set_security_mode_req_t;

typedef struct __attribute__((packed, aligned(4))) _mt7697_get_security_mode_req_t {
	mt7697_cmd_hdr_t		cmd;
	uint32_t 			if_idx;
	uint32_t			port;
} mt7697_get_security_mode_req_t;

typedef struct __attribute__((packed, aligned(4))) _mt7697_get_security_mode_rsp_t {
	mt7697_rsp_hdr_t		rsp;
	uint32_t 			if_idx;
	uint32_t			auth_mode;
	uint32_t			encrypt_type;
} mt7697_get_security_mode_rsp_t;

typedef struct __attribute__((packed, aligned(4))) _mt7697_connect_ind_t {
	mt7697_rsp_hdr_t		rsp;
	uint32_t 			if_idx;
	uint32_t			channel;
	uint8_t				bssid[LEN32_ALIGNED(WIFI_MAC_ADDRESS_LENGTH)];
} mt7697_connect_ind_t;

typedef struct __attribute__((packed, aligned(4))) _mt7697_disconnect_req_t {
	mt7697_cmd_hdr_t		cmd;
	uint32_t			port;
	uint8_t				addr[LEN32_ALIGNED(WIFI_MAC_ADDRESS_LENGTH)];
} mt7697_disconnect_req_t;

typedef struct __attribute__((packed, aligned(4))) _mt7697_disconnect_ind_t {
	mt7697_rsp_hdr_t		rsp;
	uint32_t 			if_idx;
	uint8_t				bssid[LEN32_ALIGNED(WIFI_MAC_ADDRESS_LENGTH)];
} mt7697_disconnect_ind_t;

typedef struct __attribute__((packed, aligned(4))) _mt7697_tx_raw_packet_t {
   	mt7697_cmd_hdr_t		cmd;
	uint32_t 			len;
	uint8_t				data[LEN32_ALIGNED(MT7697_IEEE80211_FRAME_LEN)];
} mt7697_tx_raw_packet_t;

typedef struct __attribute__((packed, aligned(4))) _mt7697_rx_raw_packet_t {
   	mt7697_rsp_hdr_t		hdr;
	uint8_t				data[];
} mt7697_rx_raw_packet_t;

typedef struct _mt7697_wifi_info_t {
	uint8_t				tx_data[LEN32_ALIGNED(MT7697_IEEE80211_FRAME_LEN)];
	struct netif			*netif;
        swi_s2m_info_t 			*s2m_info;
  	uint16_t			if_idx;
	uint8_t 			channel;
        uint8_t                         reload;
} mt7697_wifi_info_t;

int32_t swi_wifi_proc_cmd(swi_m2s_info_t*);
int32_t swi_wifi_init(swi_s2m_info_t*);

#endif
