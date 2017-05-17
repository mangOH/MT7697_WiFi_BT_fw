#ifndef SPI_SLAVE_WIFI_H
#define SPI_SLAVE_WIFI_H

// WIFI
#include <wifi_api.h>

#define MT7697_MAX_SCAN_RESULTS		16
#define MT7697_IEEE80211_DATA_LEN	2304
#define MT7697_PIN_LEN			8

#define mt7697_cfg_req			mt7697_cmd_hdr
#define mt7697_get_radio_state_req	mt7697_cmd_hdr
#define mt7697_get_rx_filter_req	mt7697_cmd_hdr
#define mt7697_get_listen_interval_req	mt7697_cmd_hdr
#define mt7697_scan_stop		mt7697_cmd_hdr

#define mt7697_set_radio_state_rsp	mt7697_rsp_hdr
#define mt7697_set_op_mode_rsp		mt7697_rsp_hdr
#define mt7697_set_rx_filter_rsp	mt7697_rsp_hdr
#define mt7697_set_listen_interval_rsp	mt7697_rsp_hdr
#define mt7697_set_pmk_rsp		mt7697_rsp_hdr
#define mt7697_set_security_mode_rsp	mt7697_rsp_hdr
#define mt7697_scan_stop_rsp		mt7697_rsp_hdr

enum mt7697_wifi_cmd_types {
	MT7697_CMD_MAC_ADDR_REQ = 0,
	MT7697_CMD_MAC_ADDR_RSP,
	MT7697_CMD_GET_CFG_REQ,
	MT7697_CMD_GET_CFG_RSP,
	MT7697_CMD_GET_WIRELESS_MODE_REQ,
	MT7697_CMD_GET_WIRELESS_MODE_RSP,
	MT7697_CMD_SET_OP_MODE_REQ,
	MT7697_CMD_SET_OP_MODE_RSP,
	MT7697_CMD_GET_RADIO_STATE_REQ,
	MT7697_CMD_GET_RADIO_STATE_RSP,
	MT7697_CMD_SET_RADIO_STATE_REQ,
	MT7697_CMD_SET_RADIO_STATE_RSP,
	MT7697_CMD_GET_RX_FILTER_REQ,
	MT7697_CMD_GET_RX_FILTER_RSP,
	MT7697_CMD_SET_RX_FILTER_REQ,
	MT7697_CMD_SET_RX_FILTER_RSP,
	MT7697_CMD_GET_LISTEN_INTERVAL_REQ,
	MT7697_CMD_GET_LISTEN_INTERVAL_RSP,
	MT7697_CMD_SET_LISTEN_INTERVAL_REQ,
	MT7697_CMD_SET_LISTEN_INTERVAL_RSP,
	MT7697_CMD_SET_SECURITY_MODE_REQ,
	MT7697_CMD_SET_SECURITY_MODE_RSP,
	MT7697_CMD_GET_SECURITY_MODE_REQ,
	MT7697_CMD_GET_SECURITY_MODE_RSP,
	MT7697_CMD_SCAN_REQ,
	MT7697_CMD_SCAN_RSP,
	MT7697_CMD_SCAN_COMPLETE,
	MT7697_CMD_SCAN_STOP,
	MT7697_CMD_SCAN_STOP_RSP,
	MT7697_CMD_GET_PMK_REQ,
	MT7697_CMD_GET_PMK_RSP,
	MT7697_CMD_SET_PMK_REQ,
	MT7697_CMD_SET_PMK_RSP,
	MT7697_CMD_CONNECT_REQ,
	MT7697_CMD_CONNECT_RSP,
	MT7697_CMD_DISCONNECT_REQ,
	MT7697_CMD_DISCONNECT_RSP,
	MT7697_CMD_TX_RAW,
	MT7697_CMD_RX_RAW,
};

struct mt7697_wifi_info {
	wifi_scan_list_item_t 		ap_data[MT7697_MAX_SCAN_RESULTS];
	uint8_t				tx_data[MT7697_IEEE80211_DATA_LEN];
	uint8_t				rx_data[MT7697_IEEE80211_DATA_LEN];
  	uint8_t				probe_rsp[MT7697_IEEE80211_DATA_LEN];
	uint16_t			scan_idx;
	uint16_t			if_idx;
};

struct mt7697_cmd_hdr {
	uint16_t			len;
	uint8_t				grp;
	uint8_t				type;
} __attribute__((__packed__, aligned(4)));

struct mt7697_rsp_hdr {
	struct mt7697_cmd_hdr		cmd;
	int32_t				result;
} __attribute__((__packed__, aligned(4)));

struct mt7697_mac_addr_req {
	struct mt7697_cmd_hdr		cmd;
	uint32_t			port;
} __attribute__((packed, aligned(4)));

struct mt7697_mac_addr_rsp {
	struct mt7697_rsp_hdr		rsp;
	uint16_t			addr_len;
	uint8_t 			addr[WIFI_MAC_ADDRESS_LENGTH];
} __attribute__((packed, aligned(4)));

struct mt7697_get_wireless_mode_req {
	struct mt7697_cmd_hdr		cmd;
	uint32_t			port;
} __attribute__((packed, aligned(4)));

struct mt7697_get_wireless_mode_rsp {
	struct mt7697_rsp_hdr		rsp;
	uint32_t			mode;
} __attribute__((packed, aligned(4)));

struct mt7697_cfg_rsp {
	struct mt7697_rsp_hdr		rsp;
	wifi_config_t			cfg;
} __attribute__((packed, aligned(4)));

struct mt7697_set_op_mode_req {
	struct mt7697_cmd_hdr		cmd;
	uint32_t			opmode;
} __attribute__((packed, aligned(4)));

struct mt7697_get_radio_state_rsp {
	struct mt7697_rsp_hdr		rsp;
	uint32_t			state;
} __attribute__((packed, aligned(4)));

struct mt7697_set_radio_state_req {
	struct mt7697_cmd_hdr		cmd;
	uint32_t			state;
} __attribute__((packed, aligned(4)));

struct mt7697_get_rx_filter_rsp {
	struct mt7697_rsp_hdr		rsp;
	uint32_t			rx_filter;
} __attribute__((packed, aligned(4)));

struct mt7697_set_rx_filter_req {
	struct mt7697_cmd_hdr		cmd;
	uint32_t			rx_filter;
} __attribute__((packed, aligned(4)));

struct mt7697_get_listen_interval_rsp {
	struct mt7697_rsp_hdr		rsp;
	uint32_t			interval;
} __attribute__((packed, aligned(4)));

struct mt7697_set_listen_interval_req {
	struct mt7697_cmd_hdr		cmd;
	uint32_t			interval;
} __attribute__((packed, aligned(4)));

struct mt7697_scan_req {
	struct mt7697_cmd_hdr		cmd;
	uint32_t 			if_idx;
	uint8_t				mode;
	uint8_t				option;
	uint8_t				ssid_len;
	uint8_t				bssid_len;
	uint8_t				ssid_bssid[WIFI_MAC_ADDRESS_LENGTH + WIFI_MAX_LENGTH_OF_SSID];
} __attribute__((packed, aligned(4)));

struct mt7697_scan_rsp {
	struct mt7697_rsp_hdr		rsp;
	int32_t 			rssi;
	uint32_t 			channel;
	uint32_t			probe_rsp_len;
	uint8_t				probe_rsp[];
} __attribute__((packed, aligned(4)));

struct mt7697_scan_complete_rsp {
	struct mt7697_rsp_hdr		rsp;
	uint32_t 			if_idx;
} __attribute__((packed, aligned(4)));

struct mt7697_get_pmk_req {
	struct mt7697_cmd_hdr		cmd;
	uint32_t			port;
} __attribute__((packed, aligned(4)));

struct mt7697_get_pmk_rsp {
	struct mt7697_rsp_hdr		rsp;
	uint8_t				pmk[WIFI_LENGTH_PMK];
} __attribute__((packed, aligned(4)));

struct mt7697_set_pmk_req {
	struct mt7697_cmd_hdr		cmd;
	uint32_t			port;
	uint8_t				pmk[WIFI_LENGTH_PMK];
} __attribute__((packed, aligned(4)));

struct mt7697_set_security_mode_req {
	struct mt7697_cmd_hdr		cmd;
	uint32_t			port;
	uint32_t			auth_mode;
	uint32_t			encrypt_type;
} __attribute__((packed, aligned(4)));

struct mt7697_get_security_mode_req {
	struct mt7697_cmd_hdr		cmd;
	uint32_t 			if_idx;
	uint32_t			port;
} __attribute__((packed, aligned(4)));

struct mt7697_get_security_mode_rsp {
	struct mt7697_rsp_hdr		rsp;
	uint32_t 			if_idx;
	uint32_t			auth_mode;
	uint32_t			encrypt_type;
} __attribute__((packed, aligned(4)));

struct mt7697_connect_req {
	struct mt7697_cmd_hdr		cmd;
	uint32_t 			if_idx;
	uint32_t			port;
	uint32_t			channel;
	uint32_t			bssid_len;
	uint32_t			ssid_len;
	uint8_t				bssid_ssid[];
} __attribute__((packed, aligned(4)));

struct mt7697_connect_rsp {
	struct mt7697_rsp_hdr		rsp;
	uint32_t 			if_idx;
	uint32_t			channel;
	uint8_t				bssid[WIFI_MAC_ADDRESS_LENGTH];
} __attribute__((packed, aligned(4)));

struct mt7697_disconnect_req {
	struct mt7697_cmd_hdr		cmd;
	uint32_t 			if_idx;
	uint32_t			addr_len;
	uint8_t				addr[];
} __attribute__((packed, aligned(4)));

struct mt7697_disconnect_rsp {
	struct mt7697_rsp_hdr		rsp;
	uint32_t 			if_idx;
	uint8_t				bssid[WIFI_MAC_ADDRESS_LENGTH];
} __attribute__((packed, aligned(4)));

struct mt7697_tx_raw_packet {
   	struct mt7697_cmd_hdr		cmd;
	uint32_t 			len;
	uint8_t				data[];
} __attribute__((packed, aligned(4)));

struct mt7697_rx_raw_packet {
   	struct mt7697_cmd_hdr		cmd;
	uint32_t 			len;
	uint8_t				data[];
} __attribute__((packed, aligned(4)));

int32_t wifi_proc_cmd(uint8_t, uint16_t, uint8_t);

int32_t wifi_station_connected_event_handler(wifi_event_t, uint8_t*, uint32_t);
int32_t wifi_station_port_secure_event_handler(wifi_event_t, uint8_t*, uint32_t);
int32_t wifi_station_disconnected_event_handler(wifi_event_t, uint8_t*, uint32_t);
int32_t wifi_init_done_handler(wifi_event_t, uint8_t*, uint32_t);

#endif
