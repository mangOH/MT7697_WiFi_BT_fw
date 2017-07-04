// stdlib
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

// FreeRTOS
#include <FreeRTOS.h>
#include <task.h>

#include <wifi_api.h>
#include <wifi_rx_desc.h>
#include <wifi_private_api.h>

// SWI
#include "spi_slave_queues.h"
#include "spi_slave_wifi.h"

struct mt7697_wifi_info wifi_info __attribute__((__section__(".spi_slave"), unused)) = {
    .if_idx = (uint16_t)-1,
    .channel = 0,
};

static bool wifi_validate_wifi_port(uint32_t port)
{
    return ((port >= WIFI_PORT_STA) && (port <= WIFI_PORT_AP));
}

static int32_t wifi_rx_data_evt_hndlr(uint8_t* payload, uint32_t length)
{
    struct mt7697_rx_raw_packet	rx_req;
    P_HW_MAC_RX_DESC_T pRxWI = (P_HW_MAC_RX_DESC_T)payload;
    uint8_t* pucMacHeader;       /* 802.11 header  */
    uint8_t* pucPayload;         /* 802.11 payload */
    int32_t ret = 1;
    uint16_t u2PayloadLength;
    uint16_t u2RxStatusOffst = sizeof(HW_MAC_RX_DESC_T);
    uint8_t ucRxPktType = HAL_RX_STATUS_GET_PKT_TYPE(pRxWI);
    uint8_t ucMacHeaderLength;

    // =======  Process RX Vector (if any) ========
    if (ucRxPktType != RX_PKT_TYPE_RX_DATA) {
        LOG_W(common, "unhandled packet type(%u)", ucRxPktType);
        goto cleanup;
    }

    if (ucRxPktType == RX_PKT_TYPE_RX_DATA) {
        uint16_t u2GrpOffst = sizeof(HW_MAC_RX_DESC_T);
        uint8_t ucGroupVLD = HAL_RX_STATUS_GET_GROUP_VLD(pRxWI);

        // RX Status Group
        if (ucGroupVLD & BIT(RX_GROUP_VLD_4)) {
            u2GrpOffst += sizeof(HW_MAC_RX_STS_GROUP_4_T);
        }

        if (ucGroupVLD & BIT(RX_GROUP_VLD_1)) {
            u2GrpOffst += sizeof(HW_MAC_RX_STS_GROUP_1_T);
        }

        if (ucGroupVLD & BIT(RX_GROUP_VLD_2)) {
            u2GrpOffst += sizeof(HW_MAC_RX_STS_GROUP_2_T);
        }

        if (ucGroupVLD & BIT(RX_GROUP_VLD_3)) {
//            P_HW_MAC_RX_STS_GROUP_3_T grp3 = (P_HW_MAC_RX_STS_GROUP_3_T)(payload + u2GrpOffst);
            u2GrpOffst += sizeof(HW_MAC_RX_STS_GROUP_3_T);
        }

        u2RxStatusOffst = u2GrpOffst;
    }

    // Locate the MAC Header based on GroupVLD
    pucMacHeader = (uint8_t*)(((uint32_t)pRxWI + (HAL_RX_STATUS_GET_HEADER_OFFSET(pRxWI)) + u2RxStatusOffst) & 0xFFFFFFFE);
    ucMacHeaderLength = HAL_RX_STATUS_GET_HEADER_LEN(pRxWI);

    pucPayload = (uint8_t*)((uint32_t)(pucMacHeader + ucMacHeaderLength) & 0xFFFFFFFC);
    u2PayloadLength = (uint16_t)(HAL_RX_STATUS_GET_RX_BYTE_CNT(pRxWI) - ((uint32_t)pucPayload - (uint32_t)pRxWI));

    LOG_I(common, "Protocol Version(0x%02x)", *pucMacHeader & 0xC0);
    LOG_I(common, "Type/Sub-type(0x%02x/0x%02x)", *pucMacHeader & 0x30, *pucMacHeader & 0x0F);
    LOG_I(common, "To/From DS(%u/%u)", *(pucMacHeader + 1) & 0x80, *(pucMacHeader + 1) & 0x40);
    LOG_I(common, "More Fragments/Retry/Power Mgmt/More data/WEP/Order(%u/%u/%u/%u/%u/%u)", 
	*(pucMacHeader + 1) & 0x20, *(pucMacHeader + 1) & 0x10, *(pucMacHeader + 1) & 0x08, 
	*(pucMacHeader + 1) & 0x04, *(pucMacHeader + 1) & 0x02, *(pucMacHeader + 1) & 0x01);
    LOG_I(common, "Duration ID(%u)", *((uint16_t*)(pucMacHeader + 2)));

    LOG_HEXDUMP_I(common, "Addr1", pucMacHeader + 4, WIFI_MAC_ADDRESS_LENGTH);
    LOG_HEXDUMP_I(common, "Addr2", pucMacHeader + 4 + WIFI_MAC_ADDRESS_LENGTH, WIFI_MAC_ADDRESS_LENGTH);
    LOG_HEXDUMP_I(common, "Addr3", pucMacHeader + 4 + 2 * WIFI_MAC_ADDRESS_LENGTH, WIFI_MAC_ADDRESS_LENGTH);

    LOG_I(common, "Sequence/Fragment number(0x%02x%02x/0x%02x)", 
	*(pucMacHeader + 4 + 3 * WIFI_MAC_ADDRESS_LENGTH), *(pucMacHeader + 4 + 3 * WIFI_MAC_ADDRESS_LENGTH + 1) & 0xF0,
	*(pucMacHeader + 4 + 3 * WIFI_MAC_ADDRESS_LENGTH + 1) & 0x0F);

    if ((*(pucMacHeader + 1) & 0x80) && (*(pucMacHeader + 1) & 0x40)) {
        LOG_HEXDUMP_I(common, "Addr4", pucMacHeader + 4 + 3 * WIFI_MAC_ADDRESS_LENGTH + 2, WIFI_MAC_ADDRESS_LENGTH);
    }

    LOG_HEXDUMP_I(common, "Rx data", pucPayload, u2PayloadLength);

    rx_req.hdr.cmd.grp = MT7697_CMD_GRP_80211;
    rx_req.hdr.cmd.type = MT7697_CMD_RX_RAW;
    rx_req.hdr.cmd.len = sizeof(struct mt7697_rx_raw_packet) + length;
    rx_req.hdr.result = length;
    memcpy(wifi_info.rx_data, payload, length);

    LOG_I(common, "<-- Rx DATA len(%u)", rx_req.hdr.cmd.len);
    size_t bWrite = spi_queue_write(QUEUE_WIFI_SLAVE_TO_MASTER, (const uint32_t*)&rx_req, QUEUE_LEN_TO_WORD(sizeof(struct mt7697_rx_raw_packet)));
    if (bWrite != QUEUE_LEN_TO_WORD(sizeof(struct mt7697_rx_raw_packet))) {
	LOG_W(common, "spi_queue_write() failed(%d != %d)", bWrite, QUEUE_LEN_TO_WORD(sizeof(struct mt7697_rx_raw_packet)));
	goto cleanup;
    }

    bWrite = spi_queue_write(QUEUE_WIFI_SLAVE_TO_MASTER, (const uint32_t*)wifi_info.rx_data, QUEUE_LEN_TO_WORD(length));
    if (bWrite != QUEUE_LEN_TO_WORD(length)) {
	LOG_W(common, "spi_queue_write() failed(%d != %d)", bWrite, QUEUE_LEN_TO_WORD(length));
	goto cleanup;
    }

cleanup:
    return ret;
}

static int32_t wifi_event_hndlr(wifi_event_t event, uint8_t* payload, uint32_t length)
{
    int32_t ret = 0;

    LOG_I(common, "event(%u) payload(%u)", event, length);

    switch (event) {
    case WIFI_EVENT_IOT_REPORT_BEACON_PROBE_RESPONSE:
    {
        wifi_scan_list_item_t ap_data;
        struct mt7697_scan_rsp scan_rsp;

        LOG_I(common, "probe response(%u)", length);
        if (length == 0) {
            LOG_W(common, "empty probe response(%d)", length);
            ret = -1;
	    goto cleanup;
        }

        ret = wifi_connection_parse_beacon(payload, length, &ap_data);
        if (ret < 0) {
            LOG_W(common, "wifi_connection_parse_beacon() failed(%d)", ret);
            goto cleanup;
        }		

        printf("\n%-4s%-33s%-20s%-8s%-8s%-8s%-8s%-8s%-8s%-8s\n", "Ch", "SSID", "BSSID", "Auth", "Cipher", "RSSI", "WPS_EN", "CM", "DPID", "SR");
        printf("%-4d", ap_data.channel);
        printf("%-33s", ap_data.ssid);
        printf("%02x:%02x:%02x:%02x:%02x:%02x   ",
            ap_data.bssid[0], ap_data.bssid[1], ap_data.bssid[2], ap_data.bssid[3], ap_data.bssid[4], ap_data.bssid[5]);
        printf("%-8d", ap_data.auth_mode);
        printf("%-8d", ap_data.encrypt_type);
        printf("%-8d", ap_data.rssi);
        printf("%-8d", ap_data.is_wps_supported);

        /*If received Beacon frame, the configuration_methods is 0, because the configuration_methods is not exist in Beacon, it can't be prased. it exist in Probe Response Frame.*/
        /*If received Probe Response frame, the configuration_methods value is  meaningful.*/
        printf("%-8d", ap_data.wps_element.configuration_methods);
        printf("%-8d", ap_data.wps_element.device_password_id);
        printf("%-8d", ap_data.wps_element.selected_registrar);
        printf("\n\n");

        scan_rsp.rssi = ap_data.rssi;
        scan_rsp.channel = ap_data.channel;

        scan_rsp.rsp.cmd.len = sizeof(struct mt7697_scan_rsp) + length;
        scan_rsp.rsp.cmd.grp = MT7697_CMD_GRP_80211;
        scan_rsp.rsp.cmd.type = MT7697_CMD_SCAN_RSP;
        scan_rsp.rsp.result = 0;
        scan_rsp.probe_rsp_len = length;

        LOG_I(common, "<-- SCAN rsp len(%u) result(%d)", scan_rsp.rsp.cmd.len, scan_rsp.rsp.result);
        size_t bWrite = spi_queue_write(QUEUE_WIFI_SLAVE_TO_MASTER, (const uint32_t*)&scan_rsp, QUEUE_LEN_TO_WORD(sizeof(struct mt7697_scan_rsp)));
        if (bWrite != QUEUE_LEN_TO_WORD(sizeof(struct mt7697_scan_rsp))) {
            LOG_W(common, "spi_queue_write() failed(%d != %d)", bWrite, QUEUE_LEN_TO_WORD(sizeof(struct mt7697_scan_rsp)));
            ret = -1;
	    goto cleanup;
        }

        bWrite = spi_queue_write(QUEUE_WIFI_SLAVE_TO_MASTER, (const uint32_t*)payload, QUEUE_LEN_TO_WORD(length));
        if (bWrite != QUEUE_LEN_TO_WORD(length)) {
            LOG_W(common, "spi_queue_write() failed(%d != %d)", bWrite, QUEUE_LEN_TO_WORD(length));
            ret = -1;
	    goto cleanup;
        }

        break;
    }
    case WIFI_EVENT_IOT_SCAN_COMPLETE:
    {
        struct mt7697_scan_complete_rsp scan_rsp;

        scan_rsp.rsp.cmd.len = sizeof(struct mt7697_scan_complete_rsp);
        scan_rsp.rsp.cmd.grp = MT7697_CMD_GRP_80211;
        scan_rsp.rsp.cmd.type = MT7697_CMD_SCAN_COMPLETE;
        scan_rsp.if_idx = wifi_info.if_idx;

	LOG_I(common, "stop scan");
    	ret = wifi_connection_stop_scan();
    	if (ret < 0) {
      	    LOG_W(common, "wifi_connection_stop_scan() failed(%d)", ret);
      	    goto cleanup;
    	}

        scan_rsp.rsp.result = ret;
        LOG_I(common, "<-- SCAN COMPLETE if idx(%u) len(%u) result(%d)", scan_rsp.if_idx, scan_rsp.rsp.cmd.len, ret);
        size_t bWrite = spi_queue_write(QUEUE_WIFI_SLAVE_TO_MASTER, (const uint32_t*)&scan_rsp, QUEUE_LEN_TO_WORD(scan_rsp.rsp.cmd.len));
        if (bWrite != QUEUE_LEN_TO_WORD(scan_rsp.rsp.cmd.len)) {
            LOG_W(common, "spi_queue_write() failed(%d != %d)", bWrite, QUEUE_LEN_TO_WORD(scan_rsp.rsp.cmd.len));
            ret = -1;
	    goto cleanup;
        }

        break;
    }
    case WIFI_EVENT_IOT_CONNECTED:
    {
        LOG_I(common, "LinkUp!\n");
        LOG_HEXDUMP_I(common, "MAC", payload, length);
        break;
    }
    case WIFI_EVENT_IOT_PORT_SECURE:
    {
        struct mt7697_connect_rsp connect_rsp;

        connect_rsp.rsp.cmd.len = sizeof(struct mt7697_connect_rsp);
        connect_rsp.rsp.cmd.grp = MT7697_CMD_GRP_80211;
        connect_rsp.rsp.cmd.type = MT7697_CMD_CONNECT_RSP;
        connect_rsp.if_idx = wifi_info.if_idx;

        LOG_I(common, "Port Secure!\n");
        LOG_HEXDUMP_I(common, "MAC", payload, length);
	if ((length >= WIFI_MAC_ADDRESS_LENGTH) && payload) 
	    memcpy(connect_rsp.bssid, payload, WIFI_MAC_ADDRESS_LENGTH);
	else 
	    memset(connect_rsp.bssid, 0, sizeof(connect_rsp.bssid));

        LOG_I(common, "channel(%u)", wifi_info.channel);
        connect_rsp.channel = wifi_info.channel;

        connect_rsp.rsp.result = ret;
        LOG_I(common, "<-- CONNECTED len(%u) result(%d)", connect_rsp.rsp.cmd.len, ret);
        size_t bWrite = spi_queue_write(QUEUE_WIFI_SLAVE_TO_MASTER, (const uint32_t*)&connect_rsp, QUEUE_LEN_TO_WORD(connect_rsp.rsp.cmd.len));
        if (bWrite != QUEUE_LEN_TO_WORD(connect_rsp.rsp.cmd.len)) {
            LOG_W(common, "spi_queue_write() failed(%d != %d)", bWrite, QUEUE_LEN_TO_WORD(connect_rsp.rsp.cmd.len));
	    goto cleanup;
        }

        break;
    }
    case WIFI_EVENT_IOT_DISCONNECTED:
    {
        struct mt7697_disconnect_rsp disconnect_rsp;
        uint8_t link_status;

        LOG_I(common, "Disconnect!\n");
        ret = wifi_connection_get_link_status(&link_status);
        if (ret < 0) {
	    LOG_W(common, "wifi_connection_get_link_status() failed(%d)", ret);
	    goto cleanup;
        }

	LOG_HEXDUMP_I(common, "MAC", payload, length);
        if (link_status == 0) {
	    disconnect_rsp.rsp.cmd.len = sizeof(struct mt7697_disconnect_rsp);
            disconnect_rsp.rsp.cmd.grp = MT7697_CMD_GRP_80211;
            disconnect_rsp.rsp.cmd.type = MT7697_CMD_DISCONNECT_RSP;
            disconnect_rsp.if_idx = wifi_info.if_idx;
	
	    if ((length >= WIFI_MAC_ADDRESS_LENGTH) && payload)   
	        memcpy(disconnect_rsp.bssid, payload, WIFI_MAC_ADDRESS_LENGTH);
	    else 
	        memset(disconnect_rsp.bssid, 0, sizeof(disconnect_rsp.bssid));

            disconnect_rsp.rsp.result = ret;
            LOG_I(common, "<-- DISCONNECT len(%u) result(%d)", disconnect_rsp.rsp.cmd.len, ret);
            size_t bWrite = spi_queue_write(QUEUE_WIFI_SLAVE_TO_MASTER, (const uint32_t*)&disconnect_rsp, QUEUE_LEN_TO_WORD(disconnect_rsp.rsp.cmd.len));
            if (bWrite != QUEUE_LEN_TO_WORD(disconnect_rsp.rsp.cmd.len)) {
                LOG_W(common, "spi_queue_write() failed(%d != %d)", bWrite, QUEUE_LEN_TO_WORD(disconnect_rsp.rsp.cmd.len));
                ret = -1;
	        goto cleanup;
           }
        }

	break;
    }
    default:
        LOG_W(common, "unhandled event(%u)", event);
        goto cleanup;
    }        

cleanup:
    return ret;
}

static int32_t wifi_proc_get_psk_req(uint8_t channel, uint16_t len)
{
    struct mt7697_get_psk_rsp psk_rsp;
    size_t words_read;
    uint32_t port;
    int32_t ret = 0;
    uint8_t psk_len = 0;

    psk_rsp.rsp.cmd.len = sizeof(struct mt7697_get_psk_rsp);
    psk_rsp.rsp.cmd.grp = MT7697_CMD_GRP_80211;
    psk_rsp.rsp.cmd.type = MT7697_CMD_GET_PSK_RSP;

    LOG_I(common, "--> GET PSK(%d)", len);
    if (len != sizeof(struct mt7697_get_psk_req)) {
	LOG_W(common, "invalid get PSK req len(%d != %d)", len, sizeof(struct mt7697_get_psk_req));
	ret = -1;
	goto cleanup;
    }
	
    words_read = spi_queue_read(channel, (uint32_t*)&port, QUEUE_LEN_TO_WORD(sizeof(uint32_t)));
    if (words_read != QUEUE_LEN_TO_WORD(sizeof(uint32_t))) {
        LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, QUEUE_LEN_TO_WORD(sizeof(uint32_t)));
	ret = -1;
	goto cleanup;
    }

    if (!wifi_validate_wifi_port(port)) {
        LOG_W(common, "invalid port(%d)", port);
	ret = -1;
	goto cleanup;
    }

    LOG_I(common, "PSK port(%d)", port);
    ret = wifi_config_get_wpa_psk_key(port, psk_rsp.psk, &psk_len);
    if (ret < 0) {
	LOG_W(common, "wifi_config_get_wpa_psk_key() failed(%d)", ret);
	goto cleanup;
    }
    psk_rsp.len = psk_len;
    LOG_I(common, "PSK(%u/'%s')", psk_rsp.len, psk_rsp.psk);	

cleanup:
    psk_rsp.rsp.result = ret;
    if (ret < 0) psk_rsp.rsp.cmd.len = sizeof(struct mt7697_rsp_hdr);
    LOG_I(common, "<-- GET PSK rsp len(%u) result(%d)", psk_rsp.rsp.cmd.len, ret);
    size_t bWrite = spi_queue_write(QUEUE_WIFI_SLAVE_TO_MASTER, (const uint32_t*)&psk_rsp, QUEUE_LEN_TO_WORD(psk_rsp.rsp.cmd.len));
    if (bWrite != QUEUE_LEN_TO_WORD(psk_rsp.rsp.cmd.len)) {
	LOG_W(common, "spi_queue_write() failed(%d != %d)", bWrite, QUEUE_LEN_TO_WORD(psk_rsp.rsp.cmd.len));
        ret = -1;
    }

    return ret;
}

static int32_t wifi_proc_set_psk_req(uint8_t channel, uint16_t len)
{
    uint8_t psk[WIFI_LENGTH_PASSPHRASE] = {0};
    struct mt7697_set_psk_rsp psk_rsp;
    size_t words_read;
    uint32_t port;
    uint32_t psk_len;
    int32_t ret = 0;

    psk_rsp.cmd.len = sizeof(struct mt7697_set_psk_rsp);
    psk_rsp.cmd.grp = MT7697_CMD_GRP_80211;
    psk_rsp.cmd.type = MT7697_CMD_SET_PSK_RSP;

    LOG_I(common, "--> SET PSK(%d)", len);
    if (len != sizeof(struct mt7697_set_psk_req)) {
	LOG_W(common, "invalid set PSK req len(%d != %d)", len, sizeof(struct mt7697_set_psk_req));
	ret = -1;
	goto cleanup;
    }

    words_read = spi_queue_read(channel, (uint32_t*)&port, QUEUE_LEN_TO_WORD(sizeof(uint32_t)));
    if (words_read != QUEUE_LEN_TO_WORD(sizeof(uint32_t))) {
	LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, QUEUE_LEN_TO_WORD(sizeof(uint32_t)));
	ret = -1;
	goto cleanup;
    }

    LOG_I(common, "PSK port(%d)", port);
    if (!wifi_validate_wifi_port(port)) {
	LOG_W(common, "invalid port(%d)", port);
	ret = -1;
	goto cleanup;
    }

    words_read = spi_queue_read(channel, (uint32_t*)&psk_len, QUEUE_LEN_TO_WORD(sizeof(uint32_t)));
    if (words_read != QUEUE_LEN_TO_WORD(sizeof(uint32_t))) {
	LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, QUEUE_LEN_TO_WORD(sizeof(uint32_t)));
	ret = -1;
	goto cleanup;
    }

    LOG_I(common, "PSK len(%d)", psk_len);
    if (!psk_len || psk_len > WIFI_LENGTH_PASSPHRASE) {
	LOG_W(common, "invalid PSK len(%d)", psk_len);
	ret = -1;
	goto cleanup;
    }

    words_read = spi_queue_read(channel, (uint32_t*)psk, QUEUE_LEN_TO_WORD(WIFI_LENGTH_PASSPHRASE));
    if (words_read != QUEUE_LEN_TO_WORD(WIFI_LENGTH_PASSPHRASE)) {
	LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, QUEUE_LEN_TO_WORD(WIFI_LENGTH_PASSPHRASE));
	ret = -1;
	goto cleanup;
    }
    LOG_I(common, "PSK('%s')", psk);

    ret = wifi_config_set_wpa_psk_key(port, psk, psk_len);
    if (ret < 0) {
	LOG_W(common, "wifi_config_set_wpa_psk_key() failed(%d)", ret);
	goto cleanup;
    }

cleanup:
    psk_rsp.result = ret;
    LOG_I(common, "<-- SET PSK rsp len(%u) result(%d)", psk_rsp.cmd.len, ret);
    size_t bWrite = spi_queue_write(QUEUE_WIFI_SLAVE_TO_MASTER, (const uint32_t*)&psk_rsp, QUEUE_LEN_TO_WORD(psk_rsp.cmd.len));
    if (bWrite != QUEUE_LEN_TO_WORD(psk_rsp.cmd.len)) {
	LOG_W(common, "spi_queue_write() failed(%d != %d)", bWrite, QUEUE_LEN_TO_WORD(psk_rsp.cmd.len));
        ret = -1;
    }

    return ret;
}

static int32_t wifi_proc_mac_addr_req(uint8_t channel, uint16_t len)
{
    struct mt7697_mac_addr_rsp mac_addr_rsp;
    uint32_t port;
    int32_t ret = 0;

    mac_addr_rsp.rsp.cmd.len = sizeof(struct mt7697_mac_addr_rsp);
    mac_addr_rsp.rsp.cmd.grp = MT7697_CMD_GRP_80211;
    mac_addr_rsp.rsp.cmd.type = MT7697_CMD_MAC_ADDR_RSP;

    LOG_I(common, "--> GET MAC ADDRESS(%d)", len);
    if (len != sizeof(struct mt7697_mac_addr_req)) {
        LOG_W(common, "invalid MAC address req len(%d != %d)", len, sizeof(struct mt7697_mac_addr_req));
	ret = -1;
	goto cleanup;
    }

    size_t words_read = spi_queue_read(channel, (uint32_t*)&port, QUEUE_LEN_TO_WORD(sizeof(port)));
    if (words_read != QUEUE_LEN_TO_WORD(sizeof(port))) {
        LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, QUEUE_LEN_TO_WORD(sizeof(port)));
	ret = -1;
	goto cleanup;
    }

    if (!wifi_validate_wifi_port(port)) {
        LOG_W(common, "invalid port(%d)", port);
	ret = -1;
	goto cleanup;
    }

    LOG_I(common, "MAC address port(%d)", port);
    ret = wifi_config_get_mac_address(port, mac_addr_rsp.addr);
    if (ret < 0) {
	LOG_W(common, "wifi_config_get_mac_address() failed(%d)", ret);
	goto cleanup;
    }

    LOG_HEXDUMP_I(common, "MAC", mac_addr_rsp.addr, WIFI_MAC_ADDRESS_LENGTH);	

cleanup:
    mac_addr_rsp.rsp.result = ret;
    if (ret < 0) mac_addr_rsp.rsp.cmd.len = sizeof(struct mt7697_rsp_hdr);
    LOG_I(common, "<-- GET MAC ADDRESS rsp len(%u) result(%d)", mac_addr_rsp.rsp.cmd.len, ret);
    size_t bWrite = spi_queue_write(QUEUE_WIFI_SLAVE_TO_MASTER, (const uint32_t*)&mac_addr_rsp, QUEUE_LEN_TO_WORD(mac_addr_rsp.rsp.cmd.len));
    if (bWrite != QUEUE_LEN_TO_WORD(mac_addr_rsp.rsp.cmd.len)) {
	LOG_W(common, "spi_queue_write() failed(%d != %d)", bWrite, QUEUE_LEN_TO_WORD(mac_addr_rsp.rsp.cmd.len));
        ret = -1;
    }

    return ret;
}

static int32_t wifi_proc_get_wireless_mode_req(uint8_t channel, uint16_t len)
{
    wifi_phy_mode_t mode;
    struct mt7697_get_wireless_mode_rsp wireless_mode_rsp;
    uint32_t port;
    int32_t ret = 0;

    wireless_mode_rsp.rsp.cmd.len = sizeof(struct mt7697_get_wireless_mode_rsp);
    wireless_mode_rsp.rsp.cmd.grp = MT7697_CMD_GRP_80211;
    wireless_mode_rsp.rsp.cmd.type = MT7697_CMD_GET_WIRELESS_MODE_RSP;

    LOG_I(common, "--> GET WIRELESS MODE(%d)", len);
    if (len != sizeof(struct mt7697_get_wireless_mode_req)) {
        LOG_W(common, "invalid wireless mode req len(%d != %d)", len, sizeof(struct mt7697_get_wireless_mode_req));
	ret = -1;
	goto cleanup;
    }

    size_t words_read = spi_queue_read(channel, (uint32_t*)&port, QUEUE_LEN_TO_WORD(sizeof(uint32_t)));
    if (words_read != QUEUE_LEN_TO_WORD(sizeof(uint32_t))) {
        LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, QUEUE_LEN_TO_WORD(sizeof(uint32_t)));
	ret = -1;
	goto cleanup;
    }

    if (!wifi_validate_wifi_port(port)) {
        LOG_W(common, "invalid port(%d)", port);
	ret = -1;
	goto cleanup;
    }

    LOG_I(common, "wireless mode port(%d)", port);
    ret = wifi_config_get_wireless_mode(port, &mode);
    if (ret < 0) {
        LOG_W(common, "wifi_config_get_wireless_mode() failed(%d)", ret);
	goto cleanup;
    }

    wireless_mode_rsp.mode = mode;
    LOG_I(common, "wireless mode(%u)", wireless_mode_rsp.mode);	

cleanup:
    wireless_mode_rsp.rsp.result = ret;
    if (ret < 0) wireless_mode_rsp.rsp.cmd.len = sizeof(struct mt7697_rsp_hdr);
    LOG_I(common, "<-- GET WIRELESS MODE rsp len(%u) result(%d)", wireless_mode_rsp.rsp.cmd.len, ret);
    size_t bWrite = spi_queue_write(QUEUE_WIFI_SLAVE_TO_MASTER, (const uint32_t*)&wireless_mode_rsp, QUEUE_LEN_TO_WORD(wireless_mode_rsp.rsp.cmd.len));
    if (bWrite != QUEUE_LEN_TO_WORD(wireless_mode_rsp.rsp.cmd.len)) {
	LOG_W(common, "spi_queue_write() failed(%d != %d)", bWrite, QUEUE_LEN_TO_WORD(wireless_mode_rsp.rsp.cmd.len));
        ret = -1;
    }

    return ret;
}

static int32_t wifi_proc_set_wireless_mode_req(uint8_t channel, uint16_t len)
{
    struct mt7697_set_wireless_mode_rsp wireless_mode_rsp;
    uint32_t port;
    uint32_t mode;
    int32_t ret = 0;

    wireless_mode_rsp.cmd.len = sizeof(struct mt7697_set_wireless_mode_rsp);
    wireless_mode_rsp.cmd.grp = MT7697_CMD_GRP_80211;
    wireless_mode_rsp.cmd.type = MT7697_CMD_SET_WIRELESS_MODE_RSP;

    LOG_I(common, "--> SET WIRELESS MODE(%d)", len);
    if (len != sizeof(struct mt7697_set_wireless_mode_req)) {
        LOG_W(common, "invalid wireless mode req len(%d != %d)", len, sizeof(struct mt7697_set_wireless_mode_req));
	ret = -1;
	goto cleanup;
    }

    size_t words_read = spi_queue_read(channel, (uint32_t*)&port, QUEUE_LEN_TO_WORD(sizeof(uint32_t)));
    if (words_read != QUEUE_LEN_TO_WORD(sizeof(uint32_t))) {
        LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, QUEUE_LEN_TO_WORD(sizeof(uint32_t)));
	ret = -1;
	goto cleanup;
    }

    if (!wifi_validate_wifi_port(port)) {
        LOG_W(common, "invalid port(%d)", port);
	ret = -1;
	goto cleanup;
    }
		
    words_read = spi_queue_read(channel, (uint32_t*)&mode, QUEUE_LEN_TO_WORD(sizeof(uint32_t)));
    if (words_read != QUEUE_LEN_TO_WORD(sizeof(uint32_t))) {
        LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, QUEUE_LEN_TO_WORD(sizeof(uint32_t)));
	ret = -1;
	goto cleanup;
    }

    LOG_I(common, "wireless mode(%d) port(%d)", mode, port);
    ret = wifi_config_set_wireless_mode(port, mode);
    if (ret < 0) {
	LOG_W(common, "wifi_config_set_wireless_mode() failed(%d)", ret);
	goto cleanup;
    }

cleanup:
    wireless_mode_rsp.result = ret;
    if (ret < 0) wireless_mode_rsp.cmd.len = sizeof(struct mt7697_rsp_hdr);
    LOG_I(common, "<-- SET WIRELESS MODE rsp len(%u) result(%d)", wireless_mode_rsp.cmd.len, ret);
    size_t bWrite = spi_queue_write(QUEUE_WIFI_SLAVE_TO_MASTER, (const uint32_t*)&wireless_mode_rsp, QUEUE_LEN_TO_WORD(wireless_mode_rsp.cmd.len));
    if (bWrite != QUEUE_LEN_TO_WORD(wireless_mode_rsp.cmd.len)) {
	LOG_W(common, "spi_queue_write() failed(%d != %d)", bWrite, QUEUE_LEN_TO_WORD(wireless_mode_rsp.cmd.len));
        ret = -1;
    }

    return ret;
}

static int32_t wifi_proc_get_cfg_req(uint8_t channel, uint16_t len)
{
    struct mt7697_cfg_rsp cfg_rsp;
    int32_t ret = 0;

    memset(&cfg_rsp, 0, sizeof(struct mt7697_cfg_rsp));
    cfg_rsp.rsp.cmd.len = sizeof(struct mt7697_cfg_rsp);
    cfg_rsp.rsp.cmd.grp = MT7697_CMD_GRP_80211;
    cfg_rsp.rsp.cmd.type = MT7697_CMD_GET_CFG_RSP;

    LOG_I(common, "--> GET CONFIG(%d)", len);
    if (len != sizeof(struct mt7697_cfg_req)) {
        LOG_W(common, "invalid cfg req len(%u != %u)", len, sizeof(struct mt7697_cfg_req));
	ret = -1;
	goto cleanup;
    }

    ret = wifi_config_get_opmode(&cfg_rsp.cfg.opmode);
    if (ret < 0) {
	LOG_W(common, "wifi_config_get_opmode() failed(%d)", ret);
	goto cleanup;
    }
    LOG_I(common, "opmode(%u)", cfg_rsp.cfg.opmode);

    if ((cfg_rsp.cfg.opmode == WIFI_MODE_STA_ONLY) || (cfg_rsp.cfg.opmode == WIFI_MODE_REPEATER)) {
	ret = wifi_config_get_ssid(WIFI_PORT_STA, cfg_rsp.cfg.sta_config.ssid, &cfg_rsp.cfg.sta_config.ssid_length);
	if (ret < 0) {
	    LOG_W(common, "wifi_config_get_ssid() failed(%d)", ret);
	}
	LOG_I(common, "STA SSID(%u) ('%s')", cfg_rsp.cfg.sta_config.ssid_length, cfg_rsp.cfg.sta_config.ssid);

	ret = wifi_config_get_bssid(cfg_rsp.cfg.sta_config.bssid);
	if (ret < 0) {
	    LOG_W(common, "wifi_config_get_bssid() failed(%d)", ret);
	}
	else {	        
	    cfg_rsp.cfg.sta_config.bssid_present = true;
            LOG_HEXDUMP_I(common, "STA BSSID", cfg_rsp.cfg.sta_config.bssid, WIFI_MAC_ADDRESS_LENGTH);
	}
	
	ret = wifi_config_get_wpa_psk_key(WIFI_PORT_STA, cfg_rsp.cfg.sta_config.password, &cfg_rsp.cfg.sta_config.password_length);
	if (ret < 0) {
	    LOG_W(common, "wifi_config_get_wpa_psk_key() failed(%d)", ret);
	}
	LOG_I(common, "STA password(%u) ('%s')", cfg_rsp.cfg.sta_config.password_length, cfg_rsp.cfg.sta_config.password);
    }

    if ((cfg_rsp.cfg.opmode == WIFI_MODE_AP_ONLY) || (cfg_rsp.cfg.opmode == WIFI_MODE_REPEATER)) {
	ret = wifi_config_get_ssid(WIFI_PORT_AP, cfg_rsp.cfg.ap_config.ssid, &cfg_rsp.cfg.ap_config.ssid_length);
	if (ret < 0) {
	    LOG_W(common, "wifi_config_get_ssid() failed(%d)", ret);
	}
	LOG_I(common, "AP SSID(%u) ('%s')", cfg_rsp.cfg.ap_config.ssid_length, cfg_rsp.cfg.ap_config.ssid);

	ret = wifi_config_get_wpa_psk_key(WIFI_PORT_AP, cfg_rsp.cfg.ap_config.password, &cfg_rsp.cfg.ap_config.password_length);
	if (ret < 0) {
	    LOG_W(common, "wifi_config_get_wpa_psk_key() failed(%d)", ret);
	}
	LOG_I(common, "AP password(%u) ('%s')", cfg_rsp.cfg.ap_config.password_length, cfg_rsp.cfg.ap_config.password);	

	ret = wifi_config_get_security_mode(WIFI_PORT_AP, &cfg_rsp.cfg.ap_config.auth_mode, &cfg_rsp.cfg.ap_config.encrypt_type);
	if (ret < 0) {
	    LOG_W(common, "wifi_config_get_security_mode() failed(%d)", ret);
	    goto cleanup;
	}
	LOG_I(common, "AP auth mode(%u) encrypt type(%u)", cfg_rsp.cfg.ap_config.auth_mode, cfg_rsp.cfg.ap_config.encrypt_type);

	ret = wifi_config_get_channel(WIFI_PORT_AP, &cfg_rsp.cfg.ap_config.channel);
	if (ret < 0) {
	    LOG_W(common, "wifi_config_get_channel() failed(%d)", ret);
	}
	LOG_I(common, "AP channel(%u)", cfg_rsp.cfg.ap_config.channel);

	ret = wifi_config_get_bandwidth(WIFI_PORT_AP, &cfg_rsp.cfg.ap_config.bandwidth);
	if (ret < 0) {
	    LOG_W(common, "wifi_config_get_bandwidth() failed(%d)", ret);
	}
	LOG_I(common, "AP bandwidth(%u)", cfg_rsp.cfg.ap_config.bandwidth);

	if (cfg_rsp.cfg.ap_config.bandwidth == WIFI_IOT_COMMAND_CONFIG_BANDWIDTH_40MHZ) {
	    ret = wifi_config_get_bandwidth_extended(WIFI_PORT_AP, &cfg_rsp.cfg.ap_config.bandwidth, &cfg_rsp.cfg.ap_config.bandwidth_ext);
	    if (ret < 0) {
	        LOG_W(common, "wifi_config_get_bandwidth_extended() failed(%d)", ret);
	    }
	    LOG_I(common, "AP bandwidth ext(%u)", cfg_rsp.cfg.ap_config.bandwidth_ext);
	}
    }

cleanup:
    cfg_rsp.rsp.result = ret;
    if (ret < 0) cfg_rsp.rsp.cmd.len = sizeof(struct mt7697_rsp_hdr);
    LOG_I(common, "<-- GET CONFIG rsp len(%u) result(%d)", cfg_rsp.rsp.cmd.len, ret);
    size_t bWrite = spi_queue_write(QUEUE_WIFI_SLAVE_TO_MASTER, (const uint32_t*)&cfg_rsp, QUEUE_LEN_TO_WORD(cfg_rsp.rsp.cmd.len));
    if (bWrite != QUEUE_LEN_TO_WORD(cfg_rsp.rsp.cmd.len)) {
	LOG_W(common, "spi_queue_write() failed(%d != %d)", bWrite, QUEUE_LEN_TO_WORD(cfg_rsp.rsp.cmd.len));
        ret = -1;
    }

    return ret;
}

static int32_t wifi_proc_set_opmode_req(uint8_t channel, uint16_t len)
{
    struct mt7697_set_op_mode_rsp op_mode_rsp;
    uint32_t opmode;
    int32_t ret = 0;

    op_mode_rsp.cmd.len = sizeof(struct mt7697_get_radio_state_rsp);
    op_mode_rsp.cmd.grp = MT7697_CMD_GRP_80211;
    op_mode_rsp.cmd.type = MT7697_CMD_SET_OP_MODE_RSP;

    LOG_I(common, "--> SET OP MODE(%d)", len);
    if (len != sizeof(struct mt7697_set_op_mode_req)) {
        LOG_W(common, "invalid set opmode req len(%u != %u)", len, sizeof(struct mt7697_set_op_mode_req));
	ret = -1;
	goto cleanup;
    }
	
    size_t words_read = spi_queue_read(channel, (uint32_t*)&opmode, QUEUE_LEN_TO_WORD(sizeof(uint32_t)));
    if (words_read != QUEUE_LEN_TO_WORD(sizeof(uint32_t))) {
        LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, QUEUE_LEN_TO_WORD(sizeof(uint32_t)));
	ret = -1;
	goto cleanup;
    }

    LOG_I(common, "set opmode(%u)", opmode);
    ret = wifi_config_set_opmode(opmode);
    if (ret < 0) {
	LOG_W(common, "wifi_config_set_opmode() failed(%d)", ret);
	goto cleanup; 
    }

cleanup:
    op_mode_rsp.result = ret;
    LOG_I(common, "<-- SET OP MODE rsp len(%u) result(%d)", op_mode_rsp.cmd.len, ret);
    size_t bWrite = spi_queue_write(QUEUE_WIFI_SLAVE_TO_MASTER, (const uint32_t*)&op_mode_rsp, QUEUE_LEN_TO_WORD(op_mode_rsp.cmd.len));
    if (bWrite != QUEUE_LEN_TO_WORD(op_mode_rsp.cmd.len)) {
	LOG_W(common, "spi_queue_write() failed(%d != %d)", bWrite, QUEUE_LEN_TO_WORD(op_mode_rsp.cmd.len));
        ret = -1;
    }

    return ret;
}

static int32_t wifi_proc_get_radio_state_req(uint8_t channel, uint16_t len)
{
    struct mt7697_get_radio_state_rsp radio_state_rsp;
    int32_t ret = 0;
    uint8_t opmode;

    radio_state_rsp.rsp.cmd.len = sizeof(struct mt7697_get_radio_state_rsp);
    radio_state_rsp.rsp.cmd.grp = MT7697_CMD_GRP_80211;
    radio_state_rsp.rsp.cmd.type = MT7697_CMD_GET_RADIO_STATE_RSP;

    LOG_I(common, "--> GET RADIO STATE(%d)", len);
    if (len != sizeof(struct mt7697_get_radio_state_req)) {
        LOG_W(common, "invalid get radio state req len(%u != %u)", len, sizeof(struct mt7697_get_radio_state_req));
	ret = -1;
	goto cleanup;
    }

    ret = wifi_config_get_opmode(&opmode);
    if (ret < 0) {
	LOG_W(common, "wifi_config_get_opmode() failed(%d)", ret);
	goto cleanup;
    }
    LOG_I(common, "opmode(%u)", opmode);

    if (opmode == WIFI_MODE_STA_ONLY) {
        uint8_t state;
	ret = wifi_config_get_radio(&state);
	if (ret < 0) {
	    LOG_W(common, "wifi_config_get_radio() failed(%d)", ret);
	    goto cleanup;
        }
		
	radio_state_rsp.state = state;
	LOG_I(common, "radio state(%u)", radio_state_rsp.state);
    }

cleanup:
    radio_state_rsp.rsp.result = ret;
    if (ret < 0) radio_state_rsp.rsp.cmd.len = sizeof(struct mt7697_rsp_hdr);
    LOG_I(common, "<-- GET RADIO STATE rsp len(%u) result(%d)", radio_state_rsp.rsp.cmd.len, ret);
    size_t bWrite = spi_queue_write(QUEUE_WIFI_SLAVE_TO_MASTER, (const uint32_t*)&radio_state_rsp, QUEUE_LEN_TO_WORD(radio_state_rsp.rsp.cmd.len));
    if (bWrite != QUEUE_LEN_TO_WORD(radio_state_rsp.rsp.cmd.len)) {
	LOG_W(common, "spi_queue_write() failed(%d != %d)", bWrite, QUEUE_LEN_TO_WORD(radio_state_rsp.rsp.cmd.len));
        ret = -1;
    }

    return ret;
}

static int32_t wifi_proc_set_radio_state_req(uint8_t channel, uint16_t len)
{
    struct mt7697_set_radio_state_rsp radio_state_rsp;
    uint32_t state = 0;
    int32_t ret = 0;
    uint8_t opmode;

    radio_state_rsp.cmd.len = sizeof(struct mt7697_set_radio_state_rsp);
    radio_state_rsp.cmd.grp = MT7697_CMD_GRP_80211;
    radio_state_rsp.cmd.type = MT7697_CMD_SET_RADIO_STATE_RSP;

    LOG_I(common, "--> SET RADIO STATE(%d)", len);
    if (len != sizeof(struct mt7697_set_radio_state_req)) {
        LOG_W(common, "invalid radio set state req len(%u != %u)", len, sizeof(struct mt7697_set_radio_state_req));
	ret = -1;
	goto cleanup;
    }

    size_t words_read = spi_queue_read(channel, (uint32_t*)&state, QUEUE_LEN_TO_WORD(sizeof(uint32_t)));
    if (words_read != QUEUE_LEN_TO_WORD(sizeof(uint32_t))) {
        LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, QUEUE_LEN_TO_WORD(sizeof(uint32_t)));
	ret = -1;
	goto cleanup;
    }

    ret = wifi_config_get_opmode(&opmode);
    if (ret < 0) {
	LOG_W(common, "wifi_config_get_opmode() failed(%d)", ret);
	goto cleanup;
    }
    LOG_I(common, "opmode(%u)", opmode);

    if (opmode != WIFI_MODE_STA_ONLY) {
        LOG_W(common, "invalid op mode set radio state failed");
	ret = -1;
	goto cleanup;
    }

    LOG_I(common, "set radio(%u)", state);
    ret = wifi_config_set_radio(state);
    if (ret < 0) {
	LOG_W(common, "wifi_config_set_radio() failed(%d)", ret);
	goto cleanup;
    }	

cleanup:
    radio_state_rsp.result = ret;
    LOG_I(common, "<-- SET RADIO STATE rsp len(%u) result(%d)", radio_state_rsp.cmd.len, ret);
    size_t bWrite = spi_queue_write(QUEUE_WIFI_SLAVE_TO_MASTER, (const uint32_t*)&radio_state_rsp, QUEUE_LEN_TO_WORD(radio_state_rsp.cmd.len));
    if (bWrite != QUEUE_LEN_TO_WORD(radio_state_rsp.cmd.len)) {
	LOG_W(common, "spi_queue_write() failed(%d != %d)", bWrite, QUEUE_LEN_TO_WORD(radio_state_rsp.cmd.len));
        ret = -1;
    }

    return ret;
}

static int32_t wifi_proc_get_rx_filter_req(uint8_t channel, uint16_t len)
{
    struct mt7697_get_rx_filter_rsp rx_filter_rsp;
    int32_t ret = 0;

    rx_filter_rsp.rsp.cmd.len = sizeof(struct mt7697_get_rx_filter_rsp);
    rx_filter_rsp.rsp.cmd.grp = MT7697_CMD_GRP_80211;
    rx_filter_rsp.rsp.cmd.type = MT7697_CMD_GET_RX_FILTER_RSP;

    LOG_I(common, "--> GET RX FILTER(%d)", len);
    if (len != sizeof(struct mt7697_get_rx_filter_req)) {
        LOG_W(common, "invalid get rx filter req len(%u != %u)", len, sizeof(struct mt7697_get_rx_filter_req));
	ret = -1;
	goto cleanup;
    }

    ret = wifi_config_get_rx_filter(&rx_filter_rsp.rx_filter);
    if (ret < 0) {
	LOG_W(common, "wifi_config_get_rx_filter() failed(%d)", ret);
	goto cleanup;
    }

    LOG_I(common, "rx filter(0x%08x)", rx_filter_rsp.rx_filter);	

cleanup:
    rx_filter_rsp.rsp.result = ret;
    if (ret < 0) rx_filter_rsp.rsp.cmd.len = sizeof(struct mt7697_rsp_hdr);
    LOG_I(common, "<-- GET RX FILTER rsp len(%u) result(%d)", rx_filter_rsp.rsp.cmd.len, ret);
    size_t bWrite = spi_queue_write(QUEUE_WIFI_SLAVE_TO_MASTER, (const uint32_t*)&rx_filter_rsp, QUEUE_LEN_TO_WORD(rx_filter_rsp.rsp.cmd.len));
    if (bWrite != QUEUE_LEN_TO_WORD(rx_filter_rsp.rsp.cmd.len)) {
	LOG_W(common, "spi_queue_write() failed(%d != %d)", bWrite != QUEUE_LEN_TO_WORD(rx_filter_rsp.rsp.cmd.len));
        ret = -1;
    }

    return ret;
}

static int32_t wifi_proc_get_smart_conn_filter_req(uint8_t channel, uint16_t len)
{
    struct mt7697_get_smart_conn_filter_rsp smart_conn_filter_rsp;
    int32_t ret = 0;
    uint8_t flag;

    smart_conn_filter_rsp.rsp.cmd.len = sizeof(struct mt7697_get_smart_conn_filter_rsp);
    smart_conn_filter_rsp.rsp.cmd.grp = MT7697_CMD_GRP_80211;
    smart_conn_filter_rsp.rsp.cmd.type = MT7697_CMD_GET_SMART_CONN_FILTER_RSP;

    LOG_I(common, "--> GET SMART CONNECTION FILTER(%d)", len);

    ret = wifi_config_get_smart_connection_filter(&flag);
    if (ret < 0) {
	LOG_W(common, "wifi_config_get_smart_connection_filter() failed(%d)", ret);
	goto cleanup;
    }

    LOG_I(common, "smart connection filter(%u)", flag);
    smart_conn_filter_rsp.flag = flag;

cleanup:
    smart_conn_filter_rsp.rsp.result = ret;
    if (ret < 0) smart_conn_filter_rsp.rsp.cmd.len = sizeof(struct mt7697_rsp_hdr);
    LOG_I(common, "<-- GET RX FILTER rsp len(%u) result(%d)", smart_conn_filter_rsp.rsp.cmd.len, ret);
    size_t bWrite = spi_queue_write(QUEUE_WIFI_SLAVE_TO_MASTER, (const uint32_t*)&smart_conn_filter_rsp, QUEUE_LEN_TO_WORD(smart_conn_filter_rsp.rsp.cmd.len));
    if (bWrite != QUEUE_LEN_TO_WORD(smart_conn_filter_rsp.rsp.cmd.len)) {
	LOG_W(common, "spi_queue_write() failed(%d != %d)", bWrite != QUEUE_LEN_TO_WORD(smart_conn_filter_rsp.rsp.cmd.len));
        ret = -1;
    }

    return ret;
}

static int32_t wifi_proc_set_smart_conn_filter_req(uint8_t channel, uint16_t len)
{
    struct mt7697_set_smart_conn_filter_rsp smart_conn_filter_rsp;
    uint32_t flag;
    int32_t ret = 0;
    
    smart_conn_filter_rsp.cmd.len = sizeof(struct mt7697_set_smart_conn_filter_rsp);
    smart_conn_filter_rsp.cmd.grp = MT7697_CMD_GRP_80211;
    smart_conn_filter_rsp.cmd.type = MT7697_CMD_SET_SMART_CONN_FILTER_RSP;

    LOG_I(common, "--> SET SMART CONNECTION FILTER(%d)", len);
    if (len != sizeof(struct mt7697_set_smart_conn_filter_req)) {
        LOG_W(common, "invalid set smart connection filter req len(%u != %u)", len, sizeof(struct mt7697_set_smart_conn_filter_req));
	ret = -1;
	goto cleanup;
    }

    size_t words_read = spi_queue_read(channel, (uint32_t*)&flag, QUEUE_LEN_TO_WORD(sizeof(uint32_t)));
    if (words_read != QUEUE_LEN_TO_WORD(sizeof(uint32_t))) {
        LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, QUEUE_LEN_TO_WORD(sizeof(uint32_t)));
	ret = -1;
	goto cleanup;
    }

    LOG_I(common, "set smart connection filter(0x%u08x)", flag);
    ret = wifi_config_set_smart_connection_filter(flag);
    if (ret < 0) {
    	LOG_W(common, "wifi_config_set_smart_connection_filter() failed(%d)", ret);
	goto cleanup;
    }

cleanup:
    smart_conn_filter_rsp.result = ret;
    LOG_I(common, "<-- SET SMART CONNECTION FILTER rsp len(%u) result(%d)", smart_conn_filter_rsp.cmd.len, ret);
    size_t bWrite = spi_queue_write(QUEUE_WIFI_SLAVE_TO_MASTER, (const uint32_t*)&smart_conn_filter_rsp, QUEUE_LEN_TO_WORD(smart_conn_filter_rsp.cmd.len));
    if (bWrite != QUEUE_LEN_TO_WORD(smart_conn_filter_rsp.cmd.len)) {
	LOG_W(common, "spi_queue_write() failed(%d != %d)", bWrite, QUEUE_LEN_TO_WORD(smart_conn_filter_rsp.cmd.len));
        ret = -1;
    }

    return ret;
}

static int32_t wifi_proc_set_rx_filter_req(uint8_t channel, uint16_t len)
{
    struct mt7697_set_rx_filter_rsp rx_filter_rsp;
    uint32_t rx_filter = 0;
    int32_t ret = 0;

    rx_filter_rsp.cmd.len = sizeof(struct mt7697_set_rx_filter_rsp);
    rx_filter_rsp.cmd.grp = MT7697_CMD_GRP_80211;
    rx_filter_rsp.cmd.type = MT7697_CMD_SET_RX_FILTER_RSP;

    LOG_I(common, "--> SET RX FILTER(%d)", len);
    if (len != sizeof(struct mt7697_set_rx_filter_req)) {
        LOG_W(common, "invalid set rx filter req len(%u != %u)", len, sizeof(struct mt7697_set_rx_filter_req));
	ret = -1;
	goto cleanup;
    }

    size_t words_read = spi_queue_read(channel, (uint32_t*)&rx_filter, QUEUE_LEN_TO_WORD(sizeof(uint32_t)));
    if (words_read != QUEUE_LEN_TO_WORD(sizeof(uint32_t))) {
        LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, QUEUE_LEN_TO_WORD(sizeof(uint32_t)));
	ret = -1;
	goto cleanup;
    }

    LOG_I(common, "set rx filter(0x%u08x)", rx_filter);
    ret = wifi_config_set_rx_filter(rx_filter);
    if (ret < 0) {
    	LOG_W(common, "wifi_config_set_rx_filter() failed(%d)", ret);
	goto cleanup;
    }

cleanup:
    rx_filter_rsp.result = ret;
    LOG_I(common, "<-- SET RX FILTER rsp len(%u) result(%d)", rx_filter_rsp.cmd.len, ret);
    size_t bWrite = spi_queue_write(QUEUE_WIFI_SLAVE_TO_MASTER, (const uint32_t*)&rx_filter_rsp, QUEUE_LEN_TO_WORD(rx_filter_rsp.cmd.len));
    if (bWrite != QUEUE_LEN_TO_WORD(rx_filter_rsp.cmd.len)) {
	LOG_W(common, "spi_queue_write() failed(%d != %d)", bWrite, QUEUE_LEN_TO_WORD(rx_filter_rsp.cmd.len));
        ret = -1;
    }

    return ret;
}

static int32_t wifi_proc_get_listen_interval_req(uint8_t channel, uint16_t len)
{
    struct mt7697_get_listen_interval_rsp listen_interval_rsp;
    int32_t ret = 0;
    uint8_t listen_interval;

    listen_interval_rsp.rsp.cmd.len = sizeof(struct mt7697_get_listen_interval_rsp);
    listen_interval_rsp.rsp.cmd.grp = MT7697_CMD_GRP_80211;
    listen_interval_rsp.rsp.cmd.type = MT7697_CMD_GET_LISTEN_INTERVAL_RSP;

    LOG_I(common, "--> GET LISTEN INTERVAL(%d)", len);
    if (len != sizeof(struct mt7697_get_listen_interval_req)) {
        LOG_W(common, "invalid get listen interval req len(%u != %u)", len, sizeof(struct mt7697_get_listen_interval_req));
	ret = -1;
	goto cleanup;
    }
	
    ret = wifi_config_get_listen_interval(&listen_interval);
    if (ret < 0) {
	LOG_W(common, "wifi_config_get_listen_interval() failed(%d)", ret);
	goto cleanup;
    }

    listen_interval_rsp.interval = listen_interval;
    LOG_I(common, "listen interval(%u)", listen_interval_rsp.interval);

cleanup:
    listen_interval_rsp.rsp.result = ret;
    if (ret < 0) listen_interval_rsp.rsp.cmd.len = sizeof(struct mt7697_rsp_hdr);
    LOG_I(common, "<-- GET LISTEN INTERVAL rsp len(%u) result(%d)", listen_interval_rsp.rsp.cmd.len, ret);
    size_t bWrite = spi_queue_write(QUEUE_WIFI_SLAVE_TO_MASTER, (const uint32_t*)&listen_interval_rsp, QUEUE_LEN_TO_WORD(listen_interval_rsp.rsp.cmd.len));
    if (bWrite != QUEUE_LEN_TO_WORD(listen_interval_rsp.rsp.cmd.len)) {
	LOG_W(common, "spi_queue_write() failed(%d != %d)", bWrite, QUEUE_LEN_TO_WORD(listen_interval_rsp.rsp.cmd.len));
        ret = -1;
    }

    return ret;
}

static int32_t wifi_proc_set_listen_interval_req(uint8_t channel, uint16_t len)
{
    struct mt7697_set_listen_interval_rsp listen_interval_rsp;
    uint32_t interval = 0;
    int32_t ret = 0;

    listen_interval_rsp.cmd.len = sizeof(struct mt7697_set_listen_interval_rsp);
    listen_interval_rsp.cmd.grp = MT7697_CMD_GRP_80211;
    listen_interval_rsp.cmd.type = MT7697_CMD_SET_LISTEN_INTERVAL_RSP;

    LOG_I(common, "--> SET RX FILTER(%d)", len);
    if (len != sizeof(struct mt7697_set_listen_interval_req)) {
        LOG_W(common, "invalid set listen interval req len(%u != %u)", len, sizeof(struct mt7697_set_listen_interval_req));
	ret = -1;
	goto cleanup;
    }

    size_t words_read = spi_queue_read(channel, (uint32_t*)&interval, QUEUE_LEN_TO_WORD(sizeof(uint32_t)));
    if (words_read != QUEUE_LEN_TO_WORD(sizeof(uint32_t))) {
        LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, QUEUE_LEN_TO_WORD(sizeof(uint32_t)));
	ret = -1;
	goto cleanup;
    }

    LOG_I(common, "set rx filter(0x%u08x)", interval);
    ret = wifi_config_set_listen_interval(interval);
    if (ret < 0) {
    	LOG_W(common, "wifi_config_set_listen_interval() failed(%d)", ret);
	goto cleanup;
    }

cleanup:
    listen_interval_rsp.result = ret;
    LOG_I(common, "<-- SET RX FILTER rsp len(%u) result(%d)", listen_interval_rsp.cmd.len, ret);
    size_t bWrite = spi_queue_write(QUEUE_WIFI_SLAVE_TO_MASTER, (const uint32_t*)&listen_interval_rsp, QUEUE_LEN_TO_WORD(listen_interval_rsp.cmd.len));
    if (bWrite != QUEUE_LEN_TO_WORD(listen_interval_rsp.cmd.len)) {
	LOG_W(common, "spi_queue_write() failed(%d != %d)", bWrite, QUEUE_LEN_TO_WORD(listen_interval_rsp.cmd.len));
        ret = -1;
    }

    return ret;
}

static int32_t wifi_proc_get_security_mode_req(uint8_t channel, uint16_t len)
{    
    struct mt7697_get_security_mode_rsp security_mode_rsp;
    wifi_auth_mode_t auth_mode;
    wifi_encrypt_type_t encrypt_type;
    uint32_t port;
    int32_t ret = 0;

    security_mode_rsp.rsp.cmd.len = sizeof(struct mt7697_get_security_mode_rsp);
    security_mode_rsp.rsp.cmd.grp = MT7697_CMD_GRP_80211;
    security_mode_rsp.rsp.cmd.type = MT7697_CMD_GET_SECURITY_MODE_RSP;

    LOG_I(common, "--> GET SECURITY MODE(%d)", len);
    if (len != sizeof(struct mt7697_get_security_mode_req)) {
        LOG_W(common, "invalid get security mode req len(%u != %u)", len, sizeof(struct mt7697_get_security_mode_req));
	ret = -1;
	goto cleanup;
    }

    size_t words_read = spi_queue_read(channel, (uint32_t*)&port, QUEUE_LEN_TO_WORD(sizeof(uint32_t)));
    if (words_read != QUEUE_LEN_TO_WORD(sizeof(uint32_t))) {
        LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, QUEUE_LEN_TO_WORD(sizeof(uint32_t)));
	ret = -1;
	goto cleanup;
    }

    if (!wifi_validate_wifi_port(port)) {
        LOG_W(common, "invalid port(%d)", port);
	ret = -1;
	goto cleanup;
    }

    LOG_I(common, "security mode port(%d)", port);
	
    ret = wifi_config_get_security_mode(port, &auth_mode, &encrypt_type);
    if (ret < 0) {
	LOG_W(common, "wifi_config_get_security_mode() failed(%d)", ret);
	goto cleanup;
    }

    security_mode_rsp.auth_mode = auth_mode;
    security_mode_rsp.encrypt_type = encrypt_type;
    LOG_I(common, "auth mode(%u) encrypt type(%u)", security_mode_rsp.auth_mode, security_mode_rsp.encrypt_type);	

cleanup:
    security_mode_rsp.rsp.result = ret;
    if (ret < 0) security_mode_rsp.rsp.cmd.len = sizeof(struct mt7697_rsp_hdr);
    LOG_I(common, "<-- GET SECURITY MODE rsp len(%u) result(%d)", security_mode_rsp.rsp.cmd.len, ret);
    size_t bWrite = spi_queue_write(QUEUE_WIFI_SLAVE_TO_MASTER, (const uint32_t*)&security_mode_rsp, QUEUE_LEN_TO_WORD(security_mode_rsp.rsp.cmd.len));
    if (bWrite != QUEUE_LEN_TO_WORD(security_mode_rsp.rsp.cmd.len)) {
	LOG_W(common, "spi_queue_write() failed(%d != %d)", bWrite, QUEUE_LEN_TO_WORD(security_mode_rsp.rsp.cmd.len));
        ret = -1;
    }

    return ret;
}

static int32_t wifi_proc_set_security_mode_req(uint8_t channel, uint16_t len)
{    
    struct mt7697_set_security_mode_rsp security_mode_rsp;
    uint32_t port;
    uint32_t auth_mode;
    uint32_t encrypt_type;
    int32_t ret = 0;

    security_mode_rsp.cmd.len = sizeof(struct mt7697_set_security_mode_rsp);
    security_mode_rsp.cmd.grp = MT7697_CMD_GRP_80211;
    security_mode_rsp.cmd.type = MT7697_CMD_SET_SECURITY_MODE_RSP;

    LOG_I(common, "--> SET SECURITY MODE(%d)", len);
    if (len != sizeof(struct mt7697_set_security_mode_req)) {
        LOG_W(common, "invalid set security mode req len(%u != %u)", len, sizeof(struct mt7697_set_security_mode_req));
	ret = -1;
	goto cleanup;
    }
	
    size_t words_read = spi_queue_read(channel, (uint32_t*)&port, QUEUE_LEN_TO_WORD(sizeof(uint32_t)));
    if (words_read != QUEUE_LEN_TO_WORD(sizeof(uint32_t))) {
        LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, QUEUE_LEN_TO_WORD(sizeof(uint32_t)));
	ret = -1;
	goto cleanup;
    }

    if (!wifi_validate_wifi_port(port)) {
        LOG_W(common, "invalid port(%d)", port);
	ret = -1;
	goto cleanup;
    }
	
    words_read = spi_queue_read(channel, (uint32_t*)&auth_mode, QUEUE_LEN_TO_WORD(sizeof(uint32_t)));
    if (words_read != QUEUE_LEN_TO_WORD(sizeof(uint32_t))) {
	LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, QUEUE_LEN_TO_WORD(sizeof(uint32_t)));
	ret = -1;
	goto cleanup;
    }
    LOG_I(common, "auth mode(%d)", auth_mode);

    words_read = spi_queue_read(channel, (uint32_t*)&encrypt_type, QUEUE_LEN_TO_WORD(sizeof(uint32_t)));
    if (words_read != QUEUE_LEN_TO_WORD(sizeof(uint32_t))) {
	LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, QUEUE_LEN_TO_WORD(sizeof(uint32_t)));
	ret = -1;
	goto cleanup;
    }
    LOG_I(common, "encrypt type(%d)", encrypt_type);

    ret = wifi_config_set_security_mode(port, auth_mode, encrypt_type);
    if (ret < 0) {
	LOG_W(common, "wifi_config_set_security_mode() failed(%d)", ret);
	goto cleanup;
    }

cleanup:
    security_mode_rsp.result = ret;
    if (ret < 0) security_mode_rsp.cmd.len = sizeof(struct mt7697_rsp_hdr);
    LOG_I(common, "<-- SET SECURITY MODE rsp len(%u) result(%d)", security_mode_rsp.cmd.len, ret);
    size_t bWrite = spi_queue_write(QUEUE_WIFI_SLAVE_TO_MASTER, (const uint32_t*)&security_mode_rsp, QUEUE_LEN_TO_WORD(security_mode_rsp.cmd.len));
    if (bWrite != QUEUE_LEN_TO_WORD(security_mode_rsp.cmd.len)) {
	LOG_W(common, "spi_queue_write() failed(%d != %d)", bWrite, QUEUE_LEN_TO_WORD(security_mode_rsp.cmd.len));
        ret = -1;
    }

    return ret;
}

static int32_t wifi_proc_scan_req(uint8_t channel, uint16_t len)
{    
    struct mt7697_scan_req scan_req;
    int32_t ret = 0;

    LOG_I(common, "--> SCAN(%d)", len);
    if (len != sizeof(struct mt7697_scan_req)) {
        LOG_W(common, "invalid scan req len(%u != %u)", len, sizeof(struct mt7697_scan_req));
	ret = -1;
	goto cleanup;
    }

    size_t words_read = spi_queue_read(channel, (uint32_t*)&scan_req.if_idx, QUEUE_LEN_TO_WORD(len - sizeof(struct mt7697_cmd_hdr)));
    if (words_read != QUEUE_LEN_TO_WORD(len - sizeof(struct mt7697_cmd_hdr))) {
        LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, QUEUE_LEN_TO_WORD(len - sizeof(struct mt7697_cmd_hdr)));
	ret = -1;
	goto cleanup;
    }

    LOG_I(common, "if idx(%d)", scan_req.if_idx);
    wifi_info.if_idx = scan_req.if_idx;

    LOG_I(common, "SSID (%u/'%s')", scan_req.ssid_len, scan_req.ssid);
    LOG_HEXDUMP_I(common, "BSSID", scan_req.bssid, WIFI_MAC_ADDRESS_LENGTH);
    ret = wifi_connection_start_scan(scan_req.ssid, scan_req.ssid_len, scan_req.bssid_len ? scan_req.bssid:NULL, scan_req.mode, scan_req.option);
    if (ret < 0) {
        LOG_E(common, "wifi_connection_start_scan() failed(%d)", ret);
        goto cleanup;
    }

cleanup:
    if (ret < 0) {
	struct mt7697_scan_rsp scan_rsp;

	scan_rsp.rsp.cmd.len = sizeof(struct mt7697_scan_rsp);
    	scan_rsp.rsp.cmd.grp = MT7697_CMD_GRP_80211;
    	scan_rsp.rsp.cmd.type = MT7697_CMD_SCAN_RSP;
	scan_rsp.rsp.result = ret;

    	LOG_W(common, "<-- SCAN rsp len(%u) result(%d)", scan_rsp.rsp.cmd.len, ret);
    	size_t bWrite = spi_queue_write(QUEUE_WIFI_SLAVE_TO_MASTER, (const uint32_t*)&scan_rsp, QUEUE_LEN_TO_WORD(scan_rsp.rsp.cmd.len));
    	if (bWrite != QUEUE_LEN_TO_WORD(scan_rsp.rsp.cmd.len)) {
	    LOG_W(common, "spi_queue_write() failed(%d != %d)", bWrite, QUEUE_LEN_TO_WORD(scan_rsp.rsp.cmd.len));
        }
    }

    return ret;
}

static int32_t wifi_proc_scan_stop_req(uint8_t channel, uint16_t len)
{
    struct mt7697_scan_stop_rsp scan_stop_rsp;
    int32_t ret = 0;

    scan_stop_rsp.cmd.len = sizeof(struct mt7697_scan_stop_rsp);
    scan_stop_rsp.cmd.grp = MT7697_CMD_GRP_80211;
    scan_stop_rsp.cmd.type = MT7697_CMD_SCAN_STOP_RSP;

    LOG_I(common, "--> SCAN STOP(%d)", len);
    if (len != sizeof(struct mt7697_scan_stop)) {
        LOG_W(common, "invalid len(%d != %d)", len, sizeof(struct mt7697_scan_stop));
	ret = -1;
	goto cleanup;
    }

    LOG_I(common, "stop scan");
    ret = wifi_connection_stop_scan();
    if (ret < 0) {
      LOG_W(common, "wifi_connection_stop_scan() failed(%d)", ret);
      goto cleanup;
    }

cleanup:
    scan_stop_rsp.result = ret;
    LOG_I(common, "<-- SCAN STOP result(%d)", ret);
    size_t bWrite = spi_queue_write(QUEUE_WIFI_SLAVE_TO_MASTER, (const uint32_t*)&scan_stop_rsp, QUEUE_LEN_TO_WORD(scan_stop_rsp.cmd.len));
    if (bWrite != QUEUE_LEN_TO_WORD(scan_stop_rsp.cmd.len)) {
	LOG_W(common, "spi_queue_write() failed(%d != %d)", bWrite, QUEUE_LEN_TO_WORD(scan_stop_rsp.cmd.len));
        ret = -1;
    }

    return ret;
}

static int32_t wifi_proc_connect_req(uint8_t channel, uint16_t len)
{
    uint8_t bssid[QUEUE_LEN32_ALIGNED(WIFI_MAC_ADDRESS_LENGTH)] = {0};
    uint8_t ssid[QUEUE_LEN32_ALIGNED(WIFI_MAX_LENGTH_OF_SSID)] = {0};
    size_t words_read;
    uint32_t port;
    uint32_t ssid_len;
    uint32_t chan = 0;
    int32_t ret = 0;

    LOG_I(common, "--> CONNECT(%d)", len);
    if (len != sizeof(struct mt7697_connect_req)) {
        LOG_W(common, "invalid len(%d != %d)", len, sizeof(struct mt7697_connect_req));
	ret = -1;
	goto cleanup;
    }

    words_read = spi_queue_read(channel, (uint32_t*)&wifi_info.if_idx, QUEUE_LEN_TO_WORD(sizeof(wifi_info.if_idx)));
    if (words_read != QUEUE_LEN_TO_WORD(sizeof(wifi_info.if_idx))) {
	LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, QUEUE_LEN_TO_WORD(sizeof(wifi_info.if_idx)));
	ret = -1;
	goto cleanup;
    }
    LOG_I(common, "if idx(%u)", wifi_info.if_idx);

    words_read = spi_queue_read(channel, (uint32_t*)&port, QUEUE_LEN_TO_WORD(sizeof(port)));
    if (words_read != QUEUE_LEN_TO_WORD(sizeof(port))) {
        LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, QUEUE_LEN_TO_WORD(sizeof(port)));
	ret = -1;
	goto cleanup;
    }
    LOG_I(common, "port(%u)", port);

    words_read = spi_queue_read(channel, (uint32_t*)&chan, QUEUE_LEN_TO_WORD(sizeof(chan)));
    if (words_read != QUEUE_LEN_TO_WORD(sizeof(chan))) {
	LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, QUEUE_LEN_TO_WORD(sizeof(chan)));
	ret = -1;
	goto cleanup;
    }
	
    LOG_I(common, "channel(%u)", chan);
    if (chan == 0) {
	LOG_W(common, "invalid chan(%d)", chan);
	ret = -1;
	goto cleanup;
    }

    ret = wifi_config_set_channel(port, chan);
    if (ret < 0) {
	LOG_W(common, "wifi_config_set_channel() failed(%d)", ret);
	goto cleanup;    
    }
    wifi_info.channel = chan;

    words_read = spi_queue_read(channel, (uint32_t*)bssid, QUEUE_LEN_TO_WORD(QUEUE_LEN32_ALIGNED(WIFI_MAC_ADDRESS_LENGTH)));
    if (words_read != QUEUE_LEN_TO_WORD(QUEUE_LEN32_ALIGNED(WIFI_MAC_ADDRESS_LENGTH))) {
	LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, QUEUE_LEN_TO_WORD(QUEUE_LEN32_ALIGNED(WIFI_MAC_ADDRESS_LENGTH)));
	ret = -1;
	goto cleanup;
    }

    LOG_HEXDUMP_I(common, "BSSID", bssid, WIFI_MAC_ADDRESS_LENGTH);
    ret = wifi_config_set_bssid(bssid);
    if (ret < 0) {
	LOG_W(common, "wifi_config_set_bssid() failed(%d)", ret);
	goto cleanup;
    }

    words_read = spi_queue_read(channel, (uint32_t*)&ssid_len, QUEUE_LEN_TO_WORD(sizeof(ssid_len)));
    if (words_read != QUEUE_LEN_TO_WORD(sizeof(ssid_len))) {
	LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, QUEUE_LEN_TO_WORD(sizeof(ssid_len)));
	ret = -1;
	goto cleanup;
    }

    LOG_I(common, "SSID len(%u)", ssid_len);
    if ((ssid_len == 0) || (ssid_len > WIFI_MAX_LENGTH_OF_SSID)) {
	LOG_W(common, "invalid SSID length(%d)", ssid_len);
	ret = -1;
	goto cleanup;
    }

    words_read = spi_queue_read(channel, (uint32_t*)ssid, QUEUE_LEN_TO_WORD(QUEUE_LEN32_ALIGNED(WIFI_MAX_LENGTH_OF_SSID)));
    if (words_read != QUEUE_LEN_TO_WORD(WIFI_MAX_LENGTH_OF_SSID)) {
	LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, QUEUE_LEN_TO_WORD(WIFI_MAX_LENGTH_OF_SSID));
	ret = -1;
	goto cleanup;
    }

    LOG_I(common, "SSID('%s')", ssid);
    ret = wifi_config_set_ssid(port, ssid, ssid_len);
    if (ret < 0) {
	LOG_W(common, "wifi_config_set_ssid() failed(%d)", ret);
	goto cleanup;
    }

    LOG_I(common, "reload setting");
    ret = wifi_config_reload_setting();
    if (ret < 0) {
	LOG_W(common, "wifi_config_reload_setting() failed(%d)", ret);
	goto cleanup;
    }	

cleanup:
    if (ret < 0) {
	struct mt7697_connect_rsp connect_rsp;
    	connect_rsp.rsp.cmd.len = sizeof(struct mt7697_connect_rsp);
    	connect_rsp.rsp.cmd.grp = MT7697_CMD_GRP_80211;
    	connect_rsp.rsp.cmd.type = MT7697_CMD_CONNECT_RSP;
    	connect_rsp.rsp.result = ret;
	connect_rsp.if_idx = wifi_info.if_idx;

    	LOG_I(common, "<-- CONNECT result(%d)", ret);
    	size_t bWrite = spi_queue_write(QUEUE_WIFI_SLAVE_TO_MASTER, (const uint32_t*)&connect_rsp, QUEUE_LEN_TO_WORD(connect_rsp.rsp.cmd.len));
    	if (bWrite != QUEUE_LEN_TO_WORD(connect_rsp.rsp.cmd.len)) {
	    LOG_W(common, "spi_queue_write() failed(%d != %d)", bWrite, QUEUE_LEN_TO_WORD(connect_rsp.rsp.cmd.len));
    	}
    }

    return ret;
}

static int32_t wifi_proc_disconnect_req(uint8_t channel, uint16_t len)
{
    uint8_t addr[QUEUE_LEN32_ALIGNED(WIFI_MAC_ADDRESS_LENGTH)];
    size_t words_read;
    uint32_t if_idx;
    uint32_t port;
    int32_t ret = 0;

    LOG_I(common, "--> DISCONNECT(%d)", len);
    if (len < sizeof(struct mt7697_disconnect_req)) {
        LOG_W(common, "invalid len(%d < %d)", len, sizeof(struct mt7697_disconnect_req));
	ret = -1;
	goto cleanup;
    }

    words_read = spi_queue_read(channel, (uint32_t*)&if_idx, QUEUE_LEN_TO_WORD(sizeof(if_idx)));
    if (words_read != QUEUE_LEN_TO_WORD(sizeof(if_idx))) {
	LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, QUEUE_LEN_TO_WORD(sizeof(if_idx)));
	ret = -1;
	goto cleanup;
    }
    wifi_info.if_idx = if_idx;
    LOG_I(common, "if idx(%u)", wifi_info.if_idx);

    words_read = spi_queue_read(channel, (uint32_t*)&port, QUEUE_LEN_TO_WORD(sizeof(port)));
    if (words_read != QUEUE_LEN_TO_WORD(sizeof(port))) {
	LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, QUEUE_LEN_TO_WORD(sizeof(port)));
	ret = -1;
	goto cleanup;
    }

    LOG_I(common, "port(%u)", port);
    if (!wifi_validate_wifi_port(port)) {
        LOG_W(common, "invalid port(%d)", port);
	ret = -1;
	goto cleanup;
    }

    words_read = spi_queue_read(channel, (uint32_t*)addr, QUEUE_LEN_TO_WORD(WIFI_MAC_ADDRESS_LENGTH));
    if (words_read != QUEUE_LEN_TO_WORD(WIFI_MAC_ADDRESS_LENGTH)) {
	LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, QUEUE_LEN_TO_WORD(WIFI_MAC_ADDRESS_LENGTH));
	ret = -1;
	goto cleanup;
    }

    if (port == WIFI_PORT_AP) {
	LOG_HEXDUMP_I(common, "BSSID", addr, WIFI_MAC_ADDRESS_LENGTH);
	ret = wifi_connection_disconnect_sta(addr);
	if (ret < 0) {
  	    LOG_W(common, "wifi_connection_disconnect_sta() failed(%d)", ret);
	    goto cleanup;
	}
    }
    else {
	ret = wifi_connection_disconnect_ap();
	if (ret < 0) {
  	    LOG_W(common, "wifi_connection_disconnect_ap() failed(%d)", ret);
	    goto cleanup;
	}
    }	

cleanup:
    if (ret < 0) {
	struct mt7697_disconnect_rsp disconnect_rsp;

    	disconnect_rsp.rsp.cmd.len = sizeof(struct mt7697_disconnect_rsp);
    	disconnect_rsp.rsp.cmd.grp = MT7697_CMD_GRP_80211;
    	disconnect_rsp.rsp.cmd.type = MT7697_CMD_DISCONNECT_RSP;
    	disconnect_rsp.rsp.result = ret;
	disconnect_rsp.if_idx = if_idx;

    	LOG_I(common, "<-- DISCONNECT result(%d)", ret);
    	size_t bWrite = spi_queue_write(QUEUE_WIFI_SLAVE_TO_MASTER, (const uint32_t*)&disconnect_rsp, QUEUE_LEN_TO_WORD(disconnect_rsp.rsp.cmd.len));
    	if (bWrite != QUEUE_LEN_TO_WORD(disconnect_rsp.rsp.cmd.len)) {
	    LOG_W(common, "spi_queue_write() failed(%d != %d)", bWrite, QUEUE_LEN_TO_WORD(disconnect_rsp.rsp.cmd.len));
            ret = -1;
    	}
    }

    return ret;
}

static int32_t wifi_proc_register_rx_hndlr_req(uint8_t channel, uint16_t len)
{
    struct mt7697_register_rx_hndlr_rsp reg_rx_hndlr_rsp;
    int32_t ret = 0;

    reg_rx_hndlr_rsp.cmd.len = sizeof(struct mt7697_register_rx_hndlr_rsp);
    reg_rx_hndlr_rsp.cmd.grp = MT7697_CMD_GRP_80211;
    reg_rx_hndlr_rsp.cmd.type = MT7697_CMD_REGISTER_RX_HNDLR_RSP;

    LOG_I(common, "--> REGISTER RX HANDLER(%d)", len);
    if (len < sizeof(struct mt7697_register_rx_hndlr_req)) {
        LOG_W(common, "invalid len(%d < %d)", len, sizeof(struct mt7697_register_rx_hndlr_req));
	ret = -1;
	goto cleanup;
    }

    ret = wifi_config_register_rx_handler(wifi_rx_data_evt_hndlr);
    if (ret < 0) {
	LOG_W(common, "wifi_config_register_rx_handler() failed(%d)", ret);
	goto cleanup;
    }

cleanup:
    reg_rx_hndlr_rsp.result = ret;
    LOG_I(common, "<-- REGISTER RX HANDLER result(%d)", ret);
    size_t bWrite = spi_queue_write(QUEUE_WIFI_SLAVE_TO_MASTER, (const uint32_t*)&reg_rx_hndlr_rsp, QUEUE_LEN_TO_WORD(reg_rx_hndlr_rsp.cmd.len));
    if (bWrite != QUEUE_LEN_TO_WORD(reg_rx_hndlr_rsp.cmd.len)) {
	LOG_W(common, "spi_queue_write() failed(%d != %d)", bWrite, QUEUE_LEN_TO_WORD(reg_rx_hndlr_rsp.cmd.len));
        ret = -1;
    }

    return ret;
}

static int32_t wifi_proc_unregister_rx_hndlr_req(uint8_t channel, uint16_t len)
{
    struct mt7697_unregister_rx_hndlr_rsp unreg_rx_hndlr_rsp;
    int32_t ret = 0;

    unreg_rx_hndlr_rsp.cmd.len = sizeof(struct mt7697_register_rx_hndlr_rsp);
    unreg_rx_hndlr_rsp.cmd.grp = MT7697_CMD_GRP_80211;
    unreg_rx_hndlr_rsp.cmd.type = MT7697_CMD_REGISTER_RX_HNDLR_RSP;

    LOG_I(common, "--> UNREGSITER RX HANDLER(%d)", len);
    if (len < sizeof(struct mt7697_unregister_rx_hndlr_req)) {
        LOG_W(common, "invalid len(%d < %d)", len, sizeof(struct mt7697_unregister_rx_hndlr_req));
	ret = -1;
	goto cleanup;
    }

    ret = wifi_config_unregister_rx_handler();
    if (ret < 0) {
	LOG_W(common, "wifi_config_unregister_rx_handler() failed(%d)", ret);
	goto cleanup;
    }

cleanup:
    unreg_rx_hndlr_rsp.result = ret;
    LOG_I(common, "<-- UNREGISTER RX HANDLER result(%d)", ret);
    size_t bWrite = spi_queue_write(QUEUE_WIFI_SLAVE_TO_MASTER, (const uint32_t*)&unreg_rx_hndlr_rsp, QUEUE_LEN_TO_WORD(unreg_rx_hndlr_rsp.cmd.len));
    if (bWrite != QUEUE_LEN_TO_WORD(unreg_rx_hndlr_rsp.cmd.len)) {
	LOG_W(common, "spi_queue_write() failed(%d != %d)", bWrite, QUEUE_LEN_TO_WORD(unreg_rx_hndlr_rsp.cmd.len));
        ret = -1;
    }

    return ret;
}

static int32_t wifi_proc_tx_raw_req(uint8_t channel, uint16_t len)
{
    uint32_t tx_len;
    int32_t ret = 0;

    LOG_I(common, "--> TX RAW PKT(%d)", len);
    size_t words_read = spi_queue_read(channel, &tx_len, QUEUE_LEN_TO_WORD(sizeof(tx_len)));
    if (words_read != QUEUE_LEN_TO_WORD(sizeof(tx_len))) {
	LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, QUEUE_LEN_TO_WORD(sizeof(tx_len)));
	ret = -1;
	goto cleanup;
    }

    LOG_I(common, "Tx len(%d)", tx_len);
    if (!tx_len || tx_len > sizeof(wifi_info.tx_data)) {
	LOG_W(common, "invalid Tx len(%d)", tx_len);
	ret = -1;
	goto cleanup;
    }

    words_read = spi_queue_read(channel, (uint32_t*)wifi_info.tx_data, QUEUE_LEN_TO_WORD(tx_len));
    if (words_read != QUEUE_LEN_TO_WORD(tx_len)) {
	LOG_W(common, "spi_queue_read() failed(%d != %d)", words_read, QUEUE_LEN_TO_WORD(tx_len));
	ret = -1;
        goto cleanup;
    }

    LOG_HEXDUMP_I(common, "Tx packet", wifi_info.tx_data, tx_len);

    ret = wifi_connection_send_raw_packet(wifi_info.tx_data, tx_len);
    if (ret < 0) {
	LOG_W(common, "wifi_connection_send_raw_packet() failed(%d)", ret);
	goto cleanup;
    }

    ret = 0;

cleanup:
    return ret;
}

int32_t wifi_init_done_handler(wifi_event_t event, uint8_t *payload, uint32_t length)
{
    LOG_I(common, "WiFi Init Done: port(%d)", payload[6]);
    return 0;
}

int32_t wifi_proc_cmd(uint8_t channel, uint16_t len, uint8_t type)
{
    int32_t ret = 0;

    switch (type) {
    case MT7697_CMD_GET_PSK_REQ:
	ret = wifi_proc_get_psk_req(channel, len);
	if (ret) {
	    LOG_W(common, "wifi_proc_get_psk_req() failed(%d)", ret);
	}

	break;

    case MT7697_CMD_SET_PSK_REQ:
	ret = wifi_proc_set_psk_req(channel, len);
	if (ret) {
	    LOG_W(common, "wifi_proc_set_psk_req() failed(%d)", ret);
	}

	break;

    case MT7697_CMD_MAC_ADDR_REQ:
	ret = wifi_proc_mac_addr_req(channel, len);
	if (ret) {
	    LOG_W(common, "wifi_proc_mac_addr_req() failed(%d)", ret);
	}

	break;
    
    case MT7697_CMD_GET_WIRELESS_MODE_REQ:
	ret = wifi_proc_get_wireless_mode_req(channel, len);
	if (ret) {
	    LOG_W(common, "wifi_proc_get_wireless_mode_req() failed(%d)", ret);
	}

	break;

    case MT7697_CMD_SET_WIRELESS_MODE_REQ:
	ret = wifi_proc_set_wireless_mode_req(channel, len);
	if (ret) {
	    LOG_W(common, "wifi_proc_set_wireless_mode_req() failed(%d)", ret);
	}

	break;

    case MT7697_CMD_GET_CFG_REQ:
 	ret = wifi_proc_get_cfg_req(channel, len);
	if (ret) {
	    LOG_W(common, "wifi_proc_get_cfg_req() failed(%d)", ret);
	}

	break;

    case MT7697_CMD_SET_OP_MODE_REQ:
	ret = wifi_proc_set_opmode_req(channel, len);
	if (ret) {
	    LOG_W(common, "wifi_proc_set_opmode_req() failed(%d)", ret);
	}

	break;

    case MT7697_CMD_GET_RADIO_STATE_REQ:
	ret = wifi_proc_get_radio_state_req(channel, len);
	if (ret) {
	    LOG_W(common, "wifi_proc_get_radio_state_req() failed(%d)", ret);
	}

	break;

    case MT7697_CMD_SET_RADIO_STATE_REQ:
	ret = wifi_proc_set_radio_state_req(channel, len);
	if (ret) {
	    LOG_W(common, "wifi_proc_set_radio_state_req failed(%d)", ret);
	}

	break;

    case MT7697_CMD_GET_RX_FILTER_REQ:
	ret = wifi_proc_get_rx_filter_req(channel, len);
	if (ret) {
	    LOG_W(common, "wifi_proc_get_rx_filter_req() failed(%d)", ret);
	}

	break;

    case MT7697_CMD_SET_RX_FILTER_REQ:
	ret = wifi_proc_set_rx_filter_req(channel, len);
	if (ret) {
	    LOG_W(common, "wifi_proc_set_rx_filter_req() failed(%d)", ret);
	}

	break;

    case MT7697_CMD_GET_SMART_CONN_FILTER_REQ:
	ret = wifi_proc_get_smart_conn_filter_req(channel, len);
	if (ret) {
	    LOG_W(common, "wifi_proc_get_smart_conn_filter_req() failed(%d)", ret);
	}

	break;

    case MT7697_CMD_SET_SMART_CONN_FILTER_REQ:
	ret = wifi_proc_set_smart_conn_filter_req(channel, len);
	if (ret) {
	    LOG_W(common, "wifi_proc_set_smart_conn_filter_req() failed(%d)", ret);
	}

	break;

    case MT7697_CMD_GET_LISTEN_INTERVAL_REQ:
	ret = wifi_proc_get_listen_interval_req(channel, len);
	if (ret) {
	    LOG_W(common, "wifi_proc_get_listen_interval_req() failed(%d)", ret);
	}

	break;

    case MT7697_CMD_SET_LISTEN_INTERVAL_REQ:
	ret = wifi_proc_set_listen_interval_req(channel, len);
	if (ret) {
	    LOG_W(common, "wifi_proc_set_listen_interval_req() failed(%d)", ret);
	}

	break;

    case MT7697_CMD_SET_SECURITY_MODE_REQ:
	ret = wifi_proc_set_security_mode_req(channel, len);
	if (ret) {
	    LOG_W(common, "wifi_proc_set_security_mode_req() failed(%d)", ret);
	}

	break;

    case MT7697_CMD_GET_SECURITY_MODE_REQ:
	ret = wifi_proc_get_security_mode_req(channel, len);
	if (ret) {
	    LOG_W(common, "wifi_proc_get_security_mode_req() failed(%d)", ret);
	}

	break;

    case MT7697_CMD_SCAN_REQ:
	ret = wifi_proc_scan_req(channel, len);
	if (ret) {
	    LOG_W(common, "wifi_proc_scan_req() failed(%d)", ret);
	}

	break;

    case MT7697_CMD_SCAN_STOP:
 	ret = wifi_proc_scan_stop_req(channel, len);
	if (ret) {
	    LOG_W(common, "wifi_proc_scan_stop_req() failed(%d)", ret);
	}

	break;

    case MT7697_CMD_CONNECT_REQ:
	ret = wifi_proc_connect_req(channel, len);
	if (ret) {
	    LOG_W(common, "wifi_proc_connect_req() failed(%d)", ret);
	}

	break;

    case MT7697_CMD_DISCONNECT_REQ:
	ret = wifi_proc_disconnect_req(channel, len);
	if (ret) {
	    LOG_W(common, "wifi_proc_disconnect_req() failed(%d)", ret);
	}

	break;

    case MT7697_CMD_REGISTER_RX_HNDLR_REQ:
	ret = wifi_proc_register_rx_hndlr_req(channel, len);
	if (ret) {
	    LOG_W(common, "wifi_proc_register_rx_hndlr_req() failed(%d)", ret);
	}

	break;

    case MT7697_CMD_UNREGISTER_RX_HNDLR_REQ:
	ret = wifi_proc_unregister_rx_hndlr_req(channel, len);
	if (ret) {
	    LOG_W(common, "wifi_proc_unregister_rx_hndlr_req() failed(%d)", ret);
	}

	break;

    case MT7697_CMD_TX_RAW:
	ret = wifi_proc_tx_raw_req(channel, len);
	if (ret) {
	    LOG_W(common, "wifi_proc_tx_raw_req() failed(%d)", ret);
	}

	break;

    default:
	LOG_W(common, "invalid cmd type(%d)", type);
	ret = -1;
	break;
    }

    return ret;
}

int32_t wifi_init_evt_hndlrs(void)
{
    int32_t ret = 0;

    ret = wifi_connection_register_event_handler(WIFI_EVENT_IOT_REPORT_BEACON_PROBE_RESPONSE, wifi_event_hndlr);
    if (ret < 0) {
        LOG_E(common, "wifi_connection_register_event_handler() failed(%d)", ret);
        goto cleanup;
    }

    ret = wifi_connection_register_event_handler(WIFI_EVENT_IOT_SCAN_COMPLETE, wifi_event_hndlr);
    if (ret < 0) {
        LOG_E(common, "wifi_connection_register_event_handler() failed(%d)", ret);
        goto cleanup;
    }

    ret = wifi_connection_register_event_handler(WIFI_EVENT_IOT_CONNECTED, wifi_event_hndlr);
    if (ret < 0) {
	LOG_E(common, "wifi_connection_register_event_handler() failed(%d)", ret);
	goto cleanup;
    }

    ret = wifi_connection_register_event_handler(WIFI_EVENT_IOT_CONNECTION_FAILED, wifi_event_hndlr);
    if (ret < 0) {
	LOG_E(common, "wifi_connection_register_event_handler() failed(%d)", ret);
	goto cleanup;
    }

    ret = wifi_connection_register_event_handler(WIFI_EVENT_IOT_PORT_SECURE, wifi_event_hndlr);
    if (ret < 0) {
	LOG_E(common, "wifi_connection_register_event_handler() failed(%d)", ret);
	goto cleanup;
    }

    ret = wifi_connection_register_event_handler(WIFI_EVENT_IOT_WPS_COMPLETE, wifi_event_hndlr);
    if (ret < 0) {
	LOG_E(common, "wifi_connection_register_event_handler() failed(%d)", ret);
	goto cleanup;
    }

    ret = wifi_connection_register_event_handler(WIFI_EVENT_IOT_DISCONNECTED, wifi_event_hndlr);
    if (ret < 0) {
	LOG_E(common, "wifi_connection_register_event_handler() failed(%d)", ret);
	goto cleanup;
    }

cleanup:
    return ret;
}
