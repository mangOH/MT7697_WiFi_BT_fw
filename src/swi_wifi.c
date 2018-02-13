// stdlib
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

// FreeRTOS
#include <FreeRTOS.h>
#include <task.h>

#include "lwip/netif.h"
#include "ethernetif.h"

#include <wifi_api.h>
#include <wifi_rx_desc.h>
#include <wifi_private_api.h>

// SWI
#include "swi_spi_slave_queues.h"
#include "swi_wifi.h"

static int32_t swi_wifi_proc_set_pmk_req(swi_m2s_info_t* m2s_info, mt7697_cmd_hdr_t* cmd);
static int32_t swi_wifi_proc_set_channel_req(swi_m2s_info_t* m2s_info, mt7697_cmd_hdr_t* cmd);
static int32_t swi_wifi_proc_set_bssid_req(swi_m2s_info_t* m2s_info, mt7697_cmd_hdr_t* cmd);
static int32_t swi_wifi_proc_set_ssid_req(swi_m2s_info_t* m2s_info, mt7697_cmd_hdr_t* cmd);
static int32_t swi_wifi_proc_reload_settings_req(swi_m2s_info_t* m2s_info,
                                                 mt7697_cmd_hdr_t* cmd);
static int32_t swi_wifi_proc_mac_addr_req(swi_m2s_info_t* m2s_info, mt7697_cmd_hdr_t* cmd);
static int32_t swi_wifi_proc_get_wireless_mode_req(swi_m2s_info_t* m2s_info,
                                                   mt7697_cmd_hdr_t* cmd);
static int32_t swi_wifi_proc_set_wireless_mode_req(swi_m2s_info_t* m2s_info,
                                                   mt7697_cmd_hdr_t* cmd);
static int32_t swi_wifi_proc_get_cfg_req(swi_m2s_info_t* m2s_info, mt7697_cmd_hdr_t* cmd);
static int32_t swi_wifi_proc_set_op_mode_req(swi_m2s_info_t* m2s_info, mt7697_cmd_hdr_t* cmd);
static int32_t swi_wifi_proc_get_listen_interval_req(swi_m2s_info_t* m2s_info,
                                                     mt7697_cmd_hdr_t* cmd);
static int32_t swi_wifi_proc_set_listen_interval_req(swi_m2s_info_t* m2s_info,
                                                     mt7697_cmd_hdr_t* cmd);
static int32_t swi_wifi_proc_get_security_mode_req(swi_m2s_info_t* m2s_info,
                                                   mt7697_cmd_hdr_t* cmd);
static int32_t swi_wifi_proc_set_security_mode_req(swi_m2s_info_t* m2s_info,
                                                   mt7697_cmd_hdr_t* cmd);
static int32_t swi_wifi_proc_scan_req(swi_m2s_info_t* m2s_info, mt7697_cmd_hdr_t* cmd);
static int32_t swi_wifi_proc_scan_stop_req(swi_m2s_info_t* m2s_info, mt7697_cmd_hdr_t* cmd);
static int32_t swi_wifi_proc_disconnect_req(swi_m2s_info_t* m2s_info, mt7697_cmd_hdr_t* cmd);
static int32_t swi_wifi_proc_tx_raw_req(swi_m2s_info_t* m2s_info, mt7697_cmd_hdr_t* cmd);
static bool swi_wifi_validate_tx_raw_paket_size(const mt7697_cmd_hdr_t *cmd);

const struct mt7697_command_entry mt7697_commands_wifi[] = {
    CREATE_CMD_ENTRY(MT7697_CMD_SET_PMK_REQ,
                     swi_wifi_proc_set_pmk_req,
                     CREATE_VALIDATOR_ABSOLUTE(sizeof(mt7697_set_pmk_req_t))),
    CREATE_CMD_ENTRY(MT7697_CMD_SET_CHANNEL_REQ,
                     swi_wifi_proc_set_channel_req,
                     CREATE_VALIDATOR_ABSOLUTE(sizeof(mt7697_set_channel_req_t))),
    CREATE_CMD_ENTRY(MT7697_CMD_SET_BSSID_REQ,
                     swi_wifi_proc_set_bssid_req,
                     CREATE_VALIDATOR_ABSOLUTE(sizeof(mt7697_set_bssid_req_t))),
    CREATE_CMD_ENTRY(MT7697_CMD_SET_SSID_REQ,
                     swi_wifi_proc_set_ssid_req,
                     CREATE_VALIDATOR_ABSOLUTE(sizeof(mt7697_set_ssid_req_t))),
    CREATE_CMD_ENTRY(MT7697_CMD_RELOAD_SETTINGS_REQ,
                     swi_wifi_proc_reload_settings_req,
                     CREATE_VALIDATOR_ABSOLUTE(sizeof(mt7697_reload_settings_req_t))),
    CREATE_CMD_ENTRY(MT7697_CMD_MAC_ADDR_REQ,
                     swi_wifi_proc_mac_addr_req,
                     CREATE_VALIDATOR_ABSOLUTE(sizeof(mt7697_mac_addr_req_t))),
    CREATE_CMD_ENTRY(MT7697_CMD_GET_WIRELESS_MODE_REQ,
                     swi_wifi_proc_get_wireless_mode_req,
                     CREATE_VALIDATOR_ABSOLUTE(sizeof(mt7697_get_wireless_mode_req_t))),
    CREATE_CMD_ENTRY(MT7697_CMD_SET_WIRELESS_MODE_REQ,
                     swi_wifi_proc_set_wireless_mode_req,
                     CREATE_VALIDATOR_ABSOLUTE(sizeof(mt7697_set_wireless_mode_req_t))),
    CREATE_CMD_ENTRY(MT7697_CMD_GET_CFG_REQ,
                     swi_wifi_proc_get_cfg_req,
                     CREATE_VALIDATOR_ABSOLUTE(sizeof(mt7697_cfg_req_t))),
    CREATE_CMD_ENTRY(MT7697_CMD_SET_OP_MODE_REQ,
                     swi_wifi_proc_set_op_mode_req,
                     CREATE_VALIDATOR_ABSOLUTE(sizeof(mt7697_set_op_mode_req_t))),
    CREATE_CMD_ENTRY(MT7697_CMD_GET_LISTEN_INTERVAL_REQ,
                     swi_wifi_proc_get_listen_interval_req,
                     CREATE_VALIDATOR_ABSOLUTE(sizeof(mt7697_get_listen_interval_req_t))),
    CREATE_CMD_ENTRY(MT7697_CMD_SET_LISTEN_INTERVAL_REQ,
                     swi_wifi_proc_set_listen_interval_req,
                     CREATE_VALIDATOR_ABSOLUTE(sizeof(mt7697_set_listen_interval_req_t))),
    CREATE_CMD_ENTRY(MT7697_CMD_GET_SECURITY_MODE_REQ,
                     swi_wifi_proc_get_security_mode_req,
                     CREATE_VALIDATOR_ABSOLUTE(sizeof(mt7697_get_security_mode_req_t))),
    CREATE_CMD_ENTRY(MT7697_CMD_SET_SECURITY_MODE_REQ,
                     swi_wifi_proc_set_security_mode_req,
                     CREATE_VALIDATOR_ABSOLUTE(sizeof(mt7697_set_security_mode_req_t))),
    CREATE_CMD_ENTRY(MT7697_CMD_SCAN_REQ,
                     swi_wifi_proc_scan_req,
                     CREATE_VALIDATOR_ABSOLUTE(sizeof(mt7697_scan_req_t))),
    CREATE_CMD_ENTRY(MT7697_CMD_SCAN_STOP,
                     swi_wifi_proc_scan_stop_req,
                     CREATE_VALIDATOR_ABSOLUTE(sizeof(mt7697_scan_stop_req_t))),
    CREATE_CMD_ENTRY(MT7697_CMD_DISCONNECT_REQ,
                     swi_wifi_proc_disconnect_req,
                     CREATE_VALIDATOR_ABSOLUTE(sizeof(mt7697_disconnect_req_t))),
    CREATE_CMD_ENTRY(MT7697_CMD_TX_RAW,
                     swi_wifi_proc_tx_raw_req,
                     CREATE_VALIDATOR_FUNCTION(swi_wifi_validate_tx_raw_paket_size)),
};
const size_t mt7697_commands_wifi_count = ARRAY_SIZE(mt7697_commands_wifi);

mt7697_wifi_info_t wifi_info = {
    .if_idx = (uint16_t)-1,
    .channel = 0,
};

static bool swi_wifi_validate_port(uint32_t port)
{
    return ((port >= WIFI_PORT_STA) && (port <= WIFI_PORT_AP));
}

static int32_t swi_wifi_init_done_handler(wifi_event_t event, uint8_t *payload, uint32_t length)
{
    int ret;
    uint8_t opmode;

    LOG_I(common, "WiFi init done port(%d)", payload[6]);

    ret = wifi_config_get_opmode(&opmode);
    if (ret < 0) {
    LOG_W(common, "wifi_config_get_opmode() failed(%d)", ret);
    goto cleanup;
    }
    LOG_I(common, "opmode(%u)", opmode);

    wifi_info.netif =
        netif_find_by_type((opmode == WIFI_MODE_STA_ONLY) ? NETIF_TYPE_STA : NETIF_TYPE_AP);
    if (!wifi_info.netif) {
        LOG_E(common, "netif_find_by_type() failed(%d)", ret);
        goto cleanup;
    }

    netif_set_default(wifi_info.netif);

cleanup:
    return ret;
}


static int32_t swi_wifi_net_rx_hndlr(struct pbuf* buf, struct netif* netif)
{
    mt7697_rx_raw_packet_t *rx_req = NULL;
    int32_t ret = 0;

//    LOG_I(common, "netif(%u) len(%u)", netif->num, buf->tot_len);
//    LOG_HEXDUMP_I(common, "Rx data ", buf->payload, buf->tot_len);

    rx_req = (mt7697_rx_raw_packet_t*)swi_mem_pool_alloc_msg(
        &wifi_info.s2m_info->msg_pool_info, SWI_MEM_POOL_MSG_LO_PRIORITY, wifi_info.s2m_info->sendQ,
        LEN32_ALIGNED(sizeof(mt7697_rx_raw_packet_t) + buf->tot_len));
    if (!rx_req) {
    LOG_W(common, "swi_mem_pool_alloc_msg() failed");
        ret = -1;
    goto cleanup;
    }

    rx_req->hdr.cmd.grp = MT7697_CMD_GRP_80211;
    rx_req->hdr.cmd.type = MT7697_CMD_RX_RAW;
    rx_req->hdr.cmd.len = sizeof(mt7697_rx_raw_packet_t) + buf->tot_len;
    rx_req->hdr.result = buf->tot_len;
    memcpy(rx_req->data, buf->payload, buf->tot_len);

//    printf("<-- Rx(%u)\n", rx_req->hdr.cmd.len);
    ret = swi_s2m_send_req_from_isr(wifi_info.s2m_info, (mt7697_rsp_hdr_t*)rx_req);
    if (ret < 0) {
        LOG_W(common, "swi_s2m_send_req_from_isr() failed(%d)", ret);
        goto cleanup;
    }

cleanup:
    if (ret && rx_req) free(rx_req);
    return ret;
}

static int32_t swi_wifi_event_hndlr(wifi_event_t event, uint8_t* payload, uint32_t length)
{
    int32_t ret = 0;

//    LOG_I(common, "event(%u) payload(%u)", event, length);

    switch (event) {
    case WIFI_EVENT_IOT_REPORT_BEACON_PROBE_RESPONSE:
    {
        mt7697_scan_ind_t *ind;
        wifi_scan_list_item_t ap_data;

        LOG_I(common, "==> PROBE RESPONSE\n");
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

        printf("\n%-4s%-33s%-20s%-8s%-8s%-8s%-8s%-8s%-8s%-8s\n", "Ch", "SSID", "BSSID", "Auth",
               "Cipher", "RSSI", "WPS_EN", "CM", "DPID", "SR");
        printf("%-4d", ap_data.channel);
        printf("%-33s", ap_data.ssid);
        printf("%02x:%02x:%02x:%02x:%02x:%02x   ",
               ap_data.bssid[0], ap_data.bssid[1], ap_data.bssid[2], ap_data.bssid[3],
               ap_data.bssid[4], ap_data.bssid[5]);
        printf("%-8d", ap_data.auth_mode);
        printf("%-8d", ap_data.encrypt_type);
        printf("%-8d", ap_data.rssi);
        printf("%-8d", ap_data.is_wps_supported);

        /*
         * If received Beacon frame, the configuration_methods is 0, because the
         * configuration_methods is not exist in Beacon, it can't be parsed. it exist in Probe
         * Response Frame. If received Probe Response frame, the configuration_methods value is
         * meaningful.
         */
        printf("%-8d", ap_data.wps_element.configuration_methods);
        printf("%-8d", ap_data.wps_element.device_password_id);
        printf("%-8d", ap_data.wps_element.selected_registrar);
        printf("\n\n");

        ind = (mt7697_scan_ind_t*)swi_mem_pool_alloc_msg(
            &wifi_info.s2m_info->msg_pool_info, SWI_MEM_POOL_MSG_LO_PRIORITY,
            wifi_info.s2m_info->sendQ, LEN32_ALIGNED(sizeof(mt7697_scan_ind_t) + length));
        if (!ind) {
            LOG_W(common, "swi_mem_pool_alloc_msg() failed");
            ret = -1;
            goto cleanup;
        }

        ind->rsp.cmd.grp = MT7697_CMD_GRP_80211;
        ind->rsp.cmd.type = MT7697_CMD_SCAN_IND;
        ind->rsp.cmd.len = sizeof(mt7697_scan_ind_t) + length;
        ind->rssi = ap_data.rssi;
        ind->channel = ap_data.channel;
        ind->rsp.result = length;
        memcpy(ind->probe_rsp, payload, length);

        LOG_I(common, "<-- SCAN IND len(%u) result(%d)", ind->rsp.cmd.len, ind->rsp.result);
        ret = swi_s2m_send_req_from_isr(wifi_info.s2m_info, (mt7697_rsp_hdr_t*)ind);
        if (ret < 0) {
            LOG_W(common, "swi_s2m_send_req_from_isr() failed(%d)", ret);
            free(ind);
            goto cleanup;
        }

        break;
    }
    case WIFI_EVENT_IOT_SCAN_COMPLETE:
    {
        LOG_I(common, "==> SCAN COMPLETE\n");

        mt7697_scan_complete_ind_t* ind = (mt7697_scan_complete_ind_t*)swi_mem_pool_alloc_msg(
            &wifi_info.s2m_info->msg_pool_info, SWI_MEM_POOL_MSG_HI_PRIORITY,
            wifi_info.s2m_info->sendQ, LEN32_ALIGNED(sizeof(mt7697_scan_complete_ind_t)));
        if (!ind) {
            LOG_W(common, "swi_mem_pool_alloc_msg() failed");
            ret = -1;
            goto cleanup;
        }

        ind->rsp.cmd.len = sizeof(mt7697_scan_complete_ind_t);
        ind->rsp.cmd.grp = MT7697_CMD_GRP_80211;
        ind->rsp.cmd.type = MT7697_CMD_SCAN_COMPLETE_IND;
        ind->if_idx = wifi_info.if_idx;

        ind->rsp.result = ret;
        LOG_I(common, "<-- SCAN COMPLETE IND if idx(%u) len(%u) result(%d)", ind->if_idx,
              ind->rsp.cmd.len, ret);
        ret = swi_s2m_send_req_from_isr(wifi_info.s2m_info, (mt7697_rsp_hdr_t*)ind);
        if (ret < 0) {
            LOG_W(common, "swi_s2m_send_req_from_isr() failed(%d)", ret);
            free(ind);
            goto cleanup;
        }

        break;
    }
    case WIFI_EVENT_IOT_CONNECTED:
    {
        LOG_I(common, "==> CONNECTED\n");
        LOG_HEXDUMP_I(common, "MAC", payload, length);
        break;
    }
    case WIFI_EVENT_IOT_PORT_SECURE:
    {
        LOG_I(common, "==> PORT SECURE\n");
        if (wifi_info.netif) netif_set_link_up(wifi_info.netif);

        mt7697_connect_ind_t* ind = (mt7697_connect_ind_t*)swi_mem_pool_alloc_msg(
            &wifi_info.s2m_info->msg_pool_info, SWI_MEM_POOL_MSG_HI_PRIORITY,
            wifi_info.s2m_info->sendQ, LEN32_ALIGNED(sizeof(mt7697_connect_ind_t)));
        if (!ind) {
            LOG_W(common, "swi_mem_pool_alloc_msg() failed");
            ret = -1;
            goto cleanup;
        }

        ind->rsp.cmd.len = sizeof(mt7697_connect_ind_t);
        ind->rsp.cmd.grp = MT7697_CMD_GRP_80211;
        ind->rsp.cmd.type = MT7697_CMD_CONNECT_IND;
        ind->if_idx = wifi_info.if_idx;

        LOG_I(common, "Port Secure!\n");
        LOG_HEXDUMP_I(common, "MAC", payload, length);
        if ((length >= WIFI_MAC_ADDRESS_LENGTH) && payload) {
            memcpy(ind->bssid, payload, WIFI_MAC_ADDRESS_LENGTH);
        }
        else
            memset(ind->bssid, 0, WIFI_MAC_ADDRESS_LENGTH);

        LOG_I(common, "channel(%u)", wifi_info.channel);
        ind->channel = wifi_info.channel;

        ind->rsp.result = ret;
        LOG_I(common, "<-- CONNECT IND len(%u) result(%d)", ind->rsp.cmd.len, ret);
        ret = swi_s2m_send_req_from_isr(wifi_info.s2m_info, (mt7697_rsp_hdr_t*)ind);
        if (ret < 0) {
            LOG_W(common, "swi_s2m_send_req_from_isr() failed(%d)", ret);
            free(ind);
            goto cleanup;
        }

        break;
    }
    case WIFI_EVENT_IOT_DISCONNECTED:
    {
        uint8_t empty_bssid[WIFI_MAC_ADDRESS_LENGTH] = {0};

        LOG_I(common, "==> DISCONNECTED\n");
        if (wifi_info.netif) netif_set_link_down(wifi_info.netif);

        LOG_HEXDUMP_I(common, "MAC", payload, length);
        if (memcmp(payload, empty_bssid, WIFI_MAC_ADDRESS_LENGTH)) {
            mt7697_disconnect_ind_t* ind = (mt7697_disconnect_ind_t*)swi_mem_pool_alloc_msg(
                &wifi_info.s2m_info->msg_pool_info, SWI_MEM_POOL_MSG_HI_PRIORITY,
                wifi_info.s2m_info->sendQ, LEN32_ALIGNED(sizeof(mt7697_disconnect_ind_t)));
            if (!ind) {
                LOG_W(common, "swi_mem_pool_alloc_msg() failed");
                ret = -1;
                goto cleanup;
            }

            ind->rsp.cmd.len = sizeof(mt7697_disconnect_ind_t);
            ind->rsp.cmd.grp = MT7697_CMD_GRP_80211;
            ind->rsp.cmd.type = MT7697_CMD_DISCONNECT_IND;
            ind->if_idx = wifi_info.if_idx;

            if ((length >= WIFI_MAC_ADDRESS_LENGTH) && payload)
                memcpy(ind->bssid, payload, WIFI_MAC_ADDRESS_LENGTH);
            else
                memset(ind->bssid, 0, WIFI_MAC_ADDRESS_LENGTH);

            ind->rsp.result = ret;
            LOG_I(common, "<-- DISCONNECT IND len(%u) result(%d)", ind->rsp.cmd.len, ret);
            ret = swi_s2m_send_req_from_isr(wifi_info.s2m_info, (mt7697_rsp_hdr_t*)ind);
            if (ret < 0) {
                LOG_W(common, "swi_s2m_send_req_from_isr() failed(%d)", ret);
                free(ind);
                goto cleanup;
            }
        }

        break;
    }
    case WIFI_EVENT_IOT_CONNECTION_FAILED:
        LOG_I(common, "==> CONNECTION FAILED\n");
        break;

    default:
        LOG_W(common, "==> unhandled event(%u)", event);
        goto cleanup;
    }

cleanup:
    return ret;
}

static int32_t swi_wifi_proc_set_pmk_req(swi_m2s_info_t* m2s_info, mt7697_cmd_hdr_t* cmd)
{
	mt7697_set_pmk_req_t* set_pmk_req = (mt7697_set_pmk_req_t*)cmd;
    int32_t ret = 0;
    uint8_t passphrase[WIFI_LENGTH_PASSPHRASE + 1] = {0};
    uint8_t passphrase_length;
    const uint32_t port = set_pmk_req->port;
    uint8_t empty_pmk[sizeof(set_pmk_req->pmk)] = {0};

    mt7697_set_pmk_rsp_t* rsp = (mt7697_set_pmk_rsp_t*)swi_mem_pool_alloc_msg(
        &wifi_info.s2m_info->msg_pool_info, SWI_MEM_POOL_MSG_HI_PRIORITY, wifi_info.s2m_info->sendQ,
        LEN32_ALIGNED(sizeof(mt7697_set_pmk_rsp_t)));
    if (!rsp) {
        LOG_W(common, "swi_mem_pool_alloc_msg() failed");
        ret = -1;
        goto cleanup;
    }

    rsp->cmd.len = sizeof(mt7697_set_pmk_rsp_t);
    rsp->cmd.grp = MT7697_CMD_GRP_80211;
    rsp->cmd.type = MT7697_CMD_SET_PMK_RSP;

    LOG_I(common, "--> SET PMK");

    memcpy(passphrase,  set_pmk_req->pmk, sizeof(set_pmk_req->pmk));
    LOG_I(common, "PMK ('%s')", passphrase);

    LOG_I(common, "PMK port(%d)", port);
    if (!swi_wifi_validate_port(port)) {
        LOG_W(common, "invalid port(%d)", port);
        ret = -1;
        goto cleanup;
    }

    ret = wifi_config_get_wpa_psk_key(port, passphrase, &passphrase_length);
    if (ret < 0) {
        LOG_W(common, "wifi_config_get_wpa_psk_key() failed(%d)", ret);
        goto cleanup;
    }
    LOG_I(common, "Curr PMK ('%s')", passphrase);

    if (passphrase_length != sizeof(set_pmk_req->pmk) || memcmp(set_pmk_req->pmk, passphrase, sizeof(set_pmk_req->pmk))) {
        if (memcmp(set_pmk_req->pmk, empty_pmk, WIFI_LENGTH_PASSPHRASE)) {
            ret = wifi_config_set_wpa_psk_key(port, set_pmk_req->pmk, WIFI_LENGTH_PASSPHRASE);
            if (ret < 0) {
                LOG_W(common, "wifi_config_set_wpa_psk_key() failed(%d)", ret);
                goto cleanup;
            }

            if (port == WIFI_PORT_AP) {
                ret = wifi_config_set_security_mode(port, WIFI_AUTH_MODE_WPA2_PSK , WIFI_ENCRYPT_TYPE_AES_ENABLED);
                if (ret < 0) {
                    LOG_W(common, "wifi_config_set_security_mode() failed(%d)", ret);
                    goto cleanup;
                }
            }
        }
        else {
            ret = wifi_config_set_security_mode(port, WIFI_AUTH_MODE_OPEN, WIFI_ENCRYPT_TYPE_ENCRYPT_DISABLED);
            if (ret < 0) {
                LOG_W(common, "wifi_config_set_security_mode() failed(%d)", ret);
                goto cleanup;
            }
        }

        wifi_info.reload = true;
    }

cleanup:
    if (rsp) {
        rsp->result = ret;
        LOG_I(common, "<-- SET PMK rsp len(%u) result(%d)", rsp->cmd.len, ret);
        int32_t err = swi_s2m_send_req(wifi_info.s2m_info, (mt7697_rsp_hdr_t*)rsp);
        if (err < 0) {
            LOG_W(common, "swi_s2m_send_req() failed(%d)", err);
            ret = ret ? ret:err;
        }
    }

    return ret;
}

static int32_t swi_wifi_proc_set_channel_req(swi_m2s_info_t* m2s_info, mt7697_cmd_hdr_t* cmd)
{
	mt7697_set_channel_req_t* set_channel_req = (mt7697_set_channel_req_t*)cmd;
    uint32_t ch;
    uint32_t port;
    int32_t ret = 0;

    mt7697_set_channel_rsp_t* rsp = (mt7697_set_channel_rsp_t*)swi_mem_pool_alloc_msg(
        &wifi_info.s2m_info->msg_pool_info, SWI_MEM_POOL_MSG_HI_PRIORITY, wifi_info.s2m_info->sendQ,
        LEN32_ALIGNED(sizeof(mt7697_set_channel_rsp_t)));
    if (!rsp) {
        LOG_W(common, "swi_mem_pool_alloc_msg() failed");
        ret = -1;
        goto cleanup;
    }

    rsp->cmd.len = sizeof(mt7697_set_channel_rsp_t);
    rsp->cmd.grp = MT7697_CMD_GRP_80211;
    rsp->cmd.type = MT7697_CMD_SET_CHANNEL_RSP;

    LOG_I(common, "--> SET CHANNEL(%d)", cmd->len);

    port = set_channel_req->port;
    ch = set_channel_req->ch;

    ret = wifi_config_get_channel(port, &wifi_info.channel);
    if (ret < 0) {
        LOG_W(common, "wifi_config_get_channel() failed(%d)", ret);
        goto cleanup;
    }

    LOG_I(common, "channel curr/set(%u/%u)", wifi_info.channel, ch);
    if (!ch) {
        LOG_W(common, "invalid channel(%d)", ch);
        ret = -1;
        goto cleanup;
    }

    if (wifi_info.channel != ch) {
        LOG_I(common, "channel port(%d)", port);
        if (!swi_wifi_validate_port(port)) {
            LOG_W(common, "invalid port(%d)", port);
            ret = -1;
            goto cleanup;
        }

        ret = wifi_config_set_channel(port, (uint8_t)ch);
        if (ret < 0) {
            LOG_W(common, "wifi_config_set_channel() failed(%d)", ret);
            goto cleanup;
        }

        wifi_info.channel = ch;
    }

cleanup:
    if (rsp) {
        rsp->result = ret;
        LOG_I(common, "<-- SET CHANNEL rsp len(%u) result(%d)", rsp->cmd.len, ret);
        int32_t err = swi_s2m_send_req(wifi_info.s2m_info, (mt7697_rsp_hdr_t*)rsp);
        if (err < 0) {
            LOG_W(common, "swi_s2m_send_req() failed(%d)", err);
            ret = ret ? ret:err;
        }
    }

    return ret;
}

static int32_t swi_wifi_proc_set_bssid_req(swi_m2s_info_t* m2s_info, mt7697_cmd_hdr_t* cmd)
{
	mt7697_set_bssid_req_t* set_bssid_req = (mt7697_set_bssid_req_t*)cmd;
    int32_t ret = 0;

    mt7697_set_bssid_rsp_t* rsp = (mt7697_set_bssid_rsp_t*)swi_mem_pool_alloc_msg(
        &wifi_info.s2m_info->msg_pool_info, SWI_MEM_POOL_MSG_HI_PRIORITY, wifi_info.s2m_info->sendQ,
        LEN32_ALIGNED(sizeof(mt7697_set_bssid_rsp_t)));
    if (!rsp) {
        LOG_W(common, "swi_mem_pool_alloc_msg() failed");
        ret = -1;
        goto cleanup;
    }

    rsp->cmd.len = sizeof(mt7697_set_bssid_rsp_t);
    rsp->cmd.grp = MT7697_CMD_GRP_80211;
    rsp->cmd.type = MT7697_CMD_SET_BSSID_RSP;

    LOG_I(common, "--> SET BSSID(%d)", cmd->len);
    LOG_HEXDUMP_I(common, "BSSID", set_bssid_req->bssid, WIFI_MAC_ADDRESS_LENGTH);

    ret = wifi_config_set_bssid(set_bssid_req->bssid);
    if (ret < 0) {
        LOG_W(common, "wifi_config_set_bssid() failed(%d)", ret);
        goto cleanup;
    }

cleanup:
    if (rsp) {
        rsp->result = ret;
        LOG_I(common, "<-- SET BSSID rsp len(%u) result(%d)", rsp->cmd.len, ret);
        int32_t err = swi_s2m_send_req(wifi_info.s2m_info, (mt7697_rsp_hdr_t*)rsp);
        if (err < 0) {
            LOG_W(common, "swi_s2m_send_req() failed(%d)", err);
            ret = ret ? ret:err;
        }
    }

    return ret;
}

static int32_t swi_wifi_proc_set_ssid_req(swi_m2s_info_t* m2s_info, mt7697_cmd_hdr_t* cmd)
{
	mt7697_set_ssid_req_t* set_ssid_req = (mt7697_set_ssid_req_t*)cmd;
    uint8_t ssid[WIFI_MAX_LENGTH_OF_SSID + 1] = {0};
    uint8_t curr_ssid[WIFI_MAX_LENGTH_OF_SSID + 1] = {0};
    uint32_t ssid_len;
    uint32_t port;
    int32_t ret = 0;
    uint8_t curr_ssid_len;

    mt7697_set_ssid_rsp_t* rsp = (mt7697_set_ssid_rsp_t*)swi_mem_pool_alloc_msg(
        &wifi_info.s2m_info->msg_pool_info, SWI_MEM_POOL_MSG_HI_PRIORITY, wifi_info.s2m_info->sendQ,
        LEN32_ALIGNED(sizeof(mt7697_set_ssid_rsp_t)));
    if (!rsp) {
        LOG_W(common, "MT7697_S2M_QUEUE() failed");
        ret = -1;
        goto cleanup;
    }

    rsp->cmd.len = sizeof(mt7697_set_ssid_rsp_t);
    rsp->cmd.grp = MT7697_CMD_GRP_80211;
    rsp->cmd.type = MT7697_CMD_SET_SSID_RSP;

    LOG_I(common, "--> SET SSID(%d)", cmd->len);

    port = set_ssid_req->port;
    ssid_len = set_ssid_req->len;
    memcpy(ssid, set_ssid_req->ssid, WIFI_MAX_LENGTH_OF_SSID);

    LOG_I(common, "SSID len(%u)", ssid_len);
    if (ssid_len > WIFI_MAX_LENGTH_OF_SSID) {
        LOG_W(common, "invalid SSID len(%u > %u)", ssid_len, WIFI_MAX_LENGTH_OF_SSID);
        ret = -1;
        goto cleanup;
    }

    LOG_I(common, "SSID port(%d)", port);
    if (!swi_wifi_validate_port(port)) {
        LOG_W(common, "invalid port(%d)", port);
        ret = -1;
        goto cleanup;
    }

    ret = wifi_config_get_ssid(port, curr_ssid, &curr_ssid_len);
    if (ret < 0) {
        LOG_W(common, "wifi_config_get_ssid() failed(%d)", ret);
        goto cleanup;
    }

    curr_ssid[curr_ssid_len] = '\0';
    LOG_I(common, "SSID curr/set('%s'/'%s')", curr_ssid, ssid);
    if ((ssid_len != curr_ssid_len) || memcmp(ssid, curr_ssid, ssid_len)) {
        ret = wifi_config_set_ssid(port, ssid, ssid_len);
        if (ret < 0) {
            LOG_W(common, "wifi_config_set_ssid() failed(%d)", ret);
            goto cleanup;
        }

        wifi_info.reload = true;
    }

cleanup:
    if (rsp) {
        rsp->result = ret;
        LOG_I(common, "<-- SET SSID rsp len(%u) result(%d)", rsp->cmd.len, ret);
        int32_t err = swi_s2m_send_req(wifi_info.s2m_info, (mt7697_rsp_hdr_t*)rsp);
        if (err < 0) {
            LOG_W(common, "swi_s2m_send_req() failed(%d)", err);
            ret = ret ? ret:err;
        }
    }

    return ret;
}

static int32_t swi_wifi_proc_reload_settings_req(swi_m2s_info_t* m2s_info,
                                                 mt7697_cmd_hdr_t* cmd)
{
	mt7697_reload_settings_req_t* reload_settings_req = (mt7697_reload_settings_req_t*)cmd;
    uint32_t if_idx;
    int32_t ret = 0;

    mt7697_reload_settings_rsp_t* rsp = (mt7697_reload_settings_rsp_t*)swi_mem_pool_alloc_msg(
        &wifi_info.s2m_info->msg_pool_info, SWI_MEM_POOL_MSG_HI_PRIORITY, wifi_info.s2m_info->sendQ,
        LEN32_ALIGNED(sizeof(mt7697_reload_settings_rsp_t)));
    if (!rsp) {
        LOG_W(common, "swi_mem_pool_alloc_msg() failed");
        ret = -1;
        goto cleanup;
    }

    LOG_I(common, "--> RELOAD SETTINGS(%d)", cmd->len);

    rsp->cmd.len = sizeof(mt7697_reload_settings_rsp_t);
    rsp->cmd.grp = MT7697_CMD_GRP_80211;
    rsp->cmd.type = MT7697_CMD_RELOAD_SETTINGS_RSP;

    if_idx = reload_settings_req->if_idx;
    LOG_I(common, "if idx(%d)", if_idx);
    wifi_info.if_idx = if_idx;

    LOG_I(common, "reload(%d)", wifi_info.reload);
    if (wifi_info.reload) {
        ret = wifi_config_reload_setting();
        if (ret < 0) {
            LOG_W(common, "wifi_config_reload_setting() failed(%d)", ret);
            goto cleanup;
        }

        wifi_info.reload = false;
    }

cleanup:
    if (rsp) {
        rsp->result = ret;
        LOG_I(common, "<-- RELOAD SETTINGS rsp len(%u) result(%d)", rsp->cmd.len, ret);
        int32_t err = swi_s2m_send_req(wifi_info.s2m_info, (mt7697_rsp_hdr_t*)rsp);
        if (err < 0) {
            LOG_W(common, "swi_s2m_send_req() failed(%d)", err);
            ret = ret ? ret:err;
        }
    }

    return ret;
}

static int32_t swi_wifi_proc_mac_addr_req(swi_m2s_info_t* m2s_info, mt7697_cmd_hdr_t* cmd)
{
	mt7697_mac_addr_req_t* mac_addr_req = (mt7697_mac_addr_req_t*)cmd;
    uint8_t mac_addr[WIFI_MAC_ADDRESS_LENGTH];
    uint32_t port;
    int32_t ret = 0;

    mt7697_mac_addr_rsp_t* rsp = (mt7697_mac_addr_rsp_t*)swi_mem_pool_alloc_msg(
        &wifi_info.s2m_info->msg_pool_info, SWI_MEM_POOL_MSG_HI_PRIORITY, wifi_info.s2m_info->sendQ,
        LEN32_ALIGNED(sizeof(mt7697_mac_addr_rsp_t)));
    if (!rsp) {
        LOG_W(common, "swi_mem_pool_alloc_msg() failed");
        ret = -1;
        goto cleanup;
    }

    rsp->rsp.cmd.len = sizeof(mt7697_mac_addr_rsp_t);
    rsp->rsp.cmd.grp = MT7697_CMD_GRP_80211;
    rsp->rsp.cmd.type = MT7697_CMD_MAC_ADDR_RSP;

    LOG_I(common, "--> GET MAC ADDRESS(%d)", cmd->len);

    port = mac_addr_req->port;
    if (!swi_wifi_validate_port(port)) {
        LOG_W(common, "invalid port(%d)", port);
        ret = -1;
        goto cleanup;
    }

    LOG_I(common, "MAC address port(%d)", port);
    ret = wifi_config_get_mac_address(port, mac_addr);
    if (ret < 0) {
        LOG_W(common, "wifi_config_get_mac_address() failed(%d)", ret);
        goto cleanup;
    }

    memcpy(rsp->addr, mac_addr, WIFI_MAC_ADDRESS_LENGTH);
    LOG_HEXDUMP_I(common, "MAC", rsp->addr, WIFI_MAC_ADDRESS_LENGTH);

cleanup:
    if (rsp) {
        rsp->rsp.result = ret;
        LOG_I(common, "<-- GET MAC ADDRESS rsp len(%u) result(%d)", rsp->rsp.cmd.len, ret);
        int32_t err = swi_s2m_send_req(wifi_info.s2m_info, (mt7697_rsp_hdr_t*)rsp);
        if (err < 0) {
            LOG_W(common, "swi_s2m_send_req() failed(%d)", err);
            ret = ret ? ret:err;
        }
    }

    return ret;
}

static int32_t swi_wifi_proc_get_wireless_mode_req(swi_m2s_info_t* m2s_info,
                                                   mt7697_cmd_hdr_t* cmd)
{
	mt7697_get_wireless_mode_req_t* get_wireless_mode_req = (mt7697_get_wireless_mode_req_t*)cmd;
    wifi_phy_mode_t mode;
    uint32_t port;
    int32_t ret = 0;

    mt7697_get_wireless_mode_rsp_t* rsp = (mt7697_get_wireless_mode_rsp_t*)swi_mem_pool_alloc_msg(
        &wifi_info.s2m_info->msg_pool_info, SWI_MEM_POOL_MSG_HI_PRIORITY, wifi_info.s2m_info->sendQ,
        LEN32_ALIGNED(sizeof(mt7697_get_wireless_mode_rsp_t)));
    if (!rsp) {
        LOG_W(common, "swi_mem_pool_alloc_msg() failed");
        ret = -1;
        goto cleanup;
    }

    rsp->rsp.cmd.len = sizeof(mt7697_get_wireless_mode_rsp_t);
    rsp->rsp.cmd.grp = MT7697_CMD_GRP_80211;
    rsp->rsp.cmd.type = MT7697_CMD_GET_WIRELESS_MODE_RSP;

    LOG_I(common, "--> GET WIRELESS MODE(%d)", cmd->len);
    port = get_wireless_mode_req->port;

    if (!swi_wifi_validate_port(port)) {
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

    rsp->mode = mode;
    LOG_I(common, "wireless mode(%u)", rsp->mode);

cleanup:
    if (rsp) {
        rsp->rsp.result = ret;
        LOG_I(common, "<-- GET WIRELESS MODE rsp len(%u) result(%d)", rsp->rsp.cmd.len, ret);
        int32_t err = swi_s2m_send_req(wifi_info.s2m_info, (mt7697_rsp_hdr_t*)rsp);
        if (err < 0) {
            LOG_W(common, "swi_s2m_send_req() failed(%d)", err);
            ret = ret ? ret:err;
        }
    }

    return ret;
}

static int32_t swi_wifi_proc_set_wireless_mode_req(swi_m2s_info_t* m2s_info,
                                                   mt7697_cmd_hdr_t* cmd)
{
	mt7697_set_wireless_mode_req_t* set_wireless_mode_req = (mt7697_set_wireless_mode_req_t*)cmd;
    uint32_t port;
    uint32_t mode;
    int32_t ret = 0;

    mt7697_set_wireless_mode_rsp_t* rsp = (mt7697_set_wireless_mode_rsp_t*)swi_mem_pool_alloc_msg(
        &wifi_info.s2m_info->msg_pool_info, SWI_MEM_POOL_MSG_HI_PRIORITY, wifi_info.s2m_info->sendQ,
        LEN32_ALIGNED(sizeof(mt7697_set_wireless_mode_rsp_t)));
    if (!rsp) {
        LOG_W(common, "swi_mem_pool_alloc_msg() failed");
        ret = -1;
        goto cleanup;
    }

    rsp->cmd.len = sizeof(mt7697_set_wireless_mode_rsp_t);
    rsp->cmd.grp = MT7697_CMD_GRP_80211;
    rsp->cmd.type = MT7697_CMD_SET_WIRELESS_MODE_RSP;

    LOG_I(common, "--> SET WIRELESS MODE(%d)", cmd->len);
    port = set_wireless_mode_req->port;
    mode = set_wireless_mode_req->mode;

    if (!swi_wifi_validate_port(port)) {
        LOG_W(common, "invalid port(%d)", port);
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
    if (rsp) {
        rsp->result = ret;
        LOG_I(common, "<-- SET WIRELESS MODE rsp len(%u) result(%d)", rsp->cmd.len, ret);
        int32_t err = swi_s2m_send_req(wifi_info.s2m_info, (mt7697_rsp_hdr_t*)rsp);
        if (err < 0) {
            LOG_W(common, "swi_s2m_send_req() failed(%d)", err);
            ret = ret ? ret:err;
        }
    }

    return ret;
}

static int32_t swi_wifi_proc_get_cfg_req(swi_m2s_info_t* m2s_info, mt7697_cmd_hdr_t* cmd)
{
    int32_t ret = 0;

    mt7697_cfg_rsp_t* cfg_rsp = (mt7697_cfg_rsp_t*)swi_mem_pool_alloc_msg(
        &wifi_info.s2m_info->msg_pool_info, SWI_MEM_POOL_MSG_HI_PRIORITY, wifi_info.s2m_info->sendQ,
        LEN32_ALIGNED(sizeof(mt7697_cfg_rsp_t)));
    if (!cfg_rsp) {
        LOG_W(common, "swi_mem_pool_alloc_msg() failed");
        ret = -1;
        goto cleanup;
    }

    cfg_rsp->rsp.cmd.len = sizeof(mt7697_cfg_rsp_t);
    cfg_rsp->rsp.cmd.grp = MT7697_CMD_GRP_80211;
    cfg_rsp->rsp.cmd.type = MT7697_CMD_GET_CFG_RSP;

    LOG_I(common, "--> GET CONFIG(%d)", cmd->len);

    ret = wifi_config_get_opmode(&cfg_rsp->cfg.opmode);
    if (ret < 0) {
        LOG_W(common, "wifi_config_get_opmode() failed(%d)", ret);
        goto cleanup;
    }
    LOG_I(common, "opmode(%u)", cfg_rsp->cfg.opmode);

    if ((cfg_rsp->cfg.opmode == WIFI_MODE_STA_ONLY) ||
        (cfg_rsp->cfg.opmode == WIFI_MODE_REPEATER)) {
        ret = wifi_config_get_ssid(WIFI_PORT_STA, cfg_rsp->cfg.sta_config.ssid,
                                   &cfg_rsp->cfg.sta_config.ssid_length);
        if (ret < 0) {
            LOG_W(common, "wifi_config_get_ssid() failed(%d)", ret);
        }
        cfg_rsp->cfg.sta_config.ssid[cfg_rsp->cfg.sta_config.ssid_length] = '\0';
        LOG_I(common, "STA SSID(%u/'%s')", cfg_rsp->cfg.sta_config.ssid_length,
              cfg_rsp->cfg.sta_config.ssid);

        ret = wifi_config_get_bssid(cfg_rsp->cfg.sta_config.bssid);
        if (ret < 0) {
            LOG_W(common, "wifi_config_get_bssid() failed(%d)", ret);
        }
        else {
            cfg_rsp->cfg.sta_config.bssid_present = true;
            LOG_HEXDUMP_I(common, "STA BSSID", cfg_rsp->cfg.sta_config.bssid,
                          WIFI_MAC_ADDRESS_LENGTH);
        }

        ret = wifi_config_get_wpa_psk_key(WIFI_PORT_STA, cfg_rsp->cfg.sta_config.password,
                                          &cfg_rsp->cfg.sta_config.password_length);
        if (ret < 0) {
            LOG_W(common, "wifi_config_get_wpa_psk_key() failed(%d)", ret);
        }
        cfg_rsp->cfg.sta_config.password[cfg_rsp->cfg.sta_config.password_length] = '\0';
        LOG_I(common, "STA password(%u/'%s')", cfg_rsp->cfg.sta_config.password_length,
              cfg_rsp->cfg.sta_config.password);
    }

    if ((cfg_rsp->cfg.opmode == WIFI_MODE_AP_ONLY) || (cfg_rsp->cfg.opmode == WIFI_MODE_REPEATER)) {
        ret = wifi_config_get_ssid(WIFI_PORT_AP, cfg_rsp->cfg.ap_config.ssid,
                                   &cfg_rsp->cfg.ap_config.ssid_length);
        if (ret < 0) {
            LOG_W(common, "wifi_config_get_ssid() failed(%d)", ret);
        }
        cfg_rsp->cfg.ap_config.ssid[cfg_rsp->cfg.ap_config.ssid_length] = '\0';
        LOG_I(common, "AP SSID(%u/'%s')", cfg_rsp->cfg.ap_config.ssid_length,
              cfg_rsp->cfg.ap_config.ssid);

        ret = wifi_config_get_wpa_psk_key(WIFI_PORT_AP, cfg_rsp->cfg.ap_config.password,
                                          &cfg_rsp->cfg.ap_config.password_length);
        if (ret < 0) {
            LOG_W(common, "wifi_config_get_wpa_psk_key() failed(%d)", ret);
        }
        cfg_rsp->cfg.ap_config.password[cfg_rsp->cfg.ap_config.password_length] = '\0';
        LOG_I(common, "AP password(%u/'%s')", cfg_rsp->cfg.ap_config.password_length,
              cfg_rsp->cfg.ap_config.password);

        ret = wifi_config_get_security_mode(WIFI_PORT_AP, &cfg_rsp->cfg.ap_config.auth_mode,
                                            &cfg_rsp->cfg.ap_config.encrypt_type);
        if (ret < 0) {
            LOG_W(common, "wifi_config_get_security_mode() failed(%d)", ret);
            goto cleanup;
        }
        LOG_I(common, "AP auth mode(%u) encrypt type(%u)", cfg_rsp->cfg.ap_config.auth_mode,
              cfg_rsp->cfg.ap_config.encrypt_type);

        ret = wifi_config_get_channel(WIFI_PORT_AP, &cfg_rsp->cfg.ap_config.channel);
        if (ret < 0) {
            LOG_W(common, "wifi_config_get_channel() failed(%d)", ret);
        }
        LOG_I(common, "AP channel(%u)", cfg_rsp->cfg.ap_config.channel);

        ret = wifi_config_get_bandwidth(WIFI_PORT_AP, &cfg_rsp->cfg.ap_config.bandwidth);
        if (ret < 0) {
            LOG_W(common, "wifi_config_get_bandwidth() failed(%d)", ret);
        }
        LOG_I(common, "AP bandwidth(%u)", cfg_rsp->cfg.ap_config.bandwidth);

        if (cfg_rsp->cfg.ap_config.bandwidth == WIFI_IOT_COMMAND_CONFIG_BANDWIDTH_40MHZ) {
            ret = wifi_config_get_bandwidth_extended(WIFI_PORT_AP,
                                                     &cfg_rsp->cfg.ap_config.bandwidth,
                                                     &cfg_rsp->cfg.ap_config.bandwidth_ext);
            if (ret < 0) {
                LOG_W(common, "wifi_config_get_bandwidth_extended() failed(%d)", ret);
            }
            LOG_I(common, "AP bandwidth ext(%u)", cfg_rsp->cfg.ap_config.bandwidth_ext);
        }
    }

cleanup:
    if (cfg_rsp) {
        cfg_rsp->rsp.result = ret;
        LOG_I(common, "<-- GET CONFIG rsp len(%u) result(%d)", cfg_rsp->rsp.cmd.len, ret);
        int32_t err = swi_s2m_send_req(wifi_info.s2m_info, (mt7697_rsp_hdr_t*)cfg_rsp);
        if (err < 0) {
            LOG_W(common, "swi_s2m_send_req() failed(%d)", err);
            ret = ret ? ret:err;
        }
    }

    return ret;
}

static int32_t swi_wifi_proc_set_op_mode_req(swi_m2s_info_t* m2s_info, mt7697_cmd_hdr_t* cmd)
{
	mt7697_set_op_mode_req_t* set_op_mode_req = (mt7697_set_op_mode_req_t*)cmd;
    uint32_t opmode;
    int32_t ret = 0;
    uint8_t curr_opmode;

    mt7697_set_op_mode_rsp_t* rsp = (mt7697_set_op_mode_rsp_t*)swi_mem_pool_alloc_msg(
        &wifi_info.s2m_info->msg_pool_info, SWI_MEM_POOL_MSG_HI_PRIORITY, wifi_info.s2m_info->sendQ,
        LEN32_ALIGNED(sizeof(mt7697_set_op_mode_req_t)));
    if (!rsp) {
        LOG_W(common, "swi_mem_pool_alloc_msg() failed");
        ret = -1;
        goto cleanup;
    }

    rsp->cmd.len = sizeof(mt7697_set_op_mode_req_t);
    rsp->cmd.grp = MT7697_CMD_GRP_80211;
    rsp->cmd.type = MT7697_CMD_SET_OP_MODE_RSP;

    LOG_I(common, "--> SET OP MODE(%d)", cmd->len);

    opmode = set_op_mode_req->opmode;

    ret = wifi_config_get_opmode(&curr_opmode);
    if (ret < 0) {
        LOG_W(common, "wifi_config_get_opmode() failed(%d)", ret);
        goto cleanup;
    }

    LOG_I(common, "current/set opmode(%u/%u)", curr_opmode, opmode);
    if (curr_opmode != opmode) {
        ret = wifi_config_set_opmode(opmode);
        if (ret < 0) {
            LOG_W(common, "wifi_config_set_opmode() failed(%d)", ret);
            goto cleanup;
        }
    }
    else {
        ret = 0;
        goto cleanup;
    }

    wifi_info.netif = netif_find_by_type((opmode == WIFI_MODE_STA_ONLY) ? NETIF_TYPE_STA :
                                         NETIF_TYPE_AP);
    if (!wifi_info.netif) {
        LOG_E(common, "netif_find_by_type() failed(%d)", ret);
        goto cleanup;
    }

    netif_set_default(wifi_info.netif);

cleanup:
    if (rsp) {
        rsp->result = ret;
        LOG_I(common, "<-- SET OP MODE rsp len(%u) result(%d)", rsp->cmd.len, ret);
        int32_t err = swi_s2m_send_req(wifi_info.s2m_info, (mt7697_rsp_hdr_t*)rsp);
        if (err < 0) {
            LOG_W(common, "swi_s2m_send_req() failed(%d)", err);
            ret = ret ? ret:err;
        }
    }

    return ret;
}

static int32_t swi_wifi_proc_get_listen_interval_req(swi_m2s_info_t* m2s_info,
                                                     mt7697_cmd_hdr_t* cmd)
{
    int32_t ret = 0;
    uint8_t listen_interval;

    mt7697_get_listen_interval_rsp_t* rsp = (mt7697_get_listen_interval_rsp_t*)swi_mem_pool_alloc_msg(
        &wifi_info.s2m_info->msg_pool_info, SWI_MEM_POOL_MSG_HI_PRIORITY, wifi_info.s2m_info->sendQ,
        LEN32_ALIGNED(sizeof(mt7697_get_listen_interval_rsp_t)));
    if (!rsp) {
        LOG_W(common, "swi_mem_pool_alloc_msg() failed");
        ret = -1;
        goto cleanup;
    }

    rsp->rsp.cmd.len = sizeof(mt7697_get_listen_interval_rsp_t);
    rsp->rsp.cmd.grp = MT7697_CMD_GRP_80211;
    rsp->rsp.cmd.type = MT7697_CMD_GET_LISTEN_INTERVAL_RSP;

    LOG_I(common, "--> GET LISTEN INTERVAL(%d)", cmd->len);

    ret = wifi_config_get_listen_interval(&listen_interval);
    if (ret < 0) {
        LOG_W(common, "wifi_config_get_listen_interval() failed(%d)", ret);
        goto cleanup;
    }

    rsp->interval = listen_interval;
    LOG_I(common, "listen interval(%u)", rsp->interval);

cleanup:
    if (rsp) {
        rsp->rsp.result = ret;
        LOG_I(common, "<-- GET LISTEN INTERVAL rsp len(%u) result(%d)", rsp->rsp.cmd.len, ret);
        int32_t err = swi_s2m_send_req(wifi_info.s2m_info, (mt7697_rsp_hdr_t*)rsp);
        if (err < 0) {
            LOG_W(common, "swi_s2m_send_req() failed(%d)", err);
            ret = ret ? ret:err;
        }
    }

    return ret;
}

static int32_t swi_wifi_proc_set_listen_interval_req(swi_m2s_info_t* m2s_info,
                                                     mt7697_cmd_hdr_t* cmd)
{
	mt7697_set_listen_interval_req_t* set_listen_interval_req =
		(mt7697_set_listen_interval_req_t*)cmd;
    uint32_t interval = 0;
    int32_t ret = 0;

    mt7697_set_listen_interval_rsp_t* rsp =
        (mt7697_set_listen_interval_rsp_t*)swi_mem_pool_alloc_msg(
            &wifi_info.s2m_info->msg_pool_info, SWI_MEM_POOL_MSG_HI_PRIORITY,
            wifi_info.s2m_info->sendQ, LEN32_ALIGNED(sizeof(mt7697_set_listen_interval_rsp_t)));
    if (!rsp) {
        LOG_W(common, "swi_mem_pool_alloc_msg() failed");
        ret = -1;
        goto cleanup;
    }

    rsp->cmd.len = sizeof(mt7697_set_listen_interval_rsp_t);
    rsp->cmd.grp = MT7697_CMD_GRP_80211;
    rsp->cmd.type = MT7697_CMD_SET_LISTEN_INTERVAL_RSP;

    LOG_I(common, "--> SET RX FILTER(%d)", cmd->len);

    interval = set_listen_interval_req->interval;

    LOG_I(common, "set rx filter(0x%u08x)", interval);
    ret = wifi_config_set_listen_interval(interval);
    if (ret < 0) {
        LOG_W(common, "wifi_config_set_listen_interval() failed(%d)", ret);
        goto cleanup;
    }

cleanup:
    if (rsp) {
        rsp->result = ret;
        LOG_I(common, "<-- SET RX FILTER rsp len(%u) result(%d)", rsp->cmd.len, ret);
        int32_t err = swi_s2m_send_req(wifi_info.s2m_info, (mt7697_rsp_hdr_t*)rsp);
        if (err < 0) {
            LOG_W(common, "swi_s2m_send_req() failed(%d)", err);
            ret = ret ? ret:err;
        }
    }

    return ret;
}

static int32_t swi_wifi_proc_get_security_mode_req(swi_m2s_info_t* m2s_info,
                                                   mt7697_cmd_hdr_t* cmd)
{
	mt7697_get_security_mode_req_t* get_security_mode_req = (mt7697_get_security_mode_req_t*)cmd;
    wifi_auth_mode_t auth_mode;
    wifi_encrypt_type_t encrypt_type;
    uint32_t port;
    int32_t ret = 0;

    mt7697_get_security_mode_rsp_t* rsp = (mt7697_get_security_mode_rsp_t*)swi_mem_pool_alloc_msg(
        &wifi_info.s2m_info->msg_pool_info, SWI_MEM_POOL_MSG_HI_PRIORITY, wifi_info.s2m_info->sendQ,
        LEN32_ALIGNED(sizeof(mt7697_get_security_mode_rsp_t)));
    if (!rsp) {
        LOG_W(common, "swi_mem_pool_alloc_msg() failed");
        ret = -1;
        goto cleanup;
    }

    rsp->rsp.cmd.len = sizeof(mt7697_get_security_mode_rsp_t);
    rsp->rsp.cmd.grp = MT7697_CMD_GRP_80211;
    rsp->rsp.cmd.type = MT7697_CMD_GET_SECURITY_MODE_RSP;

    LOG_I(common, "--> GET SECURITY MODE(%d)", cmd->len);

    port = get_security_mode_req->port;
    /*
     * TODO: It seems that get_security_mode_req->if_idx is never used. Is this is bug or a protocol
     * design flaw?
     */

    if (!swi_wifi_validate_port(port)) {
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

    rsp->auth_mode = auth_mode;
    rsp->encrypt_type = encrypt_type;
    LOG_I(common, "auth mode(%u) encrypt type(%u)", rsp->auth_mode, rsp->encrypt_type);

cleanup:
    if (rsp) {
        rsp->rsp.result = ret;
        LOG_I(common, "<-- GET SECURITY MODE rsp len(%u) result(%d)", rsp->rsp.cmd.len, ret);
        int32_t err = swi_s2m_send_req(wifi_info.s2m_info, (mt7697_rsp_hdr_t*)rsp);
        if (err < 0) {
            LOG_W(common, "swi_s2m_send_req() failed(%d)", err);
            ret = ret ? ret:err;
        }
    }

    return ret;
}

static int32_t swi_wifi_proc_set_security_mode_req(swi_m2s_info_t* m2s_info,
                                                   mt7697_cmd_hdr_t* cmd)
{
	mt7697_set_security_mode_req_t* set_security_mode_req = (mt7697_set_security_mode_req_t*)cmd;
    uint32_t port;
    wifi_auth_mode_t curr_auth_mode;
    wifi_auth_mode_t auth_mode;
    wifi_encrypt_type_t curr_encrypt_type;
    wifi_encrypt_type_t encrypt_type;
    int32_t ret = 0;

    mt7697_set_security_mode_rsp_t* rsp = (mt7697_set_security_mode_rsp_t*)swi_mem_pool_alloc_msg(
        &wifi_info.s2m_info->msg_pool_info, SWI_MEM_POOL_MSG_HI_PRIORITY, wifi_info.s2m_info->sendQ,
        LEN32_ALIGNED(sizeof(mt7697_set_security_mode_rsp_t)));
    if (!rsp) {
        LOG_W(common, "swi_mem_pool_alloc_msg() failed");
        ret = -1;
        goto cleanup;
    }

    rsp->cmd.len = sizeof(mt7697_set_security_mode_rsp_t);
    rsp->cmd.grp = MT7697_CMD_GRP_80211;
    rsp->cmd.type = MT7697_CMD_SET_SECURITY_MODE_RSP;

    LOG_I(common, "--> SET SECURITY MODE(%d)", cmd->len);

    port = set_security_mode_req->port;
    if (!swi_wifi_validate_port(port)) {
        LOG_W(common, "invalid port(%d)", port);
        ret = -1;
        goto cleanup;
    }

    auth_mode = set_security_mode_req->auth_mode;
    encrypt_type = set_security_mode_req->encrypt_type;

    ret = wifi_config_get_security_mode(port, &curr_auth_mode, &curr_encrypt_type);
    if (ret < 0) {
        LOG_W(common, "wifi_config_get_security_mode() failed(%d)", ret);
        goto cleanup;
    }

    LOG_I(common, "auth mode curr/set(%d/%d), encrypt type curr/set(%d/%d)",
          curr_auth_mode, auth_mode, curr_encrypt_type, encrypt_type);

    if ((curr_auth_mode != auth_mode) || (curr_encrypt_type != encrypt_type)) {
        ret = wifi_config_set_security_mode(port, auth_mode, encrypt_type);
        if (ret < 0) {
            LOG_W(common, "wifi_config_set_security_mode() failed(%d)", ret);
            goto cleanup;
        }

        wifi_info.reload = true;
    }

cleanup:
    if (rsp) {
        rsp->result = ret;
        LOG_I(common, "<-- SET SECURITY MODE rsp len(%u) result(%d)", rsp->cmd.len, ret);
        int32_t err = swi_s2m_send_req(wifi_info.s2m_info, (mt7697_rsp_hdr_t*)rsp);
        if (err < 0) {
            LOG_W(common, "swi_s2m_send_req() failed(%d)", err);
            ret = ret ? ret:err;
        }
    }

    return ret;
}

static int32_t swi_wifi_proc_scan_req(swi_m2s_info_t* m2s_info, mt7697_cmd_hdr_t* cmd)
{
	mt7697_scan_req_t* scan_req = (mt7697_scan_req_t*)cmd;
    int32_t ret = 0;

    mt7697_scan_rsp_t* rsp = (mt7697_scan_rsp_t*)swi_mem_pool_alloc_msg(
        &wifi_info.s2m_info->msg_pool_info, SWI_MEM_POOL_MSG_HI_PRIORITY, wifi_info.s2m_info->sendQ,
        LEN32_ALIGNED(sizeof(mt7697_scan_rsp_t)));
    if (!rsp) {
        LOG_W(common, "swi_mem_pool_alloc_msg() failed");
        ret = -1;
        goto cleanup;
    }

    rsp->rsp.cmd.len = sizeof(mt7697_scan_rsp_t);
    rsp->rsp.cmd.grp = MT7697_CMD_GRP_80211;
    rsp->rsp.cmd.type = MT7697_CMD_SCAN_RSP;

    LOG_I(common, "--> SCAN(%d)", cmd->len);

    LOG_I(common, "if idx(%d)", scan_req->if_idx);
    wifi_info.if_idx = scan_req->if_idx;
    rsp->if_idx = wifi_info.if_idx;

    LOG_I(common, "SSID (%u/'%s')", scan_req->ssid_len, scan_req->ssid);
    LOG_HEXDUMP_I(common, "BSSID", scan_req->bssid, WIFI_MAC_ADDRESS_LENGTH);
    ret = wifi_connection_start_scan(scan_req->ssid, scan_req->ssid_len,
                                     scan_req->bssid_len ? scan_req->bssid : NULL, scan_req->mode,
                                     scan_req->option);
    if (ret < 0) {
        LOG_E(common, "wifi_connection_start_scan() failed(%d)", ret);
        goto cleanup;
    }

cleanup:
    if (rsp) {
        rsp->rsp.result = ret;
        LOG_W(common, "<-- SCAN RSP len(%u) result(%d)", rsp->rsp.cmd.len, ret);
        int32_t err = swi_s2m_send_req(wifi_info.s2m_info, (mt7697_rsp_hdr_t*)rsp);
        if (err < 0) {
            LOG_W(common, "swi_s2m_send_req() failed(%d)", err);
            ret = ret ? ret:err;
        }
    }

    return ret;
}

static int32_t swi_wifi_proc_scan_stop_req(swi_m2s_info_t* m2s_info, mt7697_cmd_hdr_t* cmd)
{
    int32_t ret = 0;

    mt7697_scan_stop_rsp_t* rsp = (mt7697_scan_stop_rsp_t*)swi_mem_pool_alloc_msg(
        &wifi_info.s2m_info->msg_pool_info, SWI_MEM_POOL_MSG_HI_PRIORITY, wifi_info.s2m_info->sendQ,
        LEN32_ALIGNED(sizeof(mt7697_scan_stop_rsp_t)));
    if (!rsp) {
        LOG_W(common, "swi_mem_pool_alloc_msg() failed");
        ret = -1;
        goto cleanup;
    }

    rsp->cmd.len = sizeof(mt7697_scan_stop_rsp_t);
    rsp->cmd.grp = MT7697_CMD_GRP_80211;
    rsp->cmd.type = MT7697_CMD_SCAN_STOP_RSP;

    LOG_I(common, "--> SCAN STOP(%d)", cmd->len);

    LOG_I(common, "stop scan");
    ret = wifi_connection_stop_scan();
    if (ret < 0) {
        LOG_W(common, "wifi_connection_stop_scan() failed(%d)", ret);
        goto cleanup;
    }

cleanup:
    if (rsp) {
        rsp->result = ret;
        LOG_I(common, "<-- SCAN STOP result(%d)", ret);
        int32_t err = swi_s2m_send_req(wifi_info.s2m_info, (mt7697_rsp_hdr_t*)rsp);
        if (err < 0) {
            LOG_W(common, "swi_s2m_send_req() failed(%d)", err);
            ret = ret ? ret:err;
        }
    }

    return ret;
}

static int32_t swi_wifi_proc_disconnect_req(swi_m2s_info_t* m2s_info, mt7697_cmd_hdr_t* cmd)
{
	mt7697_disconnect_req_t* disconnect_req = (mt7697_disconnect_req_t*)cmd;
    uint32_t port;
    int32_t ret = 0;

    mt7697_disconnect_rsp_t* rsp = (mt7697_disconnect_rsp_t*)swi_mem_pool_alloc_msg(
        &wifi_info.s2m_info->msg_pool_info, SWI_MEM_POOL_MSG_HI_PRIORITY, wifi_info.s2m_info->sendQ,
        LEN32_ALIGNED(sizeof(mt7697_disconnect_rsp_t)));
    if (!rsp) {
        LOG_W(common, "swi_mem_pool_alloc_msg() failed");
        ret = -1;
        goto cleanup;
    }

    rsp->cmd.len = sizeof(mt7697_disconnect_rsp_t);
    rsp->cmd.grp = MT7697_CMD_GRP_80211;
    rsp->cmd.type = MT7697_CMD_DISCONNECT_RSP;

    LOG_I(common, "--> DISCONNECT(%d)", cmd->len);

    port = disconnect_req->port;

    LOG_I(common, "port(%u)", port);
    if (!swi_wifi_validate_port(port)) {
        LOG_W(common, "invalid port(%d)", port);
        ret = -1;
        goto cleanup;
    }

    if (port == WIFI_PORT_AP) {
        LOG_HEXDUMP_I(common, "BSSID", disconnect_req->addr, WIFI_MAC_ADDRESS_LENGTH);
        ret = wifi_connection_disconnect_sta(disconnect_req->addr);
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

    wifi_info.reload = false;

cleanup:
    if (rsp) {
        rsp->result = ret;
        LOG_I(common, "<-- DISCONNECT RSP result(%d)", ret);
        int32_t err = swi_s2m_send_req(wifi_info.s2m_info, (mt7697_rsp_hdr_t*)rsp);
        if (err < 0) {
            LOG_W(common, "swi_s2m_send_req() failed(%d)", err);
            ret = ret ? ret:err;
        }
    }

    return ret;
}

static int32_t swi_wifi_proc_tx_raw_req(swi_m2s_info_t* m2s_info, mt7697_cmd_hdr_t* cmd)
{
	mt7697_tx_raw_packet_t* tx_raw_packet = (mt7697_tx_raw_packet_t*)cmd;
    uint32_t tx_len;
    int32_t ret = 0;

//    LOG_I(common, "--> TX(%d)", len);
    tx_len = tx_raw_packet->len;

//    LOG_HEXDUMP_I(common, "Tx packet", wifi_info.tx_data, tx_len);
    ret = ethernet_raw_pkt_sender(tx_raw_packet->data, tx_len, wifi_info.netif);
    if (ret < 0) {
        LOG_W(common, "ethernet_raw_pkt_sender() failed(%d)", ret);
        goto cleanup;
    }

    ret = 0;

cleanup:
    return ret;
}

static bool swi_wifi_validate_tx_raw_paket_size(const mt7697_cmd_hdr_t *cmd)
{
	const mt7697_tx_raw_packet_t* tx_raw_packet = (const mt7697_tx_raw_packet_t*)cmd;
	return tx_raw_packet->len == (tx_raw_packet->cmd.len - offsetof(mt7697_tx_raw_packet_t, data));
}


int32_t swi_wifi_init(swi_s2m_info_t* s2m_info)
{

    int32_t ret = 0;

    LOG_I(common, "wifi init");

    ret = wifi_connection_register_event_handler(WIFI_EVENT_IOT_INIT_COMPLETE,
                                                 swi_wifi_init_done_handler);
    if (ret < 0) {
        LOG_E(common, "wifi_connection_register_event_handler() failed(%d)", ret);
        goto cleanup;
    }

    ret = wifi_connection_register_event_handler(WIFI_EVENT_IOT_REPORT_BEACON_PROBE_RESPONSE,
                                                 swi_wifi_event_hndlr);
    if (ret < 0) {
        LOG_E(common, "wifi_connection_register_event_handler() failed(%d)", ret);
        goto cleanup;
    }

    ret = wifi_connection_register_event_handler(WIFI_EVENT_IOT_SCAN_COMPLETE,
                                                 swi_wifi_event_hndlr);
    if (ret < 0) {
        LOG_E(common, "wifi_connection_register_event_handler() failed(%d)", ret);
        goto cleanup;
    }

    ret = wifi_connection_register_event_handler(WIFI_EVENT_IOT_CONNECTED, swi_wifi_event_hndlr);
    if (ret < 0) {
        LOG_E(common, "wifi_connection_register_event_handler() failed(%d)", ret);
        goto cleanup;
    }

    ret = wifi_connection_register_event_handler(WIFI_EVENT_IOT_CONNECTION_FAILED,
                                                 swi_wifi_event_hndlr);
    if (ret < 0) {
        LOG_E(common, "wifi_connection_register_event_handler() failed(%d)", ret);
        goto cleanup;
    }

    ret = wifi_connection_register_event_handler(WIFI_EVENT_IOT_PORT_SECURE, swi_wifi_event_hndlr);
    if (ret < 0) {
        LOG_E(common, "wifi_connection_register_event_handler() failed(%d)", ret);
        goto cleanup;
    }

    ret = wifi_connection_register_event_handler(WIFI_EVENT_IOT_WPS_COMPLETE, swi_wifi_event_hndlr);
    if (ret < 0) {
        LOG_E(common, "wifi_connection_register_event_handler() failed(%d)", ret);
        goto cleanup;
    }

    ret = wifi_connection_register_event_handler(WIFI_EVENT_IOT_DISCONNECTED, swi_wifi_event_hndlr);
    if (ret < 0) {
        LOG_E(common, "wifi_connection_register_event_handler() failed(%d)", ret);
        goto cleanup;
    }

    ret = wifi_config_register_net_rx_handler(swi_wifi_net_rx_hndlr);
    if (ret < 0) {
        LOG_W(common, "wifi_config_register_net_rx_handler() failed(%d)", ret);
        goto cleanup;
    }

    wifi_info.s2m_info = s2m_info;
    wifi_info.reload = false;

cleanup:
    return ret;
}
