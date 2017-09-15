/* Copyright Statement:
 *
 * (C) 2005-2016  MediaTek Inc. All rights reserved.
 *
 * This software/firmware and related documentation ("MediaTek Software") are
 * protected under relevant copyright laws. The information contained herein
 * is confidential and proprietary to MediaTek Inc. ("MediaTek") and/or its licensors.
 * Without the prior written permission of MediaTek and/or its licensors,
 * any reproduction, modification, use or disclosure of MediaTek Software,
 * and information contained herein, in whole or in part, shall be strictly prohibited.
 * You may only use, reproduce, modify, or distribute (as applicable) MediaTek Software
 * if you have agreed to and been bound by the applicable license agreement with
 * MediaTek ("License Agreement") and been granted explicit permission to do so within
 * the License Agreement ("Permitted User").  If you are not a Permitted User,
 * please cease any access or use of MediaTek Software immediately.
 * BY OPENING THIS FILE, RECEIVER HEREBY UNEQUIVOCALLY ACKNOWLEDGES AND AGREES
 * THAT MEDIATEK SOFTWARE RECEIVED FROM MEDIATEK AND/OR ITS REPRESENTATIVES
 * ARE PROVIDED TO RECEIVER ON AN "AS-IS" BASIS ONLY. MEDIATEK EXPRESSLY DISCLAIMS ANY AND ALL
 * WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE OR NONINFRINGEMENT.
 * NEITHER DOES MEDIATEK PROVIDE ANY WARRANTY WHATSOEVER WITH RESPECT TO THE
 * SOFTWARE OF ANY THIRD PARTY WHICH MAY BE USED BY, INCORPORATED IN, OR
 * SUPPLIED WITH MEDIATEK SOFTWARE, AND RECEIVER AGREES TO LOOK ONLY TO SUCH
 * THIRD PARTY FOR ANY WARRANTY CLAIM RELATING THERETO. RECEIVER EXPRESSLY ACKNOWLEDGES
 * THAT IT IS RECEIVER'S SOLE RESPONSIBILITY TO OBTAIN FROM ANY THIRD PARTY ALL PROPER LICENSES
 * CONTAINED IN MEDIATEK SOFTWARE. MEDIATEK SHALL ALSO NOT BE RESPONSIBLE FOR ANY MEDIATEK
 * SOFTWARE RELEASES MADE TO RECEIVER'S SPECIFICATION OR TO CONFORM TO A PARTICULAR
 * STANDARD OR OPEN FORUM. RECEIVER'S SOLE AND EXCLUSIVE REMEDY AND MEDIATEK'S ENTIRE AND
 * CUMULATIVE LIABILITY WITH RESPECT TO MEDIATEK SOFTWARE RELEASED HEREUNDER WILL BE,
 * AT MEDIATEK'S OPTION, TO REVISE OR REPLACE MEDIATEK SOFTWARE AT ISSUE,
 * OR REFUND ANY SOFTWARE LICENSE FEES OR SERVICE CHARGE PAID BY RECEIVER TO
 * MEDIATEK FOR SUCH MEDIATEK SOFTWARE AT ISSUE.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "FreeRTOS.h"
#include "task.h"
#include <lwip/tcpip.h>
#include <ethernetif.h>
#include <lwip/sockets.h>

#include "sys_init.h"
#include "wifi_nvdm_config.h"
#include "wifi_lwip_helper.h"
#include "task_def.h"
#include "bt_init.h"

#if defined(MTK_BT_LWIP_ENABLE)
#include "bt_lwip.h"
#endif

#if defined(MTK_MINICLI_ENABLE)
#include "cli_def.h"
#endif

#ifdef MTK_HOMEKIT_ENABLE
#include "homekit_init.h"
#endif

#include "bsp_gpio_ept_config.h"
#include "hal_sleep_manager.h"

#if configUSE_TICKLESS_IDLE == 2
extern void tickless_init(void);
#endif
#include "connsys_profile.h"
#include "wifi_api.h"

#ifdef MTK_WIFI_CONFIGURE_FREE_ENABLE
#include "wifi_profile.h"
#include "smt_conn.h"
#endif

#include "spi_slave_queues.h"
#include "spi_slave_wifi.h"

#ifdef BLE_THROUGHPUT
extern void ble_gatt_send_data();
QueueHandle_t ble_tp_queue = NULL;
void ble_tp_task(void *param)
{
    LOG_W(common, "enter ble_tp_task");
    while (1) {
        ble_gatt_send_data();
    }
}
#endif

//#define MTK_MCS_ENABLE 
#ifdef MTK_MCS_ENABLE
#include "mcs.h"
#endif

/**
  * @brief  Main program
  * @param  None
  * @retval None
  */
int main(void)
{
    int ret;

    /* Do system initialization, eg: hardware, nvdm, logging and random seed. */
    system_init();

    /* bsp_ept_gpio_setting_init() under driver/board/mt76x7_hdk/ept will initialize the GPIO settings
     * generated by easy pinmux tool (ept). ept_*.c and ept*.h are the ept files and will be used by
     * bsp_ept_gpio_setting_init() for GPIO pinumux setup.
     */
    bsp_ept_gpio_setting_init();

#if configUSE_TICKLESS_IDLE == 2
    if (hal_sleep_manager_init() == HAL_SLEEP_MANAGER_OK) {
        tickless_init();
    }
#endif

    /* User initial the parameters for wifi initial process,  system will determin which wifi operation mode
     * will be started , and adopt which settings for the specific mode while wifi initial process is running*/
    wifi_cfg_t wifi_config = {0};
    if (0 != wifi_config_init(&wifi_config)) {
        LOG_E(common, "wifi config init fail");
        return -1;
    }

    wifi_config_t config = {0};
    wifi_config_ext_t config_ext = {0};

    LOG_I(common, "OP MODE('%s')", (wifi_config.opmode == WIFI_MODE_STA_ONLY) ? "STA":"AP");
    config.opmode = wifi_config.opmode;

    memcpy(config.sta_config.ssid, wifi_config.sta_ssid, 32);
    config.sta_config.ssid_length = wifi_config.sta_ssid_len;
    config.sta_config.bssid_present = 0;
    memcpy(config.sta_config.password, wifi_config.sta_wpa_psk, 64);
    config.sta_config.password_length = wifi_config.sta_wpa_psk_len;
    config_ext.sta_wep_key_index_present = 1;
    config_ext.sta_wep_key_index = wifi_config.sta_default_key_id;
    config_ext.sta_auto_connect_present = 1;
    config_ext.sta_auto_connect = 1;

    memcpy(config.ap_config.ssid, wifi_config.ap_ssid, 32);
    config.ap_config.ssid_length = wifi_config.ap_ssid_len;
    memcpy(config.ap_config.password, wifi_config.ap_wpa_psk, 64);
    config.ap_config.password_length = wifi_config.ap_wpa_psk_len;
    config.ap_config.auth_mode = (wifi_auth_mode_t)wifi_config.ap_auth_mode;
    config.ap_config.encrypt_type = (wifi_encrypt_type_t)wifi_config.ap_encryp_type;
    config.ap_config.channel = wifi_config.ap_channel;
    config.ap_config.bandwidth = wifi_config.ap_bw;
    config.ap_config.bandwidth_ext = WIFI_BANDWIDTH_EXT_40MHZ_UP;
    config_ext.ap_wep_key_index_present = 1;
    config_ext.ap_wep_key_index = wifi_config.ap_default_key_id;
    config_ext.ap_hidden_ssid_enable_present = 1;
    config_ext.ap_hidden_ssid_enable = wifi_config.ap_hide_ssid;

    /* Initialize wifi stack and register wifi init complete event handler,
     * notes:  the wifi initial process will be implemented and finished while system task scheduler is running,
     *            when it is done , the WIFI_EVENT_IOT_INIT_COMPLETE event will be triggered */
    wifi_init(&config, &config_ext);

    ret = wifi_connection_register_event_handler(WIFI_EVENT_IOT_INIT_COMPLETE, wifi_init_done_handler);
    if (ret < 0) {
	LOG_E(common, "wifi_connection_register_event_handler() failed(%d)", ret);
	goto cleanup;
    }

    /* Tcpip stack and net interface initialization,  dhcp client, dhcp server process initialization*/
    lwip_tcpip_config_t tcpip_config = {{0}, {0}, {0}, {0}, {0}, {0}};
    lwip_tcpip_init(&tcpip_config, config.opmode);

    ret = spi_queue_init();
    if (ret < 0) {
	LOG_E(common, "spi_queue_init() failed(%d)", ret);
	goto cleanup;
    }

    ret = wifi_init_evt_hndlrs();
    if (ret < 0) {
	LOG_E(common, "wifi_init_evt_hndlrs() failed(%d)", ret);
	goto cleanup;
    }

#ifdef MTK_WIFI_CONFIGURE_FREE_ENABLE
        uint8_t configured = 0;
        register_configure_free_callback(save_cf_credential_to_nvdm,  save_cf_ready_to_nvdm);
        get_cf_ready_to_nvdm(&configured);
        if (!configured) { // not configured
#ifdef MTK_SMTCN_ENABLE
            /* Config-Free Demo */
            if (wifi_config.opmode == 1) {
                mtk_smart_connect();
            }
#endif
        }
#endif /* MTK_WIFI_CONFIGURE_FREE_ENABLE */

#if defined(MTK_MINICLI_ENABLE)
    /* Initialize cli task to enable user input cli command from uart port.*/
    cli_def_create();
    cli_task_create();
#endif

#ifdef MTK_HOMEKIT_ENABLE
    homekit_init();
#endif

#if defined(MTK_BT_LWIP_ENABLE)
//    bt_lwip_init();
#endif

//    bt_create_task();

#ifdef BLE_THROUGHPUT
//    ble_tp_queue = xQueueCreate(100, 8);
//    xTaskCreate(ble_tp_task, BLE_TP_TASK_NAME, BLE_TP_TASK_STACKSIZE/sizeof(StackType_t), NULL, BLE_TP_TASK_PRIORITY, NULL);
#endif

    //add for MTK cloud support
#ifdef MTK_MCS_ENABLE
    mcs_init();
#ifdef MTK_BLE_GPIO_SERVICE
    mcs_status_updata_init();
#endif

#endif

    vTaskStartScheduler();

cleanup:
    /* If all is well, the scheduler will now be running, and the following line
    will never be reached.  If the following line does execute, then there was
    insufficient FreeRTOS heap memory available for the idle and/or timer tasks
    to be created.  See the memory management section on the FreeRTOS web site
    for more details. */
    for ( ;; );
}

