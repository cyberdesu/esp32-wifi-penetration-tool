#include "wifi_controller.h"

#include <stdio.h>
#include <string.h>

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_netif.h"
#include "esp_event.h"

static const char* TAG = "wifi_controller";
/**
 * @brief Stores current state of Wi-Fi interface
 */
static bool wifi_init = false;
static uint8_t original_mac_ap[6];

static void wifi_event_handler(void *event_handler_arg, esp_event_base_t event_base, int32_t event_id, void *event_data){

}

/**
 * @brief Initializes Wi-Fi interface into APSTA mode and starts it.
 * 
 * @attention This function should be called only once.
 */
static void wifi_init_apsta(){
    ESP_ERROR_CHECK(esp_netif_init());

    esp_netif_create_default_wifi_ap();
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t wifi_init_config = WIFI_INIT_CONFIG_DEFAULT();

    ESP_ERROR_CHECK(esp_wifi_init(&wifi_init_config));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));

    // save original AP MAC address
    ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_AP, original_mac_ap));

    ESP_ERROR_CHECK(esp_wifi_start());
    wifi_init = true;
}

void wifictl_ap_start(wifi_config_t *wifi_config) {
    ESP_LOGD(TAG, "Starting AP...");
    if(!wifi_init){
        wifi_init_apsta();
    }

    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_AP, wifi_config));
    ESP_LOGI(TAG, "AP started with SSID=%s", wifi_config->ap.ssid);
}

void wifictl_station_start(){
    // Konfigurasi inisialisasi WiFi
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();

    ESP_LOGD(TAG, "Starting STATION...");
    
    // Inisialisasi WiFi
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    
    // Set mode WiFi ke mode station
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    
    // Mulai WiFi
    ESP_ERROR_CHECK(esp_wifi_start());
}

void print_connected_clients(const uint8_t *ap_mac) {
    wifi_sta_list_t wifi_sta_list;
    int total_clients = 0;



    // Dapatkan alamat MAC AP
    uint8_t ap_iface_mac[6];
    ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_AP, ap_iface_mac));

    // Periksa apakah alamat MAC AP cocok dengan yang diberikan oleh pengguna
    /*if (memcmp(ap_mac, ap_iface_mac, 6) != 0) {
        printf("Error: MAC address of the specified AP does not match the active AP.\n");
        return;
    }*/

    // Dapatkan daftar klien yang terhubung
    ESP_ERROR_CHECK(esp_wifi_ap_get_sta_list(&wifi_sta_list));
    
    printf("Connected clients:\n");
    for(int i = 0; i < wifi_sta_list.num; i++) {
        total_clients++;
        printf("- MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
                wifi_sta_list.sta[i].mac[0], wifi_sta_list.sta[i].mac[1],
                wifi_sta_list.sta[i].mac[2], wifi_sta_list.sta[i].mac[3],
                wifi_sta_list.sta[i].mac[4], wifi_sta_list.sta[i].mac[5]);
    }

    // Cetak total klien yang terhubung
    printf("Total connected clients: %d\n", total_clients);
}


void wifictl_ap_stop(){
    ESP_LOGD(TAG, "Stopping AP...");
    wifi_config_t wifi_config = {
        .ap = {
            .max_connection = 0
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_AP, &wifi_config));
    ESP_LOGD(TAG, "AP stopped");
}

void wifictl_mgmt_ap_start(){
    wifi_config_t mgmt_wifi_config = {
        .ap = {
            .ssid = CONFIG_MGMT_AP_SSID,
            .ssid_len = strlen(CONFIG_MGMT_AP_SSID),
            .password = CONFIG_MGMT_AP_PASSWORD,
            .max_connection = CONFIG_MGMT_AP_MAX_CONNECTIONS,
            .authmode = WIFI_AUTH_WPA2_PSK
        },
    };
    wifictl_ap_start(&mgmt_wifi_config);
}

void wifictl_sta_connect_to_ap(const wifi_ap_record_t *ap_record, const char password[]){
    ESP_LOGD(TAG, "Connecting STA to AP...");
    if(!wifi_init){
        wifi_init_apsta();
    }

    wifi_config_t sta_wifi_config = {
        .sta = {
            .channel = ap_record->primary,
            .scan_method = WIFI_FAST_SCAN,
            .pmf_cfg.capable = false,
            .pmf_cfg.required = false
        },
    };
    mempcpy(sta_wifi_config.sta.ssid, ap_record->ssid, 32);

    if(password != NULL){
        if(strlen(password) >= 64) {
            ESP_LOGE(TAG, "Password is too long. Max supported length is 64");
            return;
        }
        memcpy(sta_wifi_config.sta.password, password, strlen(password) + 1);
    }

    ESP_LOGD(TAG, ".ssid=%s", sta_wifi_config.sta.ssid);

    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &sta_wifi_config));
    ESP_ERROR_CHECK(esp_wifi_connect());

}

void wifictl_sta_disconnect(){
    ESP_ERROR_CHECK(esp_wifi_disconnect());
}

void wifictl_set_ap_mac(const uint8_t *mac_ap){
    ESP_LOGD(TAG, "Changing AP MAC address...");
    ESP_ERROR_CHECK(esp_wifi_set_mac(WIFI_IF_AP, mac_ap));
}

void wifictl_get_ap_mac(uint8_t *mac_ap){
    esp_wifi_get_mac(WIFI_IF_AP, mac_ap);
}

void wifictl_restore_ap_mac(){
    ESP_LOGD(TAG, "Restoring original AP MAC address...");
    ESP_ERROR_CHECK(esp_wifi_set_mac(WIFI_IF_AP, original_mac_ap));
}

void wifictl_get_sta_mac(uint8_t *mac_sta){
    esp_wifi_get_mac(WIFI_IF_STA, mac_sta);
}

void wifictl_set_channel(uint8_t channel){
    if((channel == 0) || (channel >  13)){
        ESP_LOGE(TAG,"Channel out of range. Expected value from <1,13> but got %u", channel);
        return;
    }
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}