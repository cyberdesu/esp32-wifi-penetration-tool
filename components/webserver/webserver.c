/**
 * @file webserver.c
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-05
 * @copyright Copyright (c) 2021
 *
 * @brief Implements Webserver component and all available enpoints.
 *
 * Webserver is built on esp_http_server subcomponent from ESP-IDF
 * @see https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/protocols/esp_http_server.html
 */
#include "webserver.h"

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_wifi_types.h"

#include "wifi_controller.h"
#include "attack.h"
#include "pcap_serializer.h"
#include "hccapx_serializer.h"
#include "cJSON.h"
#include "pages/page_index.h"
#include <esp_http_server.h>
#include "esp_http_client.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lora.h"


static const char* TAG = "webserver";
ESP_EVENT_DEFINE_BASE(WEBSERVER_EVENTS);

/**
 * @brief Handlers for index/root \c / path endpoint
 *
 * This endpoint provides index page source
 * @param req
 * @return esp_err_t
 * @{
 */
static esp_err_t uri_root_get_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "text/html");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    return httpd_resp_send(req, (const char *)page_index, page_index_len);
}

static httpd_uri_t uri_root_get = {
    .uri = "/",
    .method = HTTP_GET,
    .handler = uri_root_get_handler,
    .user_ctx = NULL
};
//@}

/**
 * @brief Handlers for \c /reset endpoint
 *
 * This endpoint resets the attack logic to initial READY state.
 * @param req
 * @return esp_err_t
 * @{
 */
static esp_err_t uri_reset_head_handler(httpd_req_t *req) {
    ESP_ERROR_CHECK(esp_event_post(WEBSERVER_EVENTS, WEBSERVER_EVENT_ATTACK_RESET, NULL, 0, portMAX_DELAY));
    return httpd_resp_send(req, NULL, 0);
}

static httpd_uri_t uri_reset_head = {
    .uri = "/reset",
    .method = HTTP_HEAD,
    .handler = uri_reset_head_handler,
    .user_ctx = NULL
};
//@}

/**
 * @brief Handlers for \c /ap-list endpoint
 *
 * This endpoint returns list of available APs nearby.
 * It calls wifi_controller ap_scanner and serialize their SSIDs into octet response.
 * @attention reponse may take few seconds
 * @attention client may be disconnected from ESP AP after calling this endpoint
 * @param req
 * @return esp_err_t
 * @{
 */
// ... (your existing code)

/**
 * @brief Handlers for \c /ap-list endpoint
 *
 * This endpoint returns list of available APs nearby in JSON format.
 * @attention reponse may take few seconds
 * @attention client may be disconnected from ESP AP after calling this endpoint
 * @param req
 * @return esp_err_t
 * @{
 */
static const char* get_auth_mode_string(int authmode) {
    switch (authmode) {
    case WIFI_AUTH_OPEN:
        return "WIFI_AUTH_OPEN";
    case WIFI_AUTH_WEP:
        return "WIFI_AUTH_WEP";
    case WIFI_AUTH_WPA_PSK:
        return "WIFI_AUTH_WPA_PSK";
    case WIFI_AUTH_WPA2_PSK:
        return "WIFI_AUTH_WPA2_PSK";
    case WIFI_AUTH_WPA_WPA2_PSK:
        return "WIFI_AUTH_WPA_WPA2_PSK";
    case WIFI_AUTH_ENTERPRISE:
        return "WIFI_AUTH_ENTERPRISE";
    case WIFI_AUTH_WPA3_PSK:
        return "WIFI_AUTH_WPA3_PSK";
    case WIFI_AUTH_WPA2_WPA3_PSK:
        return "WIFI_AUTH_WPA2_WPA3_PSK";
    case WIFI_AUTH_WPA3_ENT_192:
        return "WIFI_AUTH_WPA3_ENT_192";
    default:
        return "WIFI_AUTH_UNKNOWN";
    }
}


static esp_err_t uri_ap_list_get_handler(httpd_req_t *req) {
    wifictl_scan_nearby_aps();

    const wifictl_ap_records_t *ap_records;
    ap_records = wifictl_get_ap_records();

    cJSON *root = cJSON_CreateArray();

    for (unsigned i = 0; i < ap_records->count; i++) {
        cJSON *apObject = cJSON_CreateObject();
        // Mengonversi BSSID dari format biner ke string heksadesimal
        char bssidStr[18];
        snprintf(bssidStr, sizeof(bssidStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                ap_records->records[i].bssid[0], ap_records->records[i].bssid[1],
                ap_records->records[i].bssid[2], ap_records->records[i].bssid[3],
                ap_records->records[i].bssid[4], ap_records->records[i].bssid[5]);

        // Menambahkan data ke objek JSON
        cJSON_AddStringToObject(apObject, "ssid", (const char *)ap_records->records[i].ssid);
        cJSON_AddStringToObject(apObject, "bssid", bssidStr);
        cJSON_AddNumberToObject(apObject, "rssi", ap_records->records[i].rssi);
        cJSON_AddStringToObject(apObject, "auth_mode", get_auth_mode_string(ap_records->records[i].authmode));
        
        // Menambahkan informasi apakah jaringan WiFi adalah tersembunyi atau tidak
        cJSON_AddBoolToObject(apObject, "hidden", (ap_records->records[i].ssid == NULL || strcmp((const char *)ap_records->records[i].ssid, "") == 0));

        // Menambahkan objek AP ke array root
        cJSON_AddItemToArray(root, apObject);
    }

    // Pastikan semua objek AP telah ditambahkan
    if (cJSON_GetArraySize(root) != ap_records->count) {
        printf("Error: Failed to add all AP objects to the JSON array.\n");
        cJSON_Delete(root);
        return ESP_FAIL;
    }

    const char *jsonStr = cJSON_Print(root);
    size_t length = strlen(jsonStr);
    printf("Total length of the JSON string: %zu\n", length);
    // Kirim respon HTTP dengan JSON string
    ESP_ERROR_CHECK(httpd_resp_set_type(req, HTTPD_TYPE_JSON));
    ESP_ERROR_CHECK(httpd_resp_send(req, jsonStr, strlen(jsonStr)));
    lora_send_packet((uint8_t*)"/ap-list",9);
    // Kirim total AP
    char totalAPStr[20]; // Buffer untuk menyimpan string total AP
    snprintf(totalAPStr, sizeof(totalAPStr), "{\"total\": %d}", ap_records->count); // Format string total AP
    lora_send_packet((uint8_t*)totalAPStr, strlen(totalAPStr));

    // Kirim masing-masing objek AP dengan jeda
    cJSON *item = root->child;
    while (item != NULL) {
        const char *jsonObjStr = cJSON_PrintUnformatted(item); // Mengubah objek JSON ke string JSON tanpa pemformatan
        size_t itemLength = strlen(jsonObjStr);
        lora_send_packet((uint8_t*)jsonObjStr, itemLength);
        printf("Packet sent...\n");
        printf("Total length of the JSON object: %zu\n", itemLength);
        cJSON_free((void *)jsonObjStr); // Membebaskan memori yang dialokasikan untuk string JSON
        vTaskDelay(pdMS_TO_TICKS(100)); // Jeda 1 detik (100 ms) antara pengiriman objek AP
        item = item->next;
    }
    lora_send_packet((uint8_t*)"data sudah terkirim semua",26);
    // Bebaskan memori cJSON
    cJSON_Delete(root);
    return ESP_OK;
}


static httpd_uri_t uri_ap_list_get = {
    .uri = "/ap-list",
    .method = HTTP_GET,
    .handler = uri_ap_list_get_handler,
    .user_ctx = NULL
};
//@}

// ... (your existing code)

//@}

/**
 * @brief Handlers for \c /run-attack endpoint
 *
 * This endpoint receives attack configuration from client. It deserialize it from octet stream to attack_request_t structure.
 * @param req
 * @return esp_err_t
 * @{
 */
// Sesuaikan dengan struktur data yang diharapkan
static esp_err_t uri_run_attack_post_handler(httpd_req_t *req) {
    // Buffer untuk menyimpan data JSON
    char *json_buffer = NULL;

    // Mendapatkan panjang konten dari header
    size_t content_length = req->content_len;

    // Allokasi buffer dan membaca data JSON
    json_buffer = malloc(content_length + 1); // +1 untuk null-terminator
    if (json_buffer == NULL) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    if (httpd_req_recv(req, json_buffer, content_length) <= 0) {
        free(json_buffer);
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    // Null-terminate string JSON
    json_buffer[content_length] = '\0';

    // Parse JSON menggunakan cJSON
    cJSON *root = cJSON_Parse(json_buffer);
    free(json_buffer);

    if (root == NULL) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    // Mendapatkan nilai dari JSON dan menetapkannya ke attack_request_t
    cJSON *ap_id = cJSON_GetObjectItemCaseSensitive(root, "ap_record_id");
    cJSON *ssid = cJSON_GetObjectItemCaseSensitive(root, "ssid");
    cJSON *attackType = cJSON_GetObjectItemCaseSensitive(root, "attack_type");
    cJSON *bssid = cJSON_GetObjectItemCaseSensitive(root, "bssid");
    cJSON *attackMethod = cJSON_GetObjectItemCaseSensitive(root, "attack_method");
    cJSON *timeout = cJSON_GetObjectItemCaseSensitive(root, "timeout");

    // Lakukan validasi terhadap nilai-nilai JSON yang diperlukan
    if (!cJSON_IsNumber(ap_id) || !cJSON_IsString(ssid) || !cJSON_IsString(bssid) || // Validasi BSSID sebagai string
        !cJSON_IsNumber(attackType) || !cJSON_IsNumber(attackMethod) || !cJSON_IsNumber(timeout)) {
        cJSON_Delete(root);
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    // Mengisi attack_request_t dengan nilai-nilai JSON
    attack_request_t attack_request;
    attack_request.ap_record_id = ap_id->valueint;
    strncpy(attack_request.ssid, ssid->valuestring, sizeof(attack_request.ssid) - 1);
    attack_request.ssid[sizeof(attack_request.ssid) - 1] = '\0';
    strncpy(attack_request.bssid, bssid->valuestring, sizeof(attack_request.bssid) - 1);
    attack_request.bssid[sizeof(attack_request.bssid) - 1] = '\0';
    attack_request.attack_type = attackType->valueint;
    attack_request.attack_method = attackMethod->valueint;
    attack_request.timeout = timeout->valueint;

    cJSON_Delete(root);

    // Kirim respons sukses ke klien
    const char *response = "Attack request received successfully";
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, response, strlen(response));

    // Kirim data ke komponen lain melalui event
    ESP_ERROR_CHECK(esp_event_post(WEBSERVER_EVENTS, WEBSERVER_EVENT_ATTACK_REQUEST, &attack_request, sizeof(attack_request_t), portMAX_DELAY));

    return ESP_OK;
}


static httpd_uri_t uri_run_attack_post = {
    .uri = "/run-attack",
    .method = HTTP_POST,
    .handler = uri_run_attack_post_handler,
    .user_ctx = NULL
};
//@}

/**
 * @brief Handlers for \c /status endpoint
 *
 * This endpoint fetches current status from main component attack wrapper, serialize it and sends it to client as octet stream.
 * @param req
 * @return esp_err_t
 * @{
 */


static esp_err_t uri_status_get_handler(httpd_req_t *req) {
    ESP_LOGD(TAG, "Fetching attack status...");
    const attack_status_t *attack_status;
    attack_status = attack_get_status();

    // Create a new JSON object
    cJSON *json_response = cJSON_CreateObject();

    // Add information to JSON object
    if (attack_status) {
        cJSON_AddNumberToObject(json_response, "state", attack_status->state);
        cJSON_AddNumberToObject(json_response, "content_size", attack_status->content_size);

        // Add a human-readable status message
        if (attack_status->state == FINISHED || attack_status->state == TIMEOUT) {
            cJSON_AddStringToObject(json_response, "status_message", "Attack Finished or Timeout");
        } else {
            cJSON_AddStringToObject(json_response, "status_message", "Attack In Progress or Other State");
        }

        // Optionally, add other fields from attack_status if available and relevant
    } else {
        cJSON_AddStringToObject(json_response, "error", "No attack status available");
    }

    // Convert JSON object to string
    char *json_string = cJSON_Print(json_response);

    // Set response type to JSON
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json_string, strlen(json_string));

    // Free resources
    cJSON_Delete(json_response);
    free(json_string);

    return ESP_OK;
}

//@}
static httpd_uri_t uri_status_get = {
    .uri = "/status",
    .method = HTTP_GET,
    .handler = uri_status_get_handler,
    .user_ctx = NULL
};
/**
 * @brief Handlers for \c /capture.pcap endpoint
 *
 * This endpoint forwards PCAP binary data from pcap_serializer via octet stream to client.
 *
 * @note Most browsers will start download process when this endpoint is called.
 * @param req
 * @return esp_err_t
 * @{
 */
static esp_err_t uri_capture_pcap_get_handler(httpd_req_t *req){
    ESP_LOGD(TAG, "Providing PCAP file...");
    ESP_ERROR_CHECK(httpd_resp_set_type(req, HTTPD_TYPE_OCTET));
    return httpd_resp_send(req, (char *) pcap_serializer_get_buffer(), pcap_serializer_get_size());
}

static httpd_uri_t uri_capture_pcap_get = {
    .uri = "/capture.pcap",
    .method = HTTP_GET,
    .handler = uri_capture_pcap_get_handler,
    .user_ctx = NULL
};
//@}

/**
 * @brief Handlers for \c /capture.hccapx endpoint
 *
 * This endpoint forwards HCCAPX binary data from hccapx_serializer via octet stream to client.
 *
 * @note Most browsers will start download process when this endpoint is called.
 * @param req
 * @return esp_err_t
 * @{
 */
static esp_err_t uri_capture_hccapx_get_handler(httpd_req_t *req){
    ESP_LOGD(TAG, "Providing HCCAPX file...");
    ESP_ERROR_CHECK(httpd_resp_set_type(req, HTTPD_TYPE_OCTET));
    return httpd_resp_send(req, (char *) hccapx_serializer_get(), sizeof(hccapx_t));
}

static httpd_uri_t uri_capture_hccapx_get = {
    .uri = "/capture.hccapx",
    .method = HTTP_GET,
    .handler = uri_capture_hccapx_get_handler,
    .user_ctx = NULL
};
//@}

void webserver_run(){
    ESP_LOGD(TAG, "Running webserver");

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    httpd_handle_t server = NULL;

    ESP_ERROR_CHECK(httpd_start(&server, &config));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_root_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_reset_head));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_ap_list_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_run_attack_post));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_status_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_capture_pcap_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_capture_hccapx_get));
}