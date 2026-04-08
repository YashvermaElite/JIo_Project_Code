#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/base64.h>
#include <mbedtls/aes.h>
#include <string.h>
#include <stdio.h>
#include "gsm.h"

LOG_MODULE_REGISTER(gsm_network, LOG_LEVEL_INF);

#define UART_DEVICE_NAME "UART_1"
#define RX_BUF_SIZE 8192
#define PAYLOAD_MAX 2048
static const struct device *uart_dev;

static char rx_buf[RX_BUF_SIZE];
static int rx_pos;

static char token[1024];
static char secret_key[64];
static char iv_key[64];
static void uart_send_raw(const char *data, size_t len);
static int build_and_upload(const char *token,
                            const char *secret_key,
                            const char *iv_key);

/*-----------------------UART RX-------------------------*/
static void uart_send_raw(const char *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        uart_poll_out(uart_dev, data[i]);
    }
}

static void uart_callback(const struct device *dev, void *user_data)
{
    uint8_t c;

    while (uart_fifo_read(dev, &c, 1) > 0)
    {
        printk("%c", c);

        if (rx_pos < RX_BUF_SIZE - 1)
        {
            rx_buf[rx_pos++] = c;
            rx_buf[rx_pos] = 0;
        }
    }
}

void uart_init()
{
    uart_dev = device_get_binding(UART_DEVICE_NAME);

    uart_irq_callback_user_data_set(uart_dev, uart_callback, NULL);
    uart_irq_rx_enable(uart_dev);

    LOG_INF("UART initialized");
}

void clear_rx()
{
    memset(rx_buf, 0, sizeof(rx_buf));
    rx_pos = 0;
}

void send_cmd(const char *cmd)
{
    clear_rx();

    printk("\n>> %s\n", cmd);

    size_t len = strlen(cmd);
    for (size_t i = 0; i < len; i++)
        uart_poll_out(uart_dev, cmd[i]);

    uart_poll_out(uart_dev, '\r');
}

void wait_resp(int timeout)
{
    int t = timeout / 10;

    while (t--)
    {
        k_sleep(K_MSEC(10));

        if (strstr(rx_buf, "OK") ||
            strstr(rx_buf, "ERROR") ||
            strstr(rx_buf, "CONNECT"))
            break;
    }
}


/*--------------------------TOKEN PARSER------------------------*/
void parse_token()
{
    char *p = strstr(rx_buf, "TOKEN");

    if (!p)
        return;

    p = strchr(p, ':');
    p++;

    while (*p == '"' || *p == ' ')
        p++;

    char *e = strchr(p, '"');

    int len = e - p;

    memcpy(token, p, len);
    token[len] = 0;

    // LOG_INF("TOKEN = %s", token);
    LOG_INF("TOKEN received");
}

/*------------------SECRET KEY PARSER------------------------*/


void parse_secret()
{
    char *a1 = strstr(rx_buf, "a1");
    char *a2 = strstr(rx_buf, "a2");

    if (!a1 || !a2)
        return;

    sscanf(a1, "\"a1\":\"%[^\"]\"", secret_key);
    sscanf(a2, "\"a2\":\"%[^\"]\"", iv_key);

    LOG_INF("Secret key received");
    LOG_DBG("KEY: %s", secret_key);
    LOG_INF("IV = %s", iv_key);
}

/*----------------------------LOGIN API-----------------------------*/
void https_login()
{
    char payload[] =
        "{\"LOGIN_ID\":\"skymet_winds\",\"PASSWORD\":\"EBD635B7FC8EFBA24BF1234A50E06560\"}";

    char url[] = "https://pmfby.gov.in/windsapi/windsapi/auth/login";

    char cmd[64];

    send_cmd("AT+QHTTPCFG=\"contextid\",1");
    wait_resp(2000);

    send_cmd("AT+QHTTPCFG=\"sslctxid\",1");
    wait_resp(2000);

    send_cmd("AT+QSSLCFG=\"seclevel\",1,0");
    wait_resp(2000);

    send_cmd("AT+QSSLCFG=\"sni\",1,1");
    wait_resp(2000);

    send_cmd("AT+QHTTPCFG=\"contenttype\",4");
    wait_resp(2000);

    send_cmd("AT+QHTTPCFG=\"responseheader\",1");
    wait_resp(2000);

    sprintf(cmd, "AT+QHTTPURL=%d,80", strlen(url));

    send_cmd(cmd);

    while (!strstr(rx_buf, "CONNECT"))
        k_sleep(K_MSEC(10));

    for (int i = 0; i < strlen(url); i++)
        uart_poll_out(uart_dev, url[i]);

    uart_poll_out(uart_dev, '\r');
    uart_poll_out(uart_dev, '\n');

    k_sleep(K_SECONDS(2));

    sprintf(cmd, "AT+QHTTPPOST=%d,60,60", strlen(payload));

    send_cmd(cmd);

    while (!strstr(rx_buf, "CONNECT"))
        k_sleep(K_MSEC(10));

    for (int i = 0; i < strlen(payload); i++)
        uart_poll_out(uart_dev, payload[i]);

    uart_poll_out(uart_dev, '\r');
    uart_poll_out(uart_dev, '\n');

    k_sleep(K_SECONDS(3));

    send_cmd("AT+QHTTPREAD=80");

    while (!strstr(rx_buf, "CONNECT"))
        k_sleep(K_MSEC(10));

    k_sleep(K_SECONDS(3));

    parse_token();
}


/*-----------------------  GET SECRET API ---------------------*/
int get_secret(const char *token, char *secret_out, size_t secret_out_len,
               char *iv_out, size_t iv_out_len)
{
    char url[] = "https://pmfby.gov.in/windsapi/windsapi/auth/getSecret";
    char http_req[2048];
    char cmd[128];

    send_cmd("AT+QHTTPCFG=\"requestheader\",1");
    wait_resp(3000);

    send_cmd("AT+QHTTPCFG=\"responseheader\",1");
    wait_resp(3000);

    send_cmd("AT+QHTTPCFG=\"contenttype\",4");
    wait_resp(3000);

    memset(rx_buf, 0, sizeof(rx_buf));
    rx_pos = 0;

    snprintf(cmd, sizeof(cmd), "AT+QHTTPURL=%zu,80", strlen(url));
    send_cmd(cmd);

    while (!strstr(rx_buf, "CONNECT"))
    {
        k_sleep(K_MSEC(20));
    }

    uart_send_raw(url, strlen(url));
    uart_poll_out(uart_dev, '\r');
    uart_poll_out(uart_dev, '\n');

    k_sleep(K_SECONDS(1));

    snprintf(http_req, sizeof(http_req),
             "POST /windsapi/windsapi/auth/getSecret HTTP/1.1\r\n"
             "Host: pmfbydemo.amnex.co.in\r\n"
             "Authorization: Bearer %s\r\n"
             "Content-Type: application/json\r\n"
             "Connection: keep-alive\r\n"
             "\r\n"
             "{}",
             token);

    memset(rx_buf, 0, sizeof(rx_buf));
    rx_pos = 0;

    snprintf(cmd, sizeof(cmd), "AT+QHTTPPOST=%zu,60,120", strlen(http_req));
    send_cmd(cmd);

    while (!strstr(rx_buf, "CONNECT"))
    {
        k_sleep(K_MSEC(20));
    }

    uart_send_raw(http_req, strlen(http_req));

    k_sleep(K_SECONDS(3));

    send_cmd("AT+QHTTPREAD=120");

    while (!strstr(rx_buf, "CONNECT"))
    {
        k_sleep(K_MSEC(20));
    }

    k_sleep(K_SECONDS(3));

    LOG_INF("GET SECRET RESPONSE:\n%s", rx_buf);

    {
        char *p1 = strstr(rx_buf, "\"a1\":\"");
        char *p2 = strstr(rx_buf, "\"a2\":\"");

        if (!p1 || !p2)
        {
            p1 = strstr(rx_buf, "\"a1\": \"");
            p2 = strstr(rx_buf, "\"a2\": \"");
        }

        if (!p1 || !p2)
        {
            LOG_ERR("a1/a2 not found in getSecret response");
            return -ENOENT;
        }

        p1 = strchr(p1, ':');
        p2 = strchr(p2, ':');
        if (!p1 || !p2)
        {
            return -EINVAL;
        }

        p1++;
        p2++;

        while (*p1 == ' ' || *p1 == '\"')
            p1++;
        while (*p2 == ' ' || *p2 == '\"')
            p2++;

        char *e1 = strchr(p1, '\"');
        char *e2 = strchr(p2, '\"');
        if (!e1 || !e2)
        {
            return -EINVAL;
        }

        size_t l1 = (size_t)(e1 - p1);
        size_t l2 = (size_t)(e2 - p2);

        if (l1 >= secret_out_len)
            l1 = secret_out_len - 1;
        if (l2 >= iv_out_len)
            l2 = iv_out_len - 1;

        memcpy(secret_out, p1, l1);
        secret_out[l1] = '\0';

        memcpy(iv_out, p2, l2);
        iv_out[l2] = '\0';
    }

    LOG_INF("Secret key and IV extracted");
    return 0;
}
static int aes_encrypt_base64(const char *input,
                              const char *key,
                              const char *iv,
                              char **out_b64)
{
    size_t len = strlen(input);
    size_t padded_len = ((len / 16) + 1) * 16;

    uint8_t *padded = k_malloc(padded_len);
    uint8_t *cipher = k_malloc(padded_len);

    if (!padded || !cipher)
        return -ENOMEM;

    memcpy(padded, input, len);

    uint8_t pad = padded_len - len;
    memset(padded + len, pad, pad);

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    mbedtls_aes_setkey_enc(&ctx, (const unsigned char *)key, 256);

    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);

    mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT,
                          padded_len, iv_copy, padded, cipher);

    mbedtls_aes_free(&ctx);

    size_t b64_len;
    size_t b64_size = ((padded_len + 2) / 3) * 4 + 1;

    char *b64 = k_malloc(b64_size);
    if (!b64)
        return -ENOMEM;

    base64_encode(b64, b64_size, &b64_len, cipher, padded_len);

    k_free(padded);
    k_free(cipher);

    *out_b64 = b64;
    return 0;
}

int build_and_upload(const char *token,
                     const char *secret_key,
                     const char *iv_key)
{
    char weather_json[2048];

    /* ---------------- WEATHER JSON ---------------- */
    snprintf(weather_json, sizeof(weather_json),
             "{"
             "\"Maximum_Temperature\":\"29.6\","
             "\"Minimum_Temperature\":\"27.2\","
             "\"now_temperature\":\"29.6\","
             "\"daily_maximum_temperature\":\"30\","
             "\"daily_minimum_temperature\":\"27\","
             "\"Maximum_Relative_Humidity\":\"70\","
             "\"Minimum_Relative_Humidity\":\"40\","
             "\"now_relative_humidity\":\"45\","
             "\"Rainfall_Cumulative\":\"0\","
             "\"rainfall\":\"0\","
             "\"now_wind_speed\":\"2.3\","
             "\"now_wind_direction\":\"180\","
             "\"average_wind_speed\":\"2.0\","
             "\"average_wind_direction\":\"175\","
             "\"Battery_Voltage\":\"12.4\","
             "\"Panel_Voltage\":\"10.2\","
             "\"IMEI_Number\":\"862287077433001\","
             "\"Time_Stamp\":\"2026-04-05 16:20:00\","
             "\"Time_Stamp_GMT\":\"2026-04-05 10:50:00\","
             "\"Signal_Strength\":\"22\","
             "\"Latitude\":\"28.654321\","
             "\"Longitude\":\"77.123456\","
             "\"PROVIDER_ID\":\"SKYMET\","
             "\"STATION_ID\":\"UPT3397\","
             "\"Device_ID\":\"3567425\""
             "}");

    LOG_INF("PLAINTEXT JSON:\n%s", weather_json);

    /* ---------------- VALIDATION ---------------- */
    if (strlen(secret_key) != 32)
    {
        LOG_ERR("Invalid key length: %d", strlen(secret_key));
        return -EINVAL;
    }

    if (strlen(iv_key) != 16)
    {
        LOG_ERR("Invalid IV length: %d", strlen(iv_key));
        return -EINVAL;
    }

    /* ---------------- AES ENCRYPT ---------------- */
    char *base64 = NULL;

    if (aes_encrypt_base64(weather_json, secret_key, iv_key, &base64) != 0)
    {
        LOG_ERR("Encryption failed");
        return -1;
    }

    /* ---------------- PAYLOAD ---------------- */
    char payload[PAYLOAD_MAX];

    snprintf(payload, sizeof(payload),
             "{\"data\":[\"%s\"]}", base64);

    LOG_INF("Payload size=%d", strlen(payload));

    /* ---------------- HTTP REQUEST ---------------- */
    char http_req[2048];

    snprintf(http_req, sizeof(http_req),
             "POST /windsapi/windsapi/data/insertJsonDataNew HTTP/1.1\r\n"
             "Host: pmfbydemo.amnex.co.in\r\n"
             "Authorization: Bearer %s\r\n"
             "Content-Type: application/json\r\n"
             "Connection: close\r\n"
             "Content-Length: %d\r\n"
             "\r\n"
             "%s",
             token,
             strlen(payload),
             payload);

    LOG_INF("HTTP request size=%d", strlen(http_req));

    /* ---------------- MODEM CONFIG ---------------- */
    send_cmd("AT+QHTTPCFG=\"requestheader\",1");
    wait_resp(2000);

    send_cmd("AT+QHTTPCFG=\"responseheader\",1");
    wait_resp(2000);

    char url[] =
        "https://pmfbydemo.amnex.co.in/windsapi/windsapi/data/insertJsonDataNew";

    char cmd[64];

    sprintf(cmd, "AT+QHTTPURL=%d,80", strlen(url));
    send_cmd(cmd);

    while (!strstr(rx_buf, "CONNECT"))
        k_sleep(K_MSEC(10));

    uart_send_raw(url, strlen(url));
    uart_poll_out(uart_dev, '\r');
    uart_poll_out(uart_dev, '\n');

    k_sleep(K_SECONDS(2));

    memset(rx_buf, 0, sizeof(rx_buf));

    sprintf(cmd, "AT+QHTTPPOST=%d,60,120", strlen(http_req));
    send_cmd(cmd);

    /* ---------------- WAIT FOR CONNECT ---------------- */
    while (!strstr(rx_buf, "CONNECT"))
        k_sleep(K_MSEC(10));

    k_sleep(K_MSEC(100));

    /* ---------------- SEND DATA ---------------- */
    int len = strlen(http_req);

    for (int i = 0; i < len; i++)
    {
        uart_poll_out(uart_dev, http_req[i]);
        k_sleep(K_USEC(500));
    }

    uart_poll_out(uart_dev, '\r');
    uart_poll_out(uart_dev, '\n');

    LOG_INF("WAITING FOR +QHTTPPOST...");

    /* ---------------- WAIT RESPONSE ---------------- */
    while (!strstr(rx_buf, "+QHTTPPOST"))
        k_sleep(K_MSEC(100));

    k_sleep(K_SECONDS(1));

    /* ---------------- READ RESPONSE ---------------- */
    send_cmd("AT+QHTTPREAD=120");

    while (!strstr(rx_buf, "CONNECT"))
        k_sleep(K_MSEC(10));

    k_sleep(K_SECONDS(3));

    LOG_INF("UPLOAD RESPONSE:\n%s", rx_buf);

    /* ---------------- CLEANUP ---------------- */
    k_free(base64);

    return 0;
}

void init_gsm()
{
    uart_init();

    k_sleep(K_SECONDS(5));

    send_cmd("AT");
    wait_resp(2000);

    https_login();

    get_secret(token, secret_key, sizeof(secret_key), iv_key, sizeof(iv_key));

    // encrypt_and_upload();
    build_and_upload(token, secret_key, iv_key);
}
