#include <zephyr/kernel.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/device.h>
#include <zephyr/logging/log.h>
#include <stdio.h>
#include <string.h>
#include <zephyr/drivers/sensor.h>
#include <zephyr/drivers/sensor/sht4x.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/uart.h>
#include "headers/sensors.h"
LOG_MODULE_REGISTER(get_temp, LOG_LEVEL_INF);

#define SHT_NODE DT_NODELABEL(sht4x)
const struct device *sht = DEVICE_DT_GET(SHT_NODE);

#define UART_DEVICE_NODE DT_NODELABEL(uart3)
const struct device *uart_dev = DEVICE_DT_GET(UART_DEVICE_NODE);

extern struct k_mutex sample_mutex;
extern struct k_mutex flash_mutex;

struct sensor_sample sample = {
    .temp = 0,
    .hum = 0,
    .wind_speed = 0,
    .wind_dir = 0,
    .rain = 0,
};
// US_Anmeometer
#define MSG_SIZE 64

/* queue to store up to 10 complete lines */
K_MSGQ_DEFINE(uart_msgq, MSG_SIZE, 10, 4);

/* receive buffer used in UART ISR callback */
static char rx_buf[MSG_SIZE];
static int rx_buf_pos;

int init_sht45()
{
    if (!device_is_ready(sht))
    {
        LOG_ERR("SHT4x not ready");
        return -1;
    }
}
void get_temp()
{
    struct sensor_value temp, humidity;

    int err = sensor_sample_fetch(sht);
    if (err)
    {
        LOG_ERR("sensor_sample_fetch failed: %d", err);
        return;
    }

    sensor_channel_get(sht, SENSOR_CHAN_AMBIENT_TEMP, &temp);
    sensor_channel_get(sht, SENSOR_CHAN_HUMIDITY, &humidity);

    uint16_t t = sensor_value_to_double(&temp) * 100;
    uint16_t h = sensor_value_to_double(&humidity) * 100;

    k_mutex_lock(&sample_mutex, K_FOREVER);
    sample.temp = t;
    sample.hum = h;
    k_mutex_unlock(&sample_mutex);
}

void clean_line(char *line)
{
    char clean[MSG_SIZE];
    int j = 0;

    for (int i = 0; i < strlen(line); i++)
    {
        if (line[i] >= 32 && line[i] <= 126) // printable ASCII only
        {
            clean[j++] = line[i];
        }
    }
    clean[j] = '\0';

    strcpy(line, clean);
}

static void try_parse_line(const char *line)
{
    // Ignore empty lines
    if (strlen(line) == 0)
        return;

    if (line[0] != 'Q')
    {
        return; // ignore boot/config messages
    }

    float wind_speed = 0.0f;
    int wind_dir = 0;
    char unit = '\0';

    if (sscanf(line, "Q,%d,%f,%c,%*[^,],%*[^,]", &wind_dir, &wind_speed, &unit) == 3)
    {
        k_mutex_lock(&sample_mutex, K_FOREVER);
        sample.wind_speed = wind_speed * 100;
        sample.wind_dir = wind_dir;
        k_mutex_unlock(&sample_mutex);

        LOG_DBG("Wind parsed: %.2f m/s dir=%d", wind_speed, wind_dir);
        return;
    }

    LOG_WRN("Parse failed: %s", line);
}
static void serial_cb(const struct device *dev, void *user_data)
{
    uint8_t c;

    if (!uart_irq_update(uart_dev) || !uart_irq_rx_ready(uart_dev))
    {
        return;
    }

    while (uart_fifo_read(uart_dev, &c, 1) == 1)
    {
        if ((c == '\n' || c == '\r') && rx_buf_pos > 0)
        {
            rx_buf[rx_buf_pos] = '\0';
            k_msgq_put(&uart_msgq, rx_buf, K_NO_WAIT);
            rx_buf_pos = 0;
        }
        else if (rx_buf_pos < (sizeof(rx_buf) - 1))
        {
            rx_buf[rx_buf_pos++] = (char)c;
        }
    }
}
void US_Anemometer(void *p1, void *p2, void *p3)
{
    char line[MSG_SIZE];

    LOG_INF("Anemometer thread started");

    if (!device_is_ready(uart_dev))
    {
        LOG_ERR("UART not ready");
        return;
    }

    int ret = uart_irq_callback_user_data_set(uart_dev, serial_cb, NULL);
    if (ret < 0)
    {
        LOG_ERR("UART callback error: %d", ret);
        return;
    }

    uart_irq_rx_enable(uart_dev);

    while (1)
    {
        if (k_msgq_get(&uart_msgq, &line, K_FOREVER) == 0)
        {
            clean_line(line);
            /* Ignore empty lines */
            if (strlen(line) == 0)
            {
                continue;
            }
            if (line[0] == 'Q')
            {
                try_parse_line(line);
            }
        }
    }
}
K_THREAD_DEFINE(anemometer_thread_id, 1024, US_Anemometer, NULL, NULL, NULL, 7, 0, 0);
