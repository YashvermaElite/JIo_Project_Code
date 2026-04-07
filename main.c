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

LOG_MODULE_REGISTER(mem_opt_flash, LOG_LEVEL_INF);
/* ===== DEVICES ===== */
const struct device *flash_dev = DEVICE_DT_GET(DT_NODELABEL(mx25r64));

#define LED2_NODE DT_ALIAS(led2)
static const struct gpio_dt_spec loadSwitch = GPIO_DT_SPEC_GET(LED2_NODE, gpios);

#define FLASH_SIZE (8 * 1024 * 1024)
/* ================= STRUCTS ================= */
/* ===== CONFIG ===== */
#define SAMPLES_PER_SEC 1
#define SECONDS_PER_MIN 60
#define MINUTES_BATCH 15
#define TOTAL_SAMPLES (SAMPLES_PER_SEC * SECONDS_PER_MIN * MINUTES_BATCH)

#define VALUES_PER_SAMPLE 2
#define TOTAL_READINGS (TOTAL_SAMPLES * VALUES_PER_SAMPLE)

#define SECTOR_SIZE 4096

/* ===== BUFFERS ===== */
static char json_buffer[60000];
static struct sensor_sample minute_buffer[60];
static int minute_index = 0;
static struct sensor_sample read_buf[60];

static uint32_t flash_address = 0;
static int minute_counter = 0;

/* ===== SYNC ===== */
struct k_mutex sample_mutex; // for sample struct
struct k_mutex flash_mutex;	 // for flash + minute buffer

/* ===== WORK ===== */
static struct k_timer data_timer;
static struct k_work flash_work;
static struct k_work json_work;
static struct k_work sensor_fetch_work;

///* ================= Global Veriables ================= */
static bool json_in_progress = false;

/* ================= FLASH WRITE ================= */
void flash_work_handler(struct k_work *work)
{
	LOG_INF("Writing 1-minute data to flash");

	k_mutex_lock(&flash_mutex, K_FOREVER);
	if (flash_address + sizeof(minute_buffer) >= FLASH_SIZE)
	{
		LOG_WRN("Flash wrapped");
		flash_address = 0;
	}

	int rc;

	if ((flash_address % SECTOR_SIZE) == 0)
	{
		rc = flash_erase(flash_dev, flash_address, SECTOR_SIZE);
		if (rc != 0)
		{
			k_mutex_unlock(&flash_mutex);
			LOG_ERR("Erase failed: %d", rc);
			return;
		}
	}
	rc = flash_write(flash_dev,
					 flash_address,
					 minute_buffer,
					 sizeof(minute_buffer));

	if (rc != 0)
	{
		LOG_ERR("Flash write failed: %d", rc);
		k_mutex_unlock(&flash_mutex);
		return;
	}

	flash_address += sizeof(minute_buffer);
	minute_counter++;
	k_mutex_unlock(&flash_mutex);
}
/* ================= JSON ================= */
void json_work_handler(struct k_work *work)
{
	int offset = 0;
	static struct sensor_sample all_data[900];
	int index = 0;

	offset += snprintf(json_buffer + offset,
					   sizeof(json_buffer) - offset,
					   "{ \"data\": [");

	k_mutex_lock(&flash_mutex, K_FOREVER);

	if (flash_address < (15 * sizeof(minute_buffer)))
	{
		LOG_WRN("Not enough data for 15 min");
		k_mutex_unlock(&flash_mutex);
		return;
	}

	uint32_t addr = flash_address - (15 * sizeof(minute_buffer));

	for (int m = 0; m < 15; m++)
	{
		int rc = flash_read(flash_dev, addr, read_buf, sizeof(read_buf));
		if (rc != 0)
		{
			LOG_ERR("Flash read failed: %d", rc);
			k_mutex_unlock(&flash_mutex);
			return;
		}

		memcpy(&all_data[index], read_buf, sizeof(read_buf));
		index += 60;
		addr += sizeof(read_buf);
	}
	k_mutex_unlock(&flash_mutex);

	/* ---- BUILD JSON (UNLOCKED) ---- */
	for (int i = 0; i < index; i++)
	{
		if (offset >= sizeof(json_buffer) - 128)
		{
			LOG_ERR("JSON buffer full, truncating");

			if (offset > 0 && json_buffer[offset - 1] == ',')
				json_buffer[offset - 1] = ']';
			else
				json_buffer[offset++] = ']';

			offset += snprintf(json_buffer + offset,
							   sizeof(json_buffer) - offset,
							   "}");
			return;
		}

		offset += snprintf(json_buffer + offset,
						   sizeof(json_buffer) - offset,
						   "{\"t\":%.2f,\"h\":%.2f,\"w\":%d.%02d,\"d\":%d,\"r\":%.2f},",
						   all_data[i].temp / 100.0,
						   all_data[i].hum / 100.0,
						   (int)(all_data[i].wind_speed / 100.0),
						   (int)(fmod(all_data[i].wind_speed, 100.0)),
						   all_data[i].wind_dir,
						   all_data[i].rain / 100.0);
	}
	k_mutex_lock(&flash_mutex, K_FOREVER);
	minute_counter = 0;
	json_in_progress = false;
	k_mutex_unlock(&flash_mutex);
	LOG_INF("JSON READY (%d bytes)", offset);
}
/* ================= TIMER ================= */
void data_timer_handler(struct k_timer *dummy)
{
	ARG_UNUSED(dummy);
	k_work_submit(&sensor_fetch_work);
}

void sensor_fetching_work_handler(struct k_work *work)
{
	struct sensor_sample local_sample;

	k_mutex_lock(&sample_mutex, K_FOREVER);
	local_sample = sample;
	k_mutex_unlock(&sample_mutex);
	ARG_UNUSED(work);

	LOG_INF("SHT45: T=%d.%02d C, H=%u.%02u %%RH, WindSpeed=%d.%02d m/s, WindDirection=%d°",
			local_sample.temp / 100, abs(local_sample.temp % 100),
			local_sample.hum / 100, abs(local_sample.hum % 100),
			local_sample.wind_speed / 100, abs(local_sample.wind_speed % 100),
			local_sample.wind_dir);

	k_mutex_lock(&flash_mutex, K_FOREVER);

	if (minute_index < 60)
	{
		minute_buffer[minute_index++] = local_sample;
	}

	if (minute_index >= 60)
	{
		k_work_submit(&flash_work);
		minute_index = 0;
	}

	k_mutex_unlock(&flash_mutex);
}
static void load_switch_on(void)
{
	gpio_pin_configure_dt(&loadSwitch, GPIO_OUTPUT | GPIO_ACTIVE_HIGH);
	gpio_pin_set_dt(&loadSwitch, 0);
	k_msleep(100);
	printk("Load switch: Power ON\n");
}

void sensor_thread()
{
	LOG_INF("Sensor thread started");
	while (1)
	{
		get_temp();
		k_msleep(1000);
	}
}
void json_thread(void *p1, void *p2, void *p3)
{
	while (1)
	{
		k_sleep(K_SECONDS(1));

		k_mutex_lock(&flash_mutex, K_FOREVER);
		int ready = (minute_counter >= 15);

		if (ready && !json_in_progress)
		{
			json_in_progress = true;
			k_work_submit(&json_work);
		}
		k_mutex_unlock(&flash_mutex);
	}
}
/* ================= MAIN ================= */
int main(void)
{
	LOG_INF("Memory Efficient Flash Logger");

	if (!device_is_ready(flash_dev))
	{
		LOG_ERR("Flash not ready");
		return -1;
	}
	load_switch_on();
	init_sht45();
	k_mutex_init(&sample_mutex);
	k_mutex_init(&flash_mutex);

	k_work_init(&flash_work, flash_work_handler);
	k_work_init(&json_work, json_work_handler);
	k_work_init(&sensor_fetch_work, sensor_fetching_work_handler);

	k_timer_init(&data_timer, data_timer_handler, NULL);
	k_timer_start(&data_timer, K_SECONDS(1), K_SECONDS(1));

	while (1)
	{
		k_sleep(K_SECONDS(10));
	}
}
K_THREAD_DEFINE(sensor_thread_id, 1024, sensor_thread, NULL, NULL, NULL, 7, 0, 0);
K_THREAD_DEFINE(json_thread_id, 4096, json_thread, NULL, NULL, NULL, 7, 0, 0);
