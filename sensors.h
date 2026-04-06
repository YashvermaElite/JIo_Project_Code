#ifndef _SENSORS_H_
#define _SENSORS_H_ 

void get_temp();
int init_sht45();
void US_Anemometer();

struct sensor_sample
{
	int16_t temp;
	int16_t hum;
	float wind_speed;
	int16_t wind_dir;
	int16_t rain;
	int16_t reserved; // padding → 12 bytes
};
extern struct sensor_sample sample;
#endif /* _SENSORS_H_ */