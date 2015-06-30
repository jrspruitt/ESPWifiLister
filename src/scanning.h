#ifndef SCANNING_H
#define SCANNING_H

static void ICACHE_FLASH_ATTR wifidata_cleaner(void);
static void ICACHE_FLASH_ATTR wifidata_printer(void);

static void ICACHE_FLASH_ATTR apscan_done(void *arg, STATUS status);
static void ICACHE_FLASH_ATTR apscan_start(void);
static void ICACHE_FLASH_ATTR apscan_init(void);

static bool ICACHE_FLASH_ATTR add_ap(struct bss_info *bss_link);
static bool ICACHE_FLASH_ATTR add_client(int ap_idx, uint8 *mac, s8 rssi);
static bool ICACHE_FLASH_ATTR add_orphan(uint8 *mac, uint8 *bssid, s8 rssi);

static void ICACHE_FLASH_ATTR packet_processor(uint8 *buf, uint16 len);
static void ICACHE_FLASH_ATTR sniffing_start(void);
static void ICACHE_FLASH_ATTR sniffing_stop(void *arg);
static int ICACHE_FLASH_ATTR get_next_channel(void);
#endif
