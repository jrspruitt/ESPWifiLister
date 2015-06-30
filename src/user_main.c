/*
The MIT License (MIT)

Copyright (c) 2015 Jason Pruitt

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include <esp8266.h>
#include "stdout.h"
#include "scanning.h"

//#define AP_CHANNELS_ONLY
#define HIDDEN		"Hidden"
#define MAX_APS		64
#define MAX_CLIENTS	32
#define EXPIRES		3
#define SNIFF_TIME	3000
#define CHANNEL_COUNT	15	// plus 1

static ETSTimer prScanTimer;

static int sniff_channel = 0;
static bool channels_used[CHANNEL_COUNT] = { false };

struct orphan {
	u8 mac[6];
	u8 bssid[6];
	s8 rssi;
	s8 expires;
};

struct orphan orphans_list[MAX_CLIENTS];

struct client {
	u8 mac[6];
	s8 rssi;
	s8 expires;
};

struct ap {
	u8 bssid[6];
	char ssid[32];
	u8 channel;
	s8 rssi;
	u8 authmode;
	s8 expires;
	struct client clients[MAX_CLIENTS];
};

struct ap ap_list[MAX_APS];

struct RxControl {
    signed rssi:8;
    unsigned rate:4;
    unsigned is_group:1;
    unsigned:1;
    unsigned sig_mode:2;
    unsigned legacy_length:12;
    unsigned damatch0:1;
    unsigned damatch1:1;
    unsigned bssidmatch0:1;
    unsigned bssidmatch1:1;
    unsigned MCS:7;
    unsigned CWB:1;
    unsigned HT_length:16;
    unsigned Smoothing:1;
    unsigned Not_Sounding:1;
    unsigned:1;
    unsigned Aggregation:1;
    unsigned STBC:2;
    unsigned FEC_CODING:1;
    unsigned SGI:1;
    unsigned rxend_state:8;
    unsigned ampdu_cnt:8;
    unsigned channel:4;
    unsigned:12;
};
 
struct Ampdu_Info
{
  uint16 length;
  uint16 seq;
  uint8  address3[6];
};

struct sniffer_buf {
    struct RxControl rx_ctrl;
    uint8_t  buf[36];
    uint16_t cnt;
    struct Ampdu_Info ampdu_info[1];
};

struct sniffer_buf2{
	struct RxControl rx_ctrl;
	u8 buf[112];
	u16 cnt;
	u16 len;
};

struct framectrl_80211
{
	u8 Protocol:2;
	u8 Type:2;
	u8 Subtype:4;
	u8 ToDS:1;
	u8 FromDS:1;
	u8 MoreFlag:1;
	u8 Retry:1;
	u8 PwrMgmt:1;
	u8 MoreData:1;
	u8 Protectedframe:1;
	u8 Order:1;
};

struct probe_request_80211
{
	struct framectrl_80211 framectrl;
	uint16 duration;
	uint8 rdaddr[6];
	uint8 tsaddr[6];
	uint8 bssid[6];
	uint16 sequencectrl;
	uint8 addr4[6];
	uint16 qos;
	uint32 htctrl;
};

static bool ICACHE_FLASH_ATTR
add_ap(struct bss_info *bss_link)
{
	int next_ap = -1;
	char *ssid;
	u8 bssid[6];
	memcpy(bssid, bss_link->bssid, 6);

	for ( int i = 0; i < MAX_APS; i++ ) {
		if ( memcmp(ap_list[i].bssid, bssid, 6) == 0 ) {
			ap_list[i].rssi = bss_link->rssi;
			ap_list[i].channel = bss_link->channel;
			ap_list[i].expires = EXPIRES;
			channels_used[ap_list[i].channel] = true;
			return true;
		}

		if ( ap_list[i].ssid[0] == 0 && next_ap == -1 )
			next_ap = i;
	}

	if ( bss_link->is_hidden ) {
		ssid = HIDDEN;
	} else {
		ssid = (char *)bss_link->ssid;
	}

	if ( next_ap >= MAX_APS || next_ap < 0 )
		return false;

	memcpy(ap_list[next_ap].bssid, bss_link->bssid, 6);
	strcpy(ap_list[next_ap].ssid, ssid);
	ap_list[next_ap].channel = bss_link->channel;
	channels_used[ap_list[next_ap].channel] = true;
	ap_list[next_ap].authmode = bss_link->authmode;
	ap_list[next_ap].rssi = bss_link->rssi;
	ap_list[next_ap].expires = EXPIRES;
	ets_bzero(ap_list[next_ap].clients, sizeof(ap_list[next_ap].clients));

	return true;
}

static bool ICACHE_FLASH_ATTR
add_client(int ap_idx, uint8 *mac, s8 rssi)
{
	int next_client = -1;

	for ( int i = 0; i < MAX_CLIENTS; i++ ) {
		if ( memcmp(ap_list[ap_idx].clients[i].mac, mac, 6) == 0 ) {
			//ets_printf("Updated Client:"MACSTR"\n", MAC2STR(mac));
			ap_list[ap_idx].clients[i].rssi = rssi;
			ap_list[ap_idx].clients[i].expires = EXPIRES;
			return true;
		}

		if ( ap_list[ap_idx].clients[i].expires == 0 && next_client == -1 )
			next_client = i;
	}

	if ( next_client >= MAX_CLIENTS || next_client < 0 )
		return false;

	//ets_printf("Added Client:"MACSTR"\n", MAC2STR(mac));
	memcpy(ap_list[ap_idx].clients[next_client].mac, mac, 6);
	ap_list[ap_idx].clients[next_client].expires = EXPIRES;
	ap_list[ap_idx].clients[next_client].rssi = rssi;
	return true;
}

static bool ICACHE_FLASH_ATTR
add_orphan(uint8 *mac, uint8 *bssid, s8 rssi)
{
	int next_orphan = -1;

	for ( int i = 0; i < MAX_CLIENTS; i++ ) {
		if ( memcmp(orphans_list[i].mac, mac, 6) == 0 ) {
			//ets_printf("Updated Orphan:"MACSTR"\n", MAC2STR(mac));
			orphans_list[i].rssi = rssi;
			orphans_list[i].expires = EXPIRES;
			return true;
		}

		if ( orphans_list[i].expires == 0 && next_orphan == -1 )
			next_orphan = i;
	}

	if ( next_orphan >= MAX_CLIENTS || next_orphan < 0 )
		return false;

	//ets_printf("Added Orphan:"MACSTR"\n", MAC2STR(mac));
	memcpy(orphans_list[next_orphan].mac, mac, 6);
	memcpy(orphans_list[next_orphan].bssid, bssid, 6);
	orphans_list[next_orphan].rssi = rssi;
	orphans_list[next_orphan].expires = EXPIRES;
	return true;
}

static void ICACHE_FLASH_ATTR
wifidata_cleaner(void)
{
	int ap_idx;
	struct ap ap_holder;
	const u8 blank[6] = { 0 };

	for ( int i = 0; i < MAX_APS; i++ ) {
		if ( ap_list[i].ssid[0] == 0 )
			continue;

		ap_list[i].expires -= 1;

		if ( ap_list[i].expires < 0 ){
			//ets_printf("Deleted: %s\n", ap_list[i].ssid);
			ap_list[i].ssid[0] = 0;
			ap_list[i].rssi = 0;
		}

		for ( int c = 0; c < MAX_CLIENTS; c++ ) {
			if ( memcmp(ap_list[i].clients[c].mac, blank, 6) == 0 )
				continue;

			ap_list[i].clients[c].expires -= 1;

			if ( ap_list[i].clients[c].expires <= 0 ) {
				//ets_printf("Deleted Client:"MACSTR"\n", MAC2STR(ap_list[i].clients[c].mac));
				ets_bzero(&ap_list[i].clients[c], sizeof(struct client));
			}
		}
	}

	for ( int o = 0; o < MAX_CLIENTS; o++ ) {
		if ( memcmp(orphans_list[o].mac, blank, 6) == 0 )
			continue;

		orphans_list[o].expires -= 1;

		if ( orphans_list[o].expires <= 0 ) {
			//ets_printf("Deleted Orphan:"MACSTR"\n", MAC2STR(orphans_list[o].mac));
			ets_bzero(&orphans_list[o], sizeof(struct orphan));
		}
	}

	// Sort APs by rssi
	for (int i = 1 ; i < MAX_APS; i++) {
   		ap_idx = i;

		while ( ap_idx > 0 && ap_list[ap_idx].rssi > ap_list[ap_idx-1].rssi) {
			ap_holder = ap_list[ap_idx];
			ap_list[ap_idx] = ap_list[ap_idx-1];
			ap_list[ap_idx-1] = ap_holder;
			ap_idx--;
		}
	}

}

static void ICACHE_FLASH_ATTR
wifidata_printer(void)
{
	char *authmode;
	uint8 counter = 0;
	//ets_printf("\033[2J"); // Clear terminal screen before print.
	ets_printf("\n");
	ets_printf("##########################################\n");

	for ( int i = 0; i < MAX_APS; i++ ) {

		if ( ap_list[i].ssid[0] == 0 )
			continue;

		//ets_printf(" Expires: %d \t", ap_list[i].expires);
		ets_printf("%-32s", ap_list[i].ssid);
		ets_printf("\tBSSID: "MACSTR, MAC2STR(ap_list[i].bssid));
		ets_printf("\tChannel: %d", ap_list[i].channel);
		ets_printf("\tRSSI: %ddbm", ap_list[i].rssi);

		switch ( ap_list[i].authmode ) {
			case 0:
				authmode = "OPEN";
				break;
			case 1:
				authmode = "WEP";
				break;
			case 2:
				authmode = "WPA_PAK";
				break;
			case 3:
				authmode = "WPA2_PAK";
				break;
			case 4:
				authmode = "WPA_WPA2_PSK";
				break;
			default:
				authmode = "Unknown";
				break;
		}

		ets_printf("\tAuthMode: %s\n", authmode);

		for ( int c = 0; c < MAX_CLIENTS; c++ ) {
			if ( ap_list[i].clients[c].expires == 0 )
				continue;

			//ets_printf(" Expires: %d \t", ap_list[i].clients[c].expires);
			ets_printf("\tClient MAC: " MACSTR, MAC2STR(ap_list[i].clients[c].mac));
			ets_printf("\tRSSI: %ddbm", ap_list[i].clients[c].rssi);

			for ( int z = 0; z < MAX_APS; z++ ) {
				if ( memcmp(ap_list[i].clients[c].mac, ap_list[z].bssid, 6) == 0 )
					ets_printf("\tSSID: %s ", ap_list[z].ssid);
			}
			ets_printf("\n");
		}
		counter++;
	}

	ets_printf("\nTotal APs: %d\n", counter);
	ets_printf("---------------------------\n");
	ets_printf("Orphan Clients\n");

	for ( int o = 0; o < MAX_CLIENTS; o++ ) {
		if ( orphans_list[o].expires == 0 )
			continue;

		//ets_printf(" Expires: %d \t", orphans_list[o].expires);
		ets_printf("\tClient MAC: "MACSTR" BSSID: "MACSTR" RSSI: %ddbm\n",
			MAC2STR(orphans_list[o].mac),
			MAC2STR(orphans_list[o].bssid),
			orphans_list[o].rssi);
	}


	ets_printf("##########################################\n");
}

static void ICACHE_FLASH_ATTR
apscan_done(void *arg, STATUS status)
{
	//ets_printf("STATUS: %d\n", status);

	if ( status == OK ) {
		struct bss_info *bss_link = (struct bss_info *)arg;
		bss_link = bss_link->next.stqe_next;

		while((bss_link = bss_link->next.stqe_next) != NULL)
			add_ap(bss_link);

		wifidata_cleaner();
		sniffing_start();
	}
}

static void ICACHE_FLASH_ATTR
apscan_start(void)
{
	os_timer_disarm(&prScanTimer);
	wifi_station_scan(NULL, apscan_done);
}

static int ICACHE_FLASH_ATTR
get_next_channel(void)
{
#ifdef AP_CHANNELS_ONLY
	for (int i = sniff_channel+1; i < CHANNEL_COUNT; i++ ) {
		if ( channels_used[i] ) {
			//ets_printf("Channel: %d\n", i);
			sniff_channel = i;
			return sniff_channel;
		}
	}

	sniff_channel = 0;

#else
	sniff_channel++;

	if ( sniff_channel >= CHANNEL_COUNT )
		sniff_channel = 0;

	//ets_printf("Channel: %d\n", sniff_channel);

#endif
	return sniff_channel;
}

static void ICACHE_FLASH_ATTR
packet_processor(uint8 *buf, uint16 len)
{
	struct sniffer_buf *sbuf;
	int ap_idx;
	uint8 server[6];
	uint8 client[6];
	uint8 full[6];
	full[0] = 0xFF;
	full[1] = 0xFF;
	full[2] = 0xFF;
	full[3] = 0xFF;
	full[4] = 0xFF;
	full[5] = 0xFF;

	if ( len == 60 ) {
		sbuf = (struct sniffer_buf *)buf;
		struct probe_request_80211 *probe_request = (struct probe_request_80211*) sbuf->buf;

		if ( probe_request->framectrl.ToDS == probe_request->framectrl.FromDS )
			return;

		if ( (probe_request->framectrl.ToDS == 1 && probe_request->framectrl.FromDS == 0) ) { 
			memcpy(server, probe_request->rdaddr, 6);
			memcpy(client, probe_request->tsaddr, 6);
		} else { 
			memcpy(server, probe_request->tsaddr, 6);
			memcpy(client, probe_request->rdaddr, 6);
		}

		if ( memcmp(client, full, 6) == 0 )
			return;

		if ( client[0] == 0x33 && client[1] == 0x33 && client[2] == 0x00 )
			return;

		if ( client[0] == 0x01 && client[1] == 0x00 && client[2] == 0x5e )
			return;

		/*
		ets_printf("%d: ", len);
		ets_printf("ToDS: %d FromDS:%d ", probe_request->framectrl.ToDS, probe_request->framectrl.FromDS);
		ets_printf("client: "MACSTR" server: "MACSTR" BSSID: "MACSTR"\n",
				MAC2STR(client),
				MAC2STR(server),
				MAC2STR(probe_request->bssid));
		*/

		ap_idx = 0;

		while ( ap_idx < MAX_APS ) {
			if ( memcmp(server, ap_list[ap_idx].bssid, 6) == 0 )
				break;
			ap_idx++;
		}

		if ( ap_idx >= MAX_APS ) {
			add_orphan(client, server, sbuf->rx_ctrl.rssi);
		} else {
			add_client(ap_idx, client, sbuf->rx_ctrl.rssi);
		}
	}
}

static void ICACHE_FLASH_ATTR
sniffing_start(void)
{
	wifi_station_disconnect();
	wifi_set_channel(sniff_channel);
	wifi_promiscuous_enable(1);

	os_timer_disarm(&prScanTimer);
	os_timer_setfn(&prScanTimer, sniffing_stop, NULL);
	os_timer_arm(&prScanTimer, SNIFF_TIME, 1);

	wifi_set_promiscuous_rx_cb((wifi_promiscuous_cb_t)packet_processor);	
}

static void ICACHE_FLASH_ATTR
sniffing_stop(void *arg)
{
	wifi_promiscuous_enable(0);

	if ( get_next_channel() != 0 ) {
		sniffing_start();

	} else {

		for ( int i = 0; i <= CHANNEL_COUNT; i++ )
			channels_used[i] = false;
		wifidata_printer();
		apscan_start();
	}
}

static void ICACHE_FLASH_ATTR
apscan_init(void)
{
	ets_bzero(ap_list, sizeof(ap_list));
	//ets_printf("Heap: %ld\n", (unsigned long)system_get_free_heap_size());
	apscan_start();
	
}

void user_init(void)
{
	system_update_cpu_freq(SYS_CPU_160MHZ);
	system_set_os_print(0);
	wifi_set_opmode(STATION_MODE);
	stdoutInit();
	ets_printf("\nReady\n");
	system_init_done_cb(apscan_init);
}
/*
void user_rf_pre_init(void)
{
}
*/
