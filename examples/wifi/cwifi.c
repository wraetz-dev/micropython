// Include c stdlibs
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

// Include MicroPython API.
#include "py/runtime.h"
#include "py/obj.h"
#include "py/builtin.h"

// Include ESP WiFi API
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "freertos/FreeRTOS.h"

// Taken from: https://github.com/ESP-EOS/ESP32-WiFi-Sniffer/blob/master/WIFI_SNIFFER_ESP32.ino
//             https://github.com/SHA2017-badge/bpp/blob/37b11b45da60a3df009ddcafd869ff4a083b8e50/esp32-recv/main/bpp_sniffer.c#L192


#define DET_LST_MAX 1000
#define NARGS 12
#define FRAME_SZ 0


typedef struct {
  unsigned frame_ctrl:16;
  unsigned duration_id:16;
  uint8_t addr1[6]; /* receiver address */
  uint8_t addr2[6]; /* sender address */
  uint8_t addr3[6]; /* filtering address */
  unsigned sequence_ctrl:16;
  uint8_t addr4[6]; /* optional */
} wifi_ieee80211_mac_hdr_t;


typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0]; /* network data ended with 4 bytes csum (CRC32) */
} wifi_ieee80211_packet_t;


typedef struct {
  unsigned short version;
  char ptype[5];
  char sig_mode[5];
  unsigned short chan;
  signed short rssi;
  char addr1[18];
  char addr2[18];
  char addr3[18];
  unsigned short mcs;
  unsigned short sig_len;
  char ssid[34];
  uint8_t frame[FRAME_SZ];
} survey_data;


static int started = 0;
static int svy_lst_idx = 0;
static survey_data *survey_recs[DET_LST_MAX];
static const char *addr_fmt = "%02x:%02x:%02x:%02x:%02x:%02x";
static wifi_country_t wifi_country = {.cc="US", .schan = 1, .nchan = 13}; //TODO: Figure out how to handle this in prod (sk)


static void startup(void);
static char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type);
static char *wifi_sniffer_sigmode_type2str(int sig_mode_enum);
static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);
static mp_obj_t survey(mp_obj_t channel_obj, mp_obj_t duration_ms_obj);


void startup(void)
{
  printf("Starting module\n");
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
  ESP_ERROR_CHECK( esp_wifi_set_country(&wifi_country) );
  ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_NULL) );
  ESP_ERROR_CHECK( esp_wifi_start() );
  started = 1;
}


char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type)
{
  switch(type) {
  case WIFI_PKT_MGMT: return "MGMT";
  case WIFI_PKT_DATA: return "DATA";
  default:  
  case WIFI_PKT_MISC: return "MISC";
  }
}


char *wifi_sniffer_sigmode_type2str(int sig_mode_enum)
{
  switch(sig_mode_enum) {
    case 0: return "11bg";
    case 1: return "11n";
    case 3: return "11ac";
    default: return "unk";
  }
}


void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type)
{
  if (type != WIFI_PKT_MGMT) return;
  if (svy_lst_idx >= (DET_LST_MAX - 1)) return;

  wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
  wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
  wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

  survey_data *data = (survey_data *) malloc(sizeof(survey_data));
  data->version = 0;
  data->chan = ppkt->rx_ctrl.channel;
  data->rssi = ppkt->rx_ctrl.rssi;
  data->mcs = ppkt->rx_ctrl.mcs;
  data->sig_len = ppkt->rx_ctrl.sig_len;
  strcpy(data->ptype, wifi_sniffer_packet_type2str(type));
  strcpy(data->sig_mode, wifi_sniffer_sigmode_type2str(ppkt->rx_ctrl.sig_mode));
  sprintf(data->addr1, addr_fmt, hdr->addr1[0], hdr->addr1[1], hdr->addr1[2], hdr->addr1[3], hdr->addr1[4], hdr->addr1[5]);
  sprintf(data->addr2, addr_fmt, hdr->addr2[0], hdr->addr2[1], hdr->addr2[2], hdr->addr2[3], hdr->addr2[4], hdr->addr2[5]);
  sprintf(data->addr3, addr_fmt, hdr->addr3[0], hdr->addr3[1], hdr->addr3[2], hdr->addr3[3], hdr->addr3[4], hdr->addr3[5]);

  uint8_t *pld = ipkt->payload;
  for (int j = 0; j < FRAME_SZ; j++) {
    data->frame[j] = pld[j];
  }

  data->ssid[0] = '\0';
  int frame_len = ppkt->rx_ctrl.sig_len - sizeof(wifi_ieee80211_packet_t);
  int frame_ctl = ntohs(hdr->frame_ctrl);
  if ((frame_len > 0) && ((frame_ctl&0xFF00) == 0x8000)) {
    if ((pld[4] == 0) && (pld[5] > 0)) {
      for (int c = 0; c < pld[5]; c++) data->ssid[c] = pld[c + 6];
      data->ssid[pld[5]] = '\0';
    }
  }

  survey_recs[svy_lst_idx++] = data;
}


static mp_obj_t survey(mp_obj_t channel_obj, mp_obj_t duration_ms_obj) 
{
    uint8_t survey_chan = mp_obj_get_int(channel_obj);
    int duration_ms = mp_obj_get_int(duration_ms_obj);

    if (!started) startup();

    printf("Starting %d ms survey of channel %02d\n", duration_ms, survey_chan);
    svy_lst_idx = 0;
    esp_wifi_set_channel(survey_chan, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
    vTaskDelay(duration_ms / portTICK_PERIOD_MS);
    esp_wifi_set_promiscuous(false);
    printf("Survey complete\n");

    mp_obj_list_t *lst = MP_OBJ_TO_PTR(mp_obj_new_list(svy_lst_idx, NULL));
    for (int i = 0; i < svy_lst_idx; i++) {
      survey_data *r = survey_recs[i];
      mp_obj_t rec_dct = mp_obj_new_dict(NARGS);
      mp_obj_dict_store(rec_dct, mp_obj_new_str_via_qstr("version", 7), mp_obj_new_int(r->version));
      mp_obj_dict_store(rec_dct, mp_obj_new_str_via_qstr("ptype", 5), mp_obj_new_str_via_qstr(r->ptype, strlen(r->ptype)));
      mp_obj_dict_store(rec_dct, mp_obj_new_str_via_qstr("chan", 4), mp_obj_new_int(r->chan));
      mp_obj_dict_store(rec_dct, mp_obj_new_str_via_qstr("rssi", 4), mp_obj_new_int(r->rssi));
      mp_obj_dict_store(rec_dct, mp_obj_new_str_via_qstr("addr1", 5), mp_obj_new_str_via_qstr(r->addr1, strlen(r->addr1)));
      mp_obj_dict_store(rec_dct, mp_obj_new_str_via_qstr("addr2", 5), mp_obj_new_str_via_qstr(r->addr2, strlen(r->addr2)));
      mp_obj_dict_store(rec_dct, mp_obj_new_str_via_qstr("addr3", 5), mp_obj_new_str_via_qstr(r->addr3, strlen(r->addr3)));
      mp_obj_dict_store(rec_dct, mp_obj_new_str_via_qstr("mcs", 3), mp_obj_new_int(r->mcs));
      mp_obj_dict_store(rec_dct, mp_obj_new_str_via_qstr("sigmode", 7), mp_obj_new_str_via_qstr(r->sig_mode, strlen(r->sig_mode)));
      mp_obj_dict_store(rec_dct, mp_obj_new_str_via_qstr("ssid", 4), mp_obj_new_str_via_qstr(r->ssid, strlen(r->ssid)));
      mp_obj_dict_store(rec_dct, mp_obj_new_str_via_qstr("siglen", 6), mp_obj_new_int(r->sig_len));

      mp_obj_list_t *frame_obj = MP_OBJ_TO_PTR(mp_obj_new_list(FRAME_SZ, NULL));
      for (int e = 0; e < FRAME_SZ; e++) {
        frame_obj->items[e] = mp_obj_new_int(r->frame[e]);
      }
      mp_obj_dict_store(rec_dct, mp_obj_new_str_via_qstr("frame", 5), MP_OBJ_FROM_PTR(frame_obj));

      lst->items[i] = rec_dct;
      free(survey_recs[i]);
    }
    return MP_OBJ_FROM_PTR(lst);
}
static MP_DEFINE_CONST_FUN_OBJ_2(survey_obj, survey);


static const mp_rom_map_elem_t example_module_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR_survey), MP_ROM_PTR(&survey_obj) },
};
static MP_DEFINE_CONST_DICT(example_module_globals, example_module_globals_table);


const mp_obj_module_t cwifi_cmodule = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&example_module_globals,
};

MP_REGISTER_MODULE(MP_QSTR_cwifi, cwifi_cmodule);
