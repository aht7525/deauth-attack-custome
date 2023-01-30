#include <stdio.h>
#include <stdint.h>

struct radio_header {
	uint8_t header_revision = 0x0;
	uint8_t header_pad = 0x0;
	uint16_t header_length = 0xc;
	uint32_t present_flag = 0x8004;
	uint16_t data_rate = 0x2;
	uint16_t tx_flag = 0x18;
	uint8_t subtype = 0xc0;
	uint8_t htc_flag = 0x0;
	uint16_t duration = 0x13a;	
} __attribute__((__packed__));

struct radio_body {
	uint8_t destination_address[6] = {0,};
	uint8_t source_address[6] = {0,};
	uint8_t bssid_address[6] = {0,};
	uint16_t sequence_number = 1496;
	uint16_t reason_code = 0x7;
} __attribute__((__packed__));

struct authenticate {
	uint16_t seq = 0x1;
	uint16_t status = 0x0;
} __attribute__((__packed__));

struct radio_frame {
	struct radio_header rh;
	struct radio_body rb;
} __attribute__((__packed__));

struct radio_frame_add_auth {
	struct radio_header rh;
        struct radio_body rb;
	struct authenticate auth;
} __attribute__((__packed__));
