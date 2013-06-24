typedef struct {
    unsigned short version : 2;
    unsigned short type : 2;
    unsigned short subtype : 4;
	unsigned short junk : 8;
} fc_type;

typedef struct  {
		fc_type wi_frameControl;
		u_int16_t wi_duration;
		u_int16_t wi_ra[3];
		u_int16_t wi_ta[3];
		u_int16_t bssid[3];
		u_int8_t fragnum;
		u_int8_t seqnum;
		u_int8_t fixed_params[12];
		u_int8_t tag_number;
		u_int8_t tag_length;
		//u_int8_t ssid[6];
	} rts_frame;

