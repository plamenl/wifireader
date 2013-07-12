

#include "wifireader.h"

using namespace std;
using namespace System;
using namespace System::Collections::Generic;

// Need to link with Wlanapi.lib and Ole32.lib
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "wpcap.lib")

extern int stopScanners;


int WiFiReader::FreqToChan(int in_freq) {
    int x = 0;
    // 80211b frequencies to channels

    while (IEEE80211Freq[x][1] != 0) {
        if (IEEE80211Freq[x][1] == in_freq) {
			fprintf(stderr,"Channel: %d\n", IEEE80211Freq[x][0]);
            return IEEE80211Freq[x][0];
        }
        x++;
    }
    return in_freq;
}
void WiFiReader::startCapture( void ) {
	 wifiReaderHandle = (HANDLE)_beginthread(WiFiReader::wifiReaderThread,0,this);	// Start thread
}
void WiFiReader::wifiReaderThread (void * p) {
	 WiFiReader* ps = (WiFiReader*)p;
	 ps->captureLoop();	// Start capture
	 return;
}

void WiFiReader::changeFreqThread (void * p) {
	 WiFiReader* ps = (WiFiReader*)p;
	 ps->changeFreq();
	 return;
}

void WiFiReader::changeFreq( void) {
	AirpcapChannelInfo *supported_channels;
	PAirpcapHandle curr_airpcap_handle;
	unsigned int num_channels=0;
	int curr_card = cardId;
	Dictionary<unsigned int, unsigned int> channels = gcnew Dictionary<unsigned int, unsigned int>();

	if (!curr_card)
		curr_airpcap_handle = airpcap_handle1;
	AirpcapGetDeviceSupportedChannels	(	curr_airpcap_handle,
											&supported_channels,
											(PUINT)&num_channels
										);	


	for (unsigned int x = 0, i = 0; x < num_channels; x++) {
		if (!channels.ContainsKey(supported_channels[x].Frequency))
			channels.Add(supported_channels[x].Frequency,x);
	}
	printf("\nCard is is: %d\n", curr_card);
	while (!stopScanners)
		{
		for each( KeyValuePair<unsigned int, unsigned int> kvp in channels )
			{

			//if (kvp.Key < 3000 && (kvp.Key != 2412 && kvp.Key != 2437 && kvp.Key != 2462))
			if (kvp.Key > 3000)
				continue;
			// skip the 4.9GHz channels
			if (kvp.Key > 4000 && kvp.Key < 5150)
				continue;

            printf("\nSetting channel for card %d: %d\n", curr_card, kvp.Key);
			if(!AirpcapSetDeviceChannelEx(curr_airpcap_handle, supported_channels[kvp.Value]))
				{
					fprintf(stderr,"Error setting the channel: %s\n", AirpcapGetLastError(curr_airpcap_handle));
					continue;
				}
			Sleep(102);
			}
		fingerprintsCapturedVal++;
		}
}

/*void WiFiReader::captureCallback(WLAN_NOTIFICATION_DATA *wlanNotifData,VOID *p)
{
	WiFiReaderScanDone = 1;
}*/

void WiFiReader::BssidScan(void) {
	ULONG oidcode;
	ULONG bytesreturned;
	char QueryBuffer[1024*30] = {0};
	m_pBSSIDList = ( NDIS_802_11_BSSID_LIST_EX *) VirtualAlloc(  NULL,
                                                        sizeof( NDIS_802_11_BSSID_LIST_EX ) * MAX_BSSIDS,
                                                        MEM_RESERVE | MEM_COMMIT,
                                                        PAGE_READWRITE) ;


	if( m_pBSSIDList == NULL) {
		fprintf(stderr,"Unable to allocate memory for bssids\n");
		}
	else {
        memset( m_pBSSIDList, 0, sizeof( NDIS_802_11_BSSID_LIST_EX) * MAX_BSSIDS) ;
        oidcode = OID_802_11_BSSID_LIST_SCAN ;
		if( hDevice == INVALID_HANDLE_VALUE)
        {
			   fprintf(stderr,"invalid handle!\n");
        }
        if (DeviceIoControl(        hDevice,
                                IOCTL_NDIS_QUERY_GLOBAL_STATS,
                                &oidcode,
                                sizeof( oidcode),
                                ( ULONG *) NULL,
                                0,
                                &bytesreturned,
                                NULL) == 0)
								fprintf(stderr,"scan error: %d\n", GetLastError());

        Sleep(3200);

        memset( m_pBSSIDList, 0, sizeof( NDIS_802_11_BSSID_LIST_EX) * MAX_BSSIDS) ;
        oidcode = OID_802_11_BSSID_LIST ;

        if( DeviceIoControl(    hDevice,
                                IOCTL_NDIS_QUERY_GLOBAL_STATS,
                                &oidcode,
                                sizeof( oidcode),
                                (LPVOID) &QueryBuffer[0],
								sizeof(QueryBuffer),
                                &bytesreturned,
                                NULL) == 0)
			  fprintf(stderr,"\nscan fail: %d\n", GetLastError());
        else {
			m_pBSSIDList = (NDIS_802_11_BSSID_LIST_EX*)QueryBuffer;
			fprintf(stderr,"\nbssids: %d\n", m_pBSSIDList->NumberOfItems);
			}
	}
}


bool WiFiReader::get_device_info(   int Index,
                        char *key_name,
                        char *device_info,
                        char *device_description)
{
        HKEY hkey ;
        DWORD size ;
        DWORD type ;
        BOOL retval ;

        retval = FALSE ;

      memset( device_info, 0, SIZEOF_DEVICE_NAME) ;

		if( RegOpenKeyExA(       HKEY_LOCAL_MACHINE,
                                key_name,
                                0,
                                KEY_READ,
                                &hkey) == ERROR_SUCCESS)
        {
                type = REG_SZ ;
                size = SIZEOF_DEVICE_NAME ;

                if( RegQueryValueExA(    hkey,
                                        "ServiceName",
                                        NULL,
                                        &type,
                                        ( BYTE *) device_info,
                                        &size) == ERROR_SUCCESS)
                {
                        type = REG_SZ ;
                        size = SIZEOF_DEVICE_NAME ;

                        if( RegQueryValueExA(    hkey,
                                                "Description",
                                                NULL,
                                                &type,
                                                ( BYTE *) device_description,
                                                &size) == ERROR_SUCCESS)
                        {
                                retval = TRUE ;
                        }
                }

                RegCloseKey( hkey) ;
        }

        return retval ;
}
bool WiFiReader::openDevice( void)
{
	//pcap_t *winpcap_adapter;
	pcap_if_t *alldevs, *d;
	//PAirpcapHandle airpcap_handle;
	char errbuf[PCAP_ERRBUF_SIZE];

	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
		return false;
	}



	/*for(d = alldevs; d; d=d->next)
		{
		if (!strcmp(d->name,"\\\\.\\airpcap00"))
			printf("%s\n",d->name);
		}*/
	d = alldevs;
	
	if((winpcap_adapter1 = pcap_open_live("\\\\.\\airpcap00",			// name of the device
		256,												// portion of the packet to capture. 
															// 65536 grants that the whole packet will be captured on all the MACs.
		0,													// promiscuous mode (nonzero means promiscuous)
		1,													// read timeout, in ms
		errbuf												// error buffer
		)) == NULL)
	{
		fprintf(stderr,"Error opening adapter with winpcap (%s)\n", errbuf);
		pcap_freealldevs(alldevs);
		return false;
	}

	if((winpcap_adapter2 = pcap_open_live("\\\\.\\airpcap01",			// name of the device
		256,												// portion of the packet to capture. 
															// 65536 grants that the whole packet will be captured on all the MACs.
		0,													// promiscuous mode (nonzero means promiscuous)
		1,													// read timeout, in ms
		errbuf												// error buffer
		)) == NULL)
	{
		fprintf(stderr,"Error opening adapter with winpcap (%s)\n", errbuf);
		//pcap_freealldevs(alldevs);
		//return false;
	}

	if((winpcap_adapter_multi = pcap_open_live("\\\\.\\airpcap_any",			// name of the device
		256,												// portion of the packet to capture. 
															// 65536 grants that the whole packet will be captured on all the MACs.
		0,													// promiscuous mode (nonzero means promiscuous)
		1,													// read timeout, in ms
		errbuf												// error buffer
		)) == NULL)
	{
		fprintf(stderr,"Error opening adapter with winpcap (%s)\n", errbuf);
		//pcap_freealldevs(alldevs);
		//return false;
	}

	//
	// Get the airpcap handle so we can change wireless-specific settings
	//
	airpcap_handle1 = pcap_get_airpcap_handle(winpcap_adapter1);
	airpcap_handle2 = pcap_get_airpcap_handle(winpcap_adapter2);
	airpcap_handle_multi = pcap_get_airpcap_handle(winpcap_adapter_multi);

	if(airpcap_handle1 == NULL)
	{
		fprintf(stderr,"This adapter doesn't have wireless extensions. Quitting\n");
		pcap_close(winpcap_adapter1);
		return false;
	}

	if(!AirpcapSetLinkType(airpcap_handle1, AIRPCAP_LT_802_11_PLUS_RADIO))
	{
		fprintf(stderr, "Error setting the link layer: %s\n", AirpcapGetLastError(airpcap_handle1));
		pcap_close(winpcap_adapter1);
		return false;
	}

	if(!AirpcapSetLinkType(airpcap_handle2, AIRPCAP_LT_802_11_PLUS_RADIO))
	{
		fprintf(stderr, "Error setting the link layer: %s\n", AirpcapGetLastError(airpcap_handle2));
		pcap_close(winpcap_adapter2);

	}

	pcap_freealldevs(alldevs);

}


void WiFiReader::captureLoop( void ) {

    // Declare and initialize variables.
	int res;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	ULONG RadioHdrLen;
	u_int32_t t_channel=0;
	u_int32_t t_change=0;
	radio_data rdata;
    unsigned int i;
	rts_frame captured_frame;
	

	//fprintf(stderr,"count is: %d\n",channels.Count);
	cardId = 0;
	_beginthread(WiFiReader::changeFreqThread,0,this);
	Sleep(10);
	cardId = 1;
	while (!stopScanners)
		{
		time(&currTime);
	 
		//printf("TIME TO CHANGE: %d\n", GetTickCount()-t_change);
		t_channel = GetTickCount();
		//printf("NEW CHAN: %d\n", t_channel);
		while((res = pcap_next_ex(winpcap_adapter_multi, &header, &pkt_data)) >= 0 && (GetTickCount()-t_channel < 80))
				{		
				//printf("TICK COUNT: %d\n", GetTickCount()-t_channel);
				if(res == 0)
					{
					// 
					// Timeout elapsed
					//
					continue;
					}

				//
				// print pkt timestamp and pkt len
				//
				//printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);			
				//
				// Print radio information
				//
				memset(&rdata,0,sizeof(rdata));
				RadioHdrLen = ::RadiotapGet(pkt_data, header->caplen, &rdata);

				//
				// The 802.11 packet follows the radio header
				//
				pkt_data += RadioHdrLen;

				//
				// Print the packet
				//
				//printf("\nPacket bytes:\n");
				memcpy((void *)&captured_frame, pkt_data,sizeof(captured_frame));
				pkt_data += sizeof(captured_frame);
				
				if (captured_frame.wi_frameControl.type || captured_frame.wi_frameControl.subtype != 8)
					continue;

				fprintf(fp, "%ld\t%ld\t%ld", header->ts.tv_sec, header->ts.tv_usec,currTime);
				fprintf(fp,"\t");
				for (int j = 0; j < 3; j++)
					{
					write_swapped_bytes(captured_frame.bssid[j], fp);
					if (j < 2)
						fprintf(fp,"-");
					}	
				fprintf(fp,"\t%d", rdata.signal_level);
				fprintf(fp,"\t%u", rdata.freq);
				if (!captured_frame.tag_number) 
					{
					fprintf(fp,"\t");
					
					for (UINT j = 0; j < captured_frame.tag_length; j++)
						{
						if (pkt_data[j])
							fprintf(fp,"%c",pkt_data[j]);
						}
					}
				fprintf(fp,"\n");		
				}

			if(res == -1)
				{
				printf("Error reading the packets: %s\n", pcap_geterr(winpcap_adapter_multi));
				}

  
		
	}
	
}


int WiFiReader::initialize() {
    // Declare and initialize variables.
	hClient = NULL;
	dwCurVersion = 0;
	
	DWORD dwResult = 0;
	DWORD dwMaxClient = 2;      // initial client version

	// Initialize status variables
	fingerprintsCapturedVal = 0;
	time(&currTime);
	WiFiReaderScanDone = 1;

	fopen_s(&fp,"wifiout.dat","w");	// can make this an input
	if (WiFiReader::openDevice())
		return 0;
	else
		return -1;
}

int WiFiReader::disconnect() {

	//
	// Close the libpcap handler. We don't need to close the AirPcap one, because 
	// pcap_close takes care of it.
	//
	pcap_close(winpcap_adapter1);
	pcap_close(winpcap_adapter2);
	pcap_close(winpcap_adapter_multi);
	fclose(fp);
	return 1;
}

int WiFiReader::fingerprintsCaptured() {
	return fingerprintsCapturedVal;
}

int WiFiReader::heartbeat() {
	return (int)currTime;
}
