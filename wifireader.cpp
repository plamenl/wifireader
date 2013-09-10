

#include "wifireader.h"

using namespace System;
using namespace System::Collections::Generic;

// Need to link with Wpcap.lib and Ole32.lib
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "wpcap.lib")

extern int stopScanners;



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

void WiFiReader::setFreq(int cardNum) {
	PAirpcapHandle curr_airpcap_handle;
	AirpcapChannelInfo *supported_channels;
	unsigned int num_channels=0;

	if (!cardNum)
		curr_airpcap_handle = airpcap_handle1;
	else if (cardNum == 1)
		curr_airpcap_handle = airpcap_handle2;
	else
		curr_airpcap_handle = airpcap_handle3;

	AirpcapGetDeviceSupportedChannels	(	curr_airpcap_handle,
											&supported_channels,
											(PUINT)&num_channels
										);	
	for (unsigned int x = 0, i = 0; x < num_channels; x++) {
		if (
			(!cardNum && supported_channels[x].Frequency == 2412) ||
			   (cardNum == 1 && supported_channels[x].Frequency == 2437) ||
			   (cardNum == 2 && supported_channels[x].Frequency == 2462)
			)
			AirpcapSetDeviceChannelEx(curr_airpcap_handle, supported_channels[x]);
				
		}
	}

void WiFiReader::changeFreq( void) {
	AirpcapChannelInfo *supported_channels;
	PAirpcapHandle curr_airpcap_handle;
	unsigned int num_channels=0;
	int curr_card = cardId;
	Dictionary<unsigned int, unsigned int> channels = gcnew Dictionary<unsigned int, unsigned int>();
	printf("\nCard is: %d\n", curr_card);

	if (!curr_card)
		curr_airpcap_handle = airpcap_handle1;
	else if (curr_card == 1)
		curr_airpcap_handle = airpcap_handle2;
	else
		curr_airpcap_handle = airpcap_handle3;

	AirpcapGetDeviceSupportedChannels	(	curr_airpcap_handle,
											&supported_channels,
											(PUINT)&num_channels
										);	

	for (unsigned int x = 0, i = 0; x < num_channels; x++) {
		if (!channels.ContainsKey(supported_channels[x].Frequency)
			&& supported_channels[x].Frequency != 2467
			&& supported_channels[x].Frequency != 2472
			&& supported_channels[x].Frequency != 2484
			&& supported_channels[x].Frequency != 5190
			&& supported_channels[x].Frequency != 5210
			&& supported_channels[x].Frequency != 5230
			&& supported_channels[x].Frequency != 5600
			&& supported_channels[x].Frequency != 5620
			&& supported_channels[x].Frequency != 5640
			)
			{
			channels.Add(supported_channels[x].Frequency,x);
			//printf("%d %ld %ld\n",curr_card, supported_channels[x].Frequency, x);
			}
	}
	
	while (!stopScanners)
		{
		for each( KeyValuePair<unsigned int, unsigned int> kvp in channels )
			{
			if (stopScanners)
				break;
			// skip the 4.9GHz channels
			if (kvp.Key > 4000 && kvp.Key < 5180)
				continue;

			// only channels 1, 6, 11 in 2.4GHz
			if (kvp.Key < 3000 && (kvp.Key != 2412 && kvp.Key != 2437 && kvp.Key != 2462))
				continue;
			if (!curr_card && kvp.Key > 5260 && multiCard)
				continue;
			else if (curr_card == 1 && (kvp.Key < 5280 || kvp.Key > 5580))
				continue;
			else if (curr_card == 2 && kvp.Key < 5660)
				continue;
			//printf("Setting channel for card %d: %d\n", curr_card, kvp.Key);
            //fprintf(fp,"Setting channel for card %d: %d\n", curr_card, kvp.Key);
			if (kvp.Key == 5660 && multiCard)
				time(&(this->currTime));
			else if (kvp.Key == 5825)
				time(&(this->currTime));

			if(!AirpcapSetDeviceChannelEx(curr_airpcap_handle, supported_channels[kvp.Value]))
				{
					fprintf(stderr,"Error setting the channel: %s\n", AirpcapGetLastError(curr_airpcap_handle));
					continue;
				}
			Sleep(102);

			}
		fingerprintsCapturedVal++;
		printf("In card %d fingerprints -> %d\n", curr_card, fingerprintsCapturedVal);
		}
}






bool WiFiReader::openDevice( void)
{
	pcap_if_t *alldevs, *d;
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
		0,												// portion of the packet to capture. 
															// 65536 grants that the whole packet will be captured on all the MACs.
		0,													// promiscuous mode (nonzero means promiscuous)
		1,													// read timeout, in ms
		errbuf												// error buffer
		)) == NULL)
	{
		//fprintf(stderr,"Error opening adapter with winpcap (%s)\n", errbuf);
		pcap_freealldevs(alldevs);
		return false;
	}
	if (multiCard) 
		{
		if((winpcap_adapter2 = pcap_open_live("\\\\.\\airpcap01",			// name of the device
			0,												// portion of the packet to capture. 
																// 65536 grants that the whole packet will be captured on all the MACs.
			0,													// promiscuous mode (nonzero means promiscuous)
			1,													// read timeout, in ms
			errbuf												// error buffer
			)) == NULL)
			{
			fprintf(stderr,"Error opening adapter with winpcap (%s)\n", errbuf);
		
			}

		if((winpcap_adapter3 = pcap_open_live("\\\\.\\airpcap02",			// name of the device
			0,												// portion of the packet to capture. 
																// 65536 grants that the whole packet will be captured on all the MACs.
			0,													// promiscuous mode (nonzero means promiscuous)
			1,													// read timeout, in ms
			errbuf												// error buffer
			)) == NULL)
			{
			fprintf(stderr,"Error opening adapter with winpcap (%s)\n", errbuf);
			}

		if((winpcap_adapter_multi = pcap_open_live("\\\\.\\airpcap_any",			// name of the device
			0,												// portion of the packet to capture. 
																// 65536 grants that the whole packet will be captured on all the MACs.
			0,													// promiscuous mode (nonzero means promiscuous)
			1,													// read timeout, in ms
			errbuf												// error buffer
			)) == NULL)
			{	
			printf("Error opening adapter with winpcap (%s)\n", errbuf);
			pcap_freealldevs(alldevs);
			return false;
			}
		airpcap_handle2 = pcap_get_airpcap_handle(winpcap_adapter2);
		airpcap_handle3 = pcap_get_airpcap_handle(winpcap_adapter3);
		airpcap_handle_multi = pcap_get_airpcap_handle(winpcap_adapter_multi);
		if(!AirpcapSetLinkType(airpcap_handle2, AIRPCAP_LT_802_11_PLUS_RADIO))
			{
			fprintf(stderr, "Error setting the link layer: %s\n", AirpcapGetLastError(airpcap_handle2));
			pcap_close(winpcap_adapter2);
			}

		if(!AirpcapSetLinkType(airpcap_handle3, AIRPCAP_LT_802_11_PLUS_RADIO))
			{
			fprintf(stderr, "Error setting the link layer: %s\n", AirpcapGetLastError(airpcap_handle3));
			pcap_close(winpcap_adapter3);
			}
		}
	//
	// Get the airpcap handle so we can change wireless-specific settings
	//
	airpcap_handle1 = pcap_get_airpcap_handle(winpcap_adapter1);
	

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
	AirpcapChannelInfo *supported_channels;
	unsigned int num_channels=0;
	pcap_t *used_adapter;

	used_adapter = winpcap_adapter1;
	fopen_s(&fp,"wifiout.dat","wb");
	time(&currTime);
	//fprintf(stderr,"count is: %d\n",channels.Count);
	//printf("Starting threads\n");
	cardId = 0;
	//_beginthread(WiFiReader::changeFreqThread,0,this);
	
	if (multiCard)
		{
		/*Sleep(40);
		cardId = 1;
		_beginthread(WiFiReader::changeFreqThread,0,this);
		Sleep(40);
		cardId = 2;
		_beginthread(WiFiReader::changeFreqThread,0,this);*/
		setFreq(0); setFreq(1); setFreq(2);
		used_adapter = winpcap_adapter_multi;
		}
	//printf("Threads started\n");
	Sleep(100);

	while (!stopScanners)
		{
		
		while((res = pcap_next_ex(used_adapter, &header, &pkt_data)) >= 0 )
				{		
				if (stopScanners)
					break;
				if(res == 0)
					{
					// 
					// Timeout elapsed
					//
					continue;
					}

				//Increase timestamp every 2 seconds
				time_t newTime;
				time(&newTime);
				if (difftime(newTime,this->currTime) > 0) {
					this->currTime = newTime;
					fingerprintsCapturedVal++;
					}
				// Read radio information
				//
				memset(&rdata,0,sizeof(rdata));
				RadioHdrLen = ::RadiotapGet(pkt_data, header->caplen, &rdata);

				//
				// The 802.11 packet follows the radio header
				//
				pkt_data += RadioHdrLen;

				memcpy((void *)&captured_frame, pkt_data,sizeof(captured_frame));
				pkt_data += sizeof(captured_frame);

				//Only interested in beacons
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
					// Get the SSID from the first tag.
					for (UINT j = 0; j < captured_frame.tag_length; j++)
						{
						int test_byte = pkt_data[j];
						if (pkt_data[j] && test_byte < 128 && test_byte >= 32)
							fprintf(fp,"%c",pkt_data[j]);
						}
					}
		
				fprintf(fp,"\n");		
				}

			/*if(res == -1)
				{
				//printf("Error reading the packets: %s\n", pcap_geterr(winpcap_adapter_multi));
				}*/

  
		
	}
	if (this->fp)
		fclose(this->fp);
	
}


int WiFiReader::initialize(int mode) {
	// Initialize status variables
	fingerprintsCapturedVal = 0;
	time(&currTime);
	WiFiReaderScanDone = 1;

	if (mode)
		multiCard = false;
	else
		multiCard = true;
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
	if (multiCard) {
		pcap_close(winpcap_adapter2);
		pcap_close(winpcap_adapter3);
	}
	//pcap_close(winpcap_adapter_multi);
	//if (fp)
	//	fclose(fp);
	return 1;
}

int WiFiReader::fingerprintsCaptured() {
	return fingerprintsCapturedVal;
}

int WiFiReader::heartbeat() {
	return (int)currTime;
}
