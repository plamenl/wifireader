

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

	d = alldevs;

	if((winpcap_adapter = pcap_open_live(d->name,			// name of the device
		65536,												// portion of the packet to capture. 
															// 65536 grants that the whole packet will be captured on all the MACs.
		1,													// promiscuous mode (nonzero means promiscuous)
		1000,												// read timeout, in ms
		errbuf												// error buffer
		)) == NULL)
	{
		fprintf(stderr,"Error opening adapter with winpcap (%s)\n", errbuf);
		pcap_freealldevs(alldevs);
		return false;
	}

	//
	// Get the airpcap handle so we can change wireless-specific settings
	//
	airpcap_handle = pcap_get_airpcap_handle(winpcap_adapter);

	if(airpcap_handle == NULL)
	{
		fprintf(stderr,"This adapter doesn't have wireless extensions. Quitting\n");
		pcap_close(winpcap_adapter);
		return false;
	}

	if(!AirpcapSetLinkType(airpcap_handle, AIRPCAP_LT_802_11_PLUS_RADIO))
	{
		fprintf(stderr, "Error setting the link layer: %s\n", AirpcapGetLastError(airpcap_handle));
		pcap_close(winpcap_adapter);
		return false;
	}
	pcap_freealldevs(alldevs);

}


void WiFiReader::captureLoop( void ) {

    // Declare and initialize variables.


    //int iRet = 0;
    //WCHAR GuidString[39] = {0};
    unsigned int i;
	unsigned int num_channels=0;
	AirpcapChannelInfo *supported_channels;
	Dictionary<unsigned int, unsigned int> channels = gcnew Dictionary<unsigned int, unsigned int>();
	AirpcapGetDeviceSupportedChannels	(	airpcap_handle,
											&supported_channels,
											(PUINT)&num_channels
										);	


	for (unsigned int x = 0, i = 0; x < num_channels; x++) {
		if (!channels.ContainsKey(supported_channels[x].Frequency))
			channels.Add(supported_channels[x].Frequency,x);
	}

	fprintf(stderr,"count is: %d\n",channels.Count);

	 for each( KeyValuePair<unsigned int, unsigned int> kvp in channels )
        {
            Console::WriteLine("Key = {0}, Value = {1}",
                kvp.Key, kvp.Value);

			if(!AirpcapSetDeviceChannelEx(airpcap_handle, supported_channels[kvp.Value]))
				{
					fprintf(stderr,"Error setting the channel: %s\n", AirpcapGetLastError(airpcap_handle));
					continue;
				}

        }
	/*while (!stopScanners) {
		BssidScan();
		time(&currTime);
		
		for (i = 0; i < m_pBSSIDList->NumberOfItems; i++) {
			
			fingerprintsCapturedVal++;
			}
	}*/
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
	pcap_close(winpcap_adapter);
	fclose(fp);
	return 1;
}

int WiFiReader::fingerprintsCaptured() {
	return fingerprintsCapturedVal;
}

int WiFiReader::heartbeat() {
	return (int)currTime;
}
