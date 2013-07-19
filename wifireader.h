#ifndef _WIFIREADER_H_
#define _WIFIREADER_H_

#include <pcap.h>
#include <airpcap.h>

#include <objbase.h>
#include <wtypes.h>

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <stddef.h> 
#include <process.h>
#include <time.h>

#include "winioctl.h"
#include "ntddndis.h"
#include "util.h"
#include "80211_dissect.h"

// Need to link with Wlanapi.lib and Ole32.lib
#pragma comment(lib, "ole32.lib")


#define LINE_LEN 16
//extern int stopScanners;		///< Global flag to know when to stop capturing scans.
static HANDLE wifiReaderHandle;		///< Global thread handle
static int WiFiReaderScanDone;

ULONG RadiotapGet(const u_char *p, ULONG caplen, radio_data *rdata);

class WiFiReader {
public:
	/// @brief Setup wifi for capture - negative return values indicate error. 0 is normal status.
	int initialize();

	/// @brief Starts scan capture by launching the thread for captureLoop().
	void startCapture( void );

	/// @brief The special form for the _beginthread call. Only for launching the capture thread. 
	static void wifiReaderThread (void * p);
	
	/// @brief The actual scan capture loop where everything is done.
	void captureLoop( void );
	//static void captureCallback(WLAN_NOTIFICATION_DATA *wlanNotifData,VOID *p);
	
	void changeFreq( void); 
	static void changeFreqThread (void * p);

	/// @brief Shutdown wifi interface, any necesary cleanup.
	int disconnect();	

	/// @brief Returns the number of fingerprints captured. Negative value indicates error.
	int fingerprintsCaptured();	

	/// @brief Returns an integer which increments at a fixed rate (e.g. once per second/cycle). This will be monitored with a watchdog timer.
	int heartbeat();

	int FreqToChan(int in_freq);
	pcap_t *winpcap_adapter1, *winpcap_adapter2, *winpcap_adapter3, *winpcap_adapter_multi;
	PAirpcapHandle airpcap_handle_multi, airpcap_handle1, airpcap_handle2, airpcap_handle3;

	bool openDevice(void);
	int fingerprintsCapturedVal;
	time_t currTime;
	FILE *fp;
	int cardId;

};

#endif