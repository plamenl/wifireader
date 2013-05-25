#ifndef _WIFIREADER_H_
#define _WIFIREADER_H_

#include <windows.h>
#include <process.h>
#include <stdio.h>

#include <wlanapi.h>
#include <objbase.h>
#include <wtypes.h>

#include "winioctl.h"
#include "ntddndis.h"

// Need to link with Wlanapi.lib and Ole32.lib
#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")

//extern int stopScanners;		///< Global flag to know when to stop capturing scans.
static HANDLE wifiReaderHandle;		///< Global thread handle
static int WiFiReaderScanDone;

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
	static void captureCallback(WLAN_NOTIFICATION_DATA *wlanNotifData,VOID *p);
	
	/// @brief Shutdown wifi interface, any necesary cleanup.
	int disconnect();	

	/// @brief Returns the number of fingerprints captured. Negative value indicates error.
	int fingerprintsCaptured();	

	/// @brief Returns an integer which increments at a fixed rate (e.g. once per second/cycle). This will be monitored with a watchdog timer.
	int heartbeat();

	int fingerprintsCapturedVal;
	time_t currTime;

	HANDLE hClient;
	DWORD dwCurVersion;

	PWLAN_INTERFACE_INFO_LIST pIfList;
    PWLAN_INTERFACE_INFO pIfInfo;

    PWLAN_BSS_LIST pBssList;
    PWLAN_BSS_ENTRY pBssEntry;
	PWLAN_AVAILABLE_NETWORK_LIST pNetworkList;
	NDIS_802_11_BSSID_LIST* m_pBSSIDList;

	FILE *fp, *fp2;
};

#endif