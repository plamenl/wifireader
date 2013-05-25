
#include <windows.h>
#include <process.h>
#include <time.h>
#include "wifireader.h"
#include <wlanapi.h>
#include <objbase.h>
#include <wtypes.h>

#include <stdio.h>
#include <stdlib.h>

// Need to link with Wlanapi.lib and Ole32.lib
#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")

extern int stopScanners;

void WiFiReader::startCapture( void ) {
	 wifiReaderHandle = (HANDLE)_beginthread(WiFiReader::wifiReaderThread,0,this);	// Start thread
}
void WiFiReader::wifiReaderThread (void * p) {
	 WiFiReader* ps = (WiFiReader*)p;
	 ps->captureLoop();	// Start capture
	 return;
}

void WiFiReader::captureCallback(WLAN_NOTIFICATION_DATA *wlanNotifData,VOID *p)
{
	WiFiReaderScanDone = 1;
}
//	DWORD dwResult;
//	unsigned int j,k;
//    int iRSSI = 0;
//
//	if(wlanNotifData->NotificationCode == wlan_notification_acm_scan_fail) {
//		fprintf(stderr,"Scan Failed\n");
//		return;
//	}
//
//	dwResult = WlanGetNetworkBssList(hClient, 
//									&wlanNotifData->InterfaceGuid, 
//									NULL, 
//									dot11_BSS_type_any, // ignored
//									0, // ignored
//									NULL, 
//									&pBssList);
//	if (dwResult != ERROR_SUCCESS) {
//		fprintf(stderr,"WlanGetNewtorkBssList failed with error: %u\n", dwResult);
//	} else {
//		fprintf(stderr,"\t%i items",pBssList->dwNumberOfItems);
//		for (j = 0; j < pBssList->dwNumberOfItems; j++) {
//			pBssEntry = (WLAN_BSS_ENTRY *) & pBssList->wlanBssEntries[j];
//
//			//time
//			fprintf(fp,"%lu\t",(unsigned long)currTime);
//
//			//timestamps
//			fprintf(fp,"%llu\t%llu\t",pBssEntry->ullTimestamp,pBssEntry->ullHostTimestamp);
//
//			//beacon interval
//			fprintf(fp,"%u\t",pBssEntry->usBeaconPeriod);
//
//			// MAC address
//			for (k = 0; k < sizeof (pBssEntry->dot11Bssid); k++) {
//				if (k == 0)
//					fprintf(fp, "%.2X", pBssEntry->dot11Bssid[k]);
//				else
//					fprintf(fp, "-%.2X", pBssEntry->dot11Bssid[k]);
//			}
//
//			// RSSI
//			iRSSI = -100 + (pBssEntry->uLinkQuality/2);    	
//			fprintf(fp,"\t%u\t%i\t", pBssEntry->uLinkQuality, iRSSI);
//
//			//SSID
//			if (pBssEntry->dot11Ssid.uSSIDLength == 0)
//				fprintf(fp,"\t");
//			else {   
//				for (k = 0; k < pBssEntry->dot11Ssid.uSSIDLength; k++) {
//					fprintf(fp,"%c", (int) pBssEntry->dot11Ssid.ucSSID[k]);
//				}
//				fprintf(fp,"\t");
//			}
//
//			fprintf(fp,"\n");
//
//			fingerprintsCapturedVal++;
//		}
//	}
//	WlanFreeMemory(pBssList);
//
//}

void WiFiReader::captureLoop( void ) {

    // Declare and initialize variables.


    int iRet = 0;
    
    WCHAR GuidString[39] = {0};

    unsigned int i, j, k;

    /* variables used for WlanEnumInterfaces  */

    pIfList = NULL;
    pIfInfo = NULL;

    pBssList = NULL;
    pBssEntry = NULL;

	pNetworkList = NULL;

    int iRSSI = 0;

	DWORD dwResult = 0;

	while (!stopScanners) {
		dwResult = WlanEnumInterfaces(hClient, NULL, &pIfList);
		if (dwResult != ERROR_SUCCESS) {
			fprintf(stderr,"WlanEnumInterfaces failed with error: %u\n", dwResult);
			return;
		}

		for (i = 0; i < (int) pIfList->dwNumberOfItems; i++) {
			pIfInfo = (WLAN_INTERFACE_INFO *) &pIfList->InterfaceInfo[i];

			time(&currTime);
			//NdisGetCurrentSystemTime(&currTime);

			if (WiFiReaderScanDone) {

				dwResult = WlanGetAvailableNetworkList(hClient,
														&pIfInfo->InterfaceGuid,
														0, NULL, &pNetworkList);
				if (dwResult == ERROR_SUCCESS) {
					for (j = 0; j < pNetworkList->dwNumberOfItems; j++) { 
						fprintf(fp2, "stuff: %s\n", pNetworkList->Network->dot11Ssid);
						pNetworkList->dwIndex++;
						}
				}
				dwResult = WlanGetNetworkBssList(hClient, 
												&pIfInfo->InterfaceGuid, 
												NULL, 
												dot11_BSS_type_any, // ignored
												0, // ignored
												NULL, 
												&pBssList);
				if (dwResult != ERROR_SUCCESS) {
					fprintf(stderr,"WlanGetNewtorkBssList failed with error: %u\n", dwResult);
				} else {
					fprintf(stderr,"\t%i items",pBssList->dwNumberOfItems);
					for (j = 0; j < pBssList->dwNumberOfItems; j++) {
						pBssEntry = (WLAN_BSS_ENTRY *) & pBssList->wlanBssEntries[j];

						//time
						fprintf(fp,"%lu\t",(unsigned long)currTime);

						//timestamps
						fprintf(fp,"%llu\t%llu\t",pBssEntry->ullTimestamp,pBssEntry->ullHostTimestamp);

						//beacon interval
						fprintf(fp,"%u\t",pBssEntry->usBeaconPeriod);

						// MAC address
						for (k = 0; k < sizeof (pBssEntry->dot11Bssid); k++) {
							if (k == 0)
								fprintf(fp, "%.2X", pBssEntry->dot11Bssid[k]);
							else
								fprintf(fp, "-%.2X", pBssEntry->dot11Bssid[k]);
						}

						// RSSI
						iRSSI = -100 + (pBssEntry->uLinkQuality/2);    	
						fprintf(fp,"\t%u\t%i\t", pBssEntry->uLinkQuality, iRSSI);

						//SSID
						if (pBssEntry->dot11Ssid.uSSIDLength == 0)
							fprintf(fp,"\t");
						else {   
							for (k = 0; k < pBssEntry->dot11Ssid.uSSIDLength; k++) {
								fprintf(fp,"%c", (int) pBssEntry->dot11Ssid.ucSSID[k]);
							}
							fprintf(fp,"\t");
						}

						fprintf(fp,"\n");

						fingerprintsCapturedVal++;
					}
				}
				WlanFreeMemory(pBssList);

				dwResult = WlanScan(hClient,
									&pIfInfo->InterfaceGuid,
									NULL,
									NULL,
									NULL);
				if (dwResult != ERROR_SUCCESS) {
					fprintf(stderr,"WlanScan failed with error: %u\n", dwResult);
				}
				WlanRegisterNotification(hClient, 
										WLAN_NOTIFICATION_SOURCE_ACM, 
										FALSE,
										(WLAN_NOTIFICATION_CALLBACK)captureCallback, 
										NULL, 
										NULL, 
										NULL);
				WiFiReaderScanDone = 0;
			}
		}
		Sleep(50);
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
	fopen_s(&fp2,"debug.dat","w");
    dwResult = WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hClient);
    if (dwResult != ERROR_SUCCESS) {
        return -1;
    } else {
		return 0;
	}
}

int WiFiReader::disconnect() {
	DWORD dwResult = 0;
		dwResult = WlanCloseHandle(hClient, NULL);
    if (dwResult != ERROR_SUCCESS) {
        return -1;
    } else {
		return 0;
	}
	fclose(fp);
	fclose(fp2);
}

int WiFiReader::fingerprintsCaptured() {
	return fingerprintsCapturedVal;
}

int WiFiReader::heartbeat() {
	return (int)currTime;
}
