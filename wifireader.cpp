
#include <windows.h>
#include <process.h>
#include <time.h>
#include "wifireader.h"
#include <objbase.h>
#include <wtypes.h>

#include <stdio.h>
#include <stdlib.h>

// Need to link with Wlanapi.lib and Ole32.lib
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

/*void WiFiReader::captureCallback(WLAN_NOTIFICATION_DATA *wlanNotifData,VOID *p)
{
	WiFiReaderScanDone = 1;
}*/

void WiFiReader::BssidScan(void) {
	ULONG oidcode;
	ULONG bytesreturned;

	m_pBSSIDList = ( NDIS_802_11_BSSID_LIST *) VirtualAlloc(  NULL,
                                                        sizeof( NDIS_802_11_BSSID_LIST) * MAX_BSSIDS,
                                                        MEM_RESERVE | MEM_COMMIT,
                                                        PAGE_READWRITE) ;

	if( m_pBSSIDList == NULL) {
		fprintf(stderr,"Unable to allocate memory for bssids\n");
		}
	else {
        memset( m_pBSSIDList, 0, sizeof( NDIS_802_11_BSSID_LIST) * MAX_BSSIDS) ;
        oidcode = OID_802_11_BSSID_LIST_SCAN ;
		if( hDevice == INVALID_HANDLE_VALUE)
        {
			   fprintf(stderr,"invalid handle!!!\n");
        }
        DeviceIoControl(        hDevice,
                                IOCTL_NDIS_QUERY_GLOBAL_STATS,
                                &oidcode,
                                sizeof( oidcode),
                                ( ULONG *) NULL,
                                0,
                                &bytesreturned,
                                NULL) ;

        Sleep(3000);

        memset( m_pBSSIDList, 0, sizeof( NDIS_802_11_BSSID_LIST) * MAX_BSSIDS) ;
        oidcode = OID_802_11_BSSID_LIST ;

        if( DeviceIoControl(    hDevice,
                                IOCTL_NDIS_QUERY_GLOBAL_STATS,
                                &oidcode,
                                sizeof( oidcode),
                                ( ULONG *) m_pBSSIDList,
                                sizeof( NDIS_802_11_BSSID_LIST) * MAX_BSSIDS,
                                &bytesreturned,
                                NULL) == 0)
        {
               // List failed
			  fprintf(stderr,"scan fail: %d\n", GetLastError());
        }
        else
        {

			 
			  fprintf(stderr,"scan success\n");
        }
	}
}

bool WiFiReader::openDevice( void)
{
        char device_file[ SIZEOF_DEVICE_NAME] ;
		FILE *fp;
		sprintf( device_file, "\\\\.\\%s", "{8BA93BA9-B159-414F-9442-03A33C418CB6}") ;
        hDevice = CreateFileA(   device_file,
                                0,
                                FILE_SHARE_READ,
                                NULL,
                                OPEN_EXISTING,
                                0,
                                NULL) ;

		if( hDevice == INVALID_HANDLE_VALUE)
        {
			   fprintf(stderr,"invalid handle!!!\n");
               return false;
        }
        else
        {
			ULONG oidcode;
			ULONG bytesreturned;
            oidcode = OID_802_11_RSSI ;
			NDIS_802_11_RSSI myrsi=0;
		if( hDevice == INVALID_HANDLE_VALUE)
        {
			   fprintf(stderr,"invalid handle!!!\n");
        }
			DeviceIoControl(        hDevice,
                                IOCTL_NDIS_QUERY_GLOBAL_STATS,
                                &oidcode,
                                sizeof( oidcode),
                                ( ULONG *) &myrsi,
                                sizeof( myrsi),
                                &bytesreturned,
                                NULL) ;   
			fprintf(stderr,"signal: %d\n", GetLastError());
			
			return true;

        }

}


void WiFiReader::captureLoop( void ) {

    // Declare and initialize variables.


    int iRet = 0;
    
    WCHAR GuidString[39] = {0};

    unsigned int i, j, k;

    /* variables used for WlanEnumInterfaces  */

   

    int iRSSI = 0;

	DWORD dwResult = 0;
	//m_airctl.list_devices();
	//NDIS_802_11_BSSID_LIST * pBSSIDList = m_airctl.scan();
	/*m_pBSSIDList = ( NDIS_802_11_BSSID_LIST *) VirtualAlloc(  NULL,
                                                        sizeof( NDIS_802_11_BSSID_LIST) * 100,
                                                        MEM_RESERVE | MEM_COMMIT,
                                                        PAGE_READWRITE) ;*/
	while (!stopScanners) {
		BssidScan();
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
	if (WiFiReader::openDevice())
		fprintf(stderr,"success opening\n");
	else
		return -1;
    /*dwResult = WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hClient);
    if (dwResult != ERROR_SUCCESS) {
        return -1;
    } else {
		return 0;
	}*/
}

int WiFiReader::disconnect() {

	if(m_pBSSIDList !=NULL){
		::VirtualFree(m_pBSSIDList,sizeof( NDIS_802_11_BSSID_LIST) * MAX_BSSIDS,0);
		m_pBSSIDList =NULL;
	}
	
	fclose(fp);
	fclose(fp2);
	return 1;
}

int WiFiReader::fingerprintsCaptured() {
	return fingerprintsCapturedVal;
}

int WiFiReader::heartbeat() {
	return (int)currTime;
}
