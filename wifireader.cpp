
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
        DeviceIoControl(        hDevice,
                                IOCTL_NDIS_QUERY_GLOBAL_STATS,
                                &oidcode,
                                sizeof( oidcode),
                                ( ULONG *) NULL,
                                0,
                                &bytesreturned,
                                NULL) ;

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
        char device_file[ SIZEOF_DEVICE_NAME];
		char key_name[ SIZEOF_DEVICE_NAME];
        char full_name[ SIZEOF_DEVICE_NAME];
        char device_info[ SIZEOF_DEVICE_NAME];
        char device_description[ SIZEOF_DEVICE_NAME];
		FILETIME file_time;
		HKEY hkey;
        int index;
        DWORD size;

        index = 0 ;
		if( RegOpenKeyExA(       HKEY_LOCAL_MACHINE,
                                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards",
                                0,
                                KEY_READ,
                                &hkey) == ERROR_SUCCESS)
			{
            size = SIZEOF_DEVICE_NAME ;

            while(  RegEnumKeyExA(   hkey,
                                        index,
                                        key_name,
                                        &size,
                                        NULL,
                                        NULL,
                                        NULL,
                                        &file_time) == ERROR_SUCCESS)
                {
                        sprintf(        full_name,
                                        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards\\%s",
                                        key_name) ;

                        get_device_info(        index,
                                                full_name,
                                                device_info,
                                                device_description) ;
						//if (!strcmp(device_description, "Gigabyte GN-WI06N (mini) PCI Express WLAN Card"))
						//	break;
						if (!strcmp(device_description, "NETGEAR WNA1100 N150 Wireless USB Adapter"))
							break;
						//if (!strcmp(device_description, "ORiNOCO 802.11bg ComboCard Gold"))
						//	break;
                        index++ ;
                        size = SIZEOF_DEVICE_NAME ;
                }

                RegCloseKey( hkey) ;
		}
		sprintf( device_file, "\\\\.\\%s", device_info) ;
        hDevice = CreateFileA(   device_file,
                                0,
                                FILE_SHARE_READ,
                                NULL,
                                OPEN_EXISTING,
                                0,
                                NULL) ;

		if( hDevice == INVALID_HANDLE_VALUE)
			{
			//fprintf(stderr,"invalid handle!!!\n");
            return false;
			}
        else
			return true;

}


void WiFiReader::captureLoop( void ) {

    // Declare and initialize variables.


    //int iRet = 0;
    //WCHAR GuidString[39] = {0};
    unsigned int i;

	while (!stopScanners) {
		BssidScan();
		time(&currTime);
		
		for (i = 0; i < m_pBSSIDList->NumberOfItems; i++) {
			int temp=i;
			char macaddress[64];
			NDIS_WLAN_BSSID_EX *bssInfo = (NDIS_WLAN_BSSID_EX *)(m_pBSSIDList->Bssid);
			while(temp!=0 ){
				bssInfo=(NDIS_WLAN_BSSID_EX *)((char*)bssInfo+ bssInfo->Length);
				temp--;
				}
			fprintf(fp,"%lu\t",(unsigned long)currTime);
			fprintf(fp,"%i\t",bssInfo->Configuration.BeaconPeriod);
			sprintf(macaddress,"%02X-%02X-%02X-%02X-%02X-%02X",(int*)bssInfo->MacAddress[0],(int*)bssInfo->MacAddress[1],
					(int*)m_pBSSIDList->Bssid[i].MacAddress[2],(int*)bssInfo->MacAddress[3],(int*)bssInfo->MacAddress[4],(int*)bssInfo->MacAddress[5]);
			
			int chan= bssInfo->Configuration.DSConfig;
						chan -=2407000;
						chan/=5000;
			
			fprintf(fp,"%s\t%i\t%i\t%s\n",macaddress, bssInfo->Rssi, chan, bssInfo->Ssid.Ssid);
			bssInfo = (NDIS_WLAN_BSSID_EX*)((char*)m_pBSSIDList->Bssid + bssInfo->Length);
			fingerprintsCapturedVal++;
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

	if(m_pBSSIDList !=NULL){
		::VirtualFree(m_pBSSIDList,sizeof( NDIS_802_11_BSSID_LIST) * MAX_BSSIDS,0);
		m_pBSSIDList =NULL;
	}
	CloseHandle(hDevice);
	fclose(fp);
	return 1;
}

int WiFiReader::fingerprintsCaptured() {
	return fingerprintsCapturedVal;
}

int WiFiReader::heartbeat() {
	return (int)currTime;
}
