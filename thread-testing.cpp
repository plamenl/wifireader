#include <windows.h>
#include <process.h>
#include <stdio.h>
#include <objbase.h>
#include <wtypes.h>

#include "winioctl.h"
#include "ntddndis.h"

//#include "dummy-header.h"

int stopScanners;

int main()
{
	stopScanners = 0;
	int dummyVar = 0;
	char device_file[ 256] ;
		FILE *fp;
		sprintf( device_file, "\\\\.\\%s", "{892BA347-821A-4A14-9410-9712BB551A52}") ;
											
        HANDLE hDevice = CreateFileA(device_file,
								GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                NULL,
                                OPEN_EXISTING,
                                0,
                                NULL);
			
			
			/*CreateFileA(   device_file,
                               GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                NULL,
                                OPEN_EXISTING,
                                0,
                                INVALID_HANDLE_VALUE   ) ;*/

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
		
			DeviceIoControl(        hDevice,
                                IOCTL_NDIS_QUERY_GLOBAL_STATS,
                                &oidcode,
                                sizeof( oidcode),
                                ( ULONG *) &myrsi,
                                sizeof( myrsi),
                                &bytesreturned,
                                NULL) ;   
			fprintf(stderr,"signal: %d\n", myrsi);
			Sleep(10000);
		}
	/*WiFiReader w;
	w.initialize();
	w.startCapture();
	for (int i = 0; i < 150 ; i++) {
		Sleep(200);
		fprintf(stderr,"\n[%i] heartbeat = %i, fingerprintsCaptured = %i",
		i,w.heartbeat(),w.fingerprintsCaptured());
	}
	stopScanners = 1;
	w.disconnect();*/
	return 0;
}