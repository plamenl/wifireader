#include "wifireader.h"

int stopScanners;

int main()
{
	stopScanners = 0;
	int dummyVar = 0;
	
	WiFiReader w;
	w.initialize(1);
	w.startCapture();
	for (int i = 0; i < 150; i++) {
		Sleep(200);
		//fprintf(stderr,"\n[%i] heartbeat = %i, fingerprintsCaptured = %i",
		//i,w.heartbeat(),w.fingerprintsCaptured());
	}
	stopScanners = 1;
	w.disconnect();
	return 0;
}