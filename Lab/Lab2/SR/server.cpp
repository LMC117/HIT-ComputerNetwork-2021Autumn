//#include "stdafx.h" //���� VS ��Ŀ������Ԥ����ͷ�ļ�
#include <stdlib.h>
#include <time.h>
#include <WinSock2.h>
#include <fstream>
#include <iostream>
#include <cmath>

using namespace std;

// #pragma comment(lib,"ws2_32.lib")

#define SERVER_PORT 12340		//�˿ں�
#define SERVER_IP "0.0.0.0"		//IP ��ַ
const int BUFFER_LENGTH = 1026; //��������С�� ����̫���� UDP ������֡�а�����ӦС�� 1480 �ֽڣ�
const int SEND_WIND_SIZE = 10;	//���ʹ��ڴ�СΪ 10��GBN ��Ӧ���� W + 1 <=N��W Ϊ���ʹ��ڴ�С��N Ϊ���кŸ�����

//����ȡ���к� 0...19 �� 20 ��
//��������ڴ�С��Ϊ 1����Ϊͣ-��Э��
const int SEQ_SIZE = 20; //���кŵĸ������� 0~19 ���� 20 ��
const int SEQ_NUMBER = 9;

//���ڷ������ݵ�һ���ֽ����ֵΪ 0�� �����ݻᷢ��ʧ��
//��˽��ն����к�Ϊ 1~20���뷢�Ͷ�һһ��Ӧ
BOOL ack[SEQ_SIZE]; //�յ� ack �������Ӧ 0~19 �� ack
char dataBuffer[SEQ_SIZE][BUFFER_LENGTH];
int curSeq;		 //��ǰ���ݰ��� seq
int curAck;		 //��ǰ�ȴ�ȷ�ϵ� ack
int totalPacket; //��Ҫ���͵İ�����
int totalSeq;	 //�ѷ��͵İ�������
int totalAck;	 //ȷ���յ���ack���İ�������

//************************************
// Method: getCurTime
// FullName: getCurTime
// Access: public
// Returns: void
// Qualifier: ��ȡ��ǰϵͳʱ�䣬������� ptime ��
// Parameter: char * ptime
//************************************
void getCurTime(char *ptime)
{
	char buffer[128];
	memset(buffer, 0, sizeof(buffer));
	time_t c_time;
	struct tm *p;
	time(&c_time);
	p = localtime(&c_time);
	sprintf(buffer, "%d/%d/%d %d:%d:%d",
			p->tm_year + 1900,
			p->tm_mon + 1,
			p->tm_mday,
			p->tm_hour,
			p->tm_min,
			p->tm_sec);
	strcpy(ptime, buffer);
}

//************************************
// Method: seqIsAvailable
// FullName: seqIsAvailable
// Access: public
// Returns: bool
// Qualifier: ��ǰ���к� curSeq �Ƿ����
//************************************
int seqIsAvailable()
{
	int step;
	step = curSeq - curAck;
	step = step >= 0 ? step : step + SEQ_SIZE;
	//���к��Ƿ��ڵ�ǰ���ʹ���֮��
	if (step >= SEND_WIND_SIZE)
	{
		return 0;
	}
	if (!ack[curSeq])
	{ //ack[curSeq]==FALSE
		return 1;
	}
	return 2;
}

//************************************
// Method: timeoutHandler
// FullName: timeoutHandler
// Access: public
// Returns: void
// Qualifier: ��ʱ�ش������������������ڵ�����֡��Ҫ�ش�
//************************************
void timeoutHandler()
{
	printf("******Time out\n");

	if (totalSeq == totalPacket)
	{ //֮ǰ���͵������һ�����ݰ�
		if (curSeq > curAck)
		{
			totalSeq -= (curSeq - curAck);
		}
		else if (curSeq < curAck)
		{
			totalSeq -= (curSeq - curAck + 20);
		}
	}
	else
	{ //֮ǰû���͵����һ�����ݰ�
		totalSeq -= SEND_WIND_SIZE;
	}

	curSeq = curAck;
	printf("*****Rensend from Packet %d\n\n", totalSeq + 1);
}

//************************************
// Method: ackHandler
// FullName: ackHandler
// Access: public
// Returns: void
// Qualifier: �յ� ack���ۻ�ȷ�ϣ�ȡ����֡�ĵ�һ���ֽ�
//���ڷ�������ʱ����һ���ֽڣ����кţ�Ϊ 0��ASCII��ʱ����ʧ�ܣ���˼�һ�ˣ��˴���Ҫ��һ��ԭ
// Parameter: char c
//************************************
void ackHandler(char c)
{
	unsigned char index = (unsigned char)c - 1;	 //���кż�һ
	printf("Recv a ack of seq %d\n", index + 1); //�ӽ��շ��յ���ȷ���յ������к�
	int next;

	if (curAck == index)
	{
		totalAck += 1;
		ack[index] = FALSE;
		curAck = (index + 1) % SEQ_SIZE;
		for (int i = 1; i < SEQ_SIZE; i++)
		{
			next = (i + index) % SEQ_SIZE;
			if (ack[next] == TRUE)
			{
				ack[next] = FALSE;
				curAck = (next + 1) % SEQ_SIZE;
				totalSeq++;
				curSeq++;
				curSeq %= SEQ_SIZE;
			}
			else
			{
				break;
			}
		}
	}
	else if (curAck < index && index - curAck + 1 <= SEND_WIND_SIZE)
	{ //Ҫ��֤��Ҫ���ܵ���Ϣ���ڻ��������ڣ�
		if (!ack[index])
		{
			totalAck += 1;
			ack[index] = TRUE;
		}
	}
	else if (SEQ_SIZE + index - curAck + 1 <= SEND_WIND_SIZE && curAck > index)
	{ //Ҫ��֤��Ҫ���ܵ���Ϣ���ڻ��������ڣ�
		if (!ack[index])
		{
			totalAck += 1;
			ack[index] = TRUE;
		}
	}
}

//************************************
// ��ǰ�յ������к� recvSeq �Ƿ��ڿ��շ�Χ��
//************************************
BOOL seqRecvAvailable(int recvSeq)
{
	int step;
	int index;
	index = recvSeq - 1;
	step = index - curAck;
	step = step >= 0 ? step : step + SEQ_SIZE;
	//���к��Ƿ��ڵ�ǰ���ʹ���֮��
	if (step >= SEND_WIND_SIZE)
	{
		return FALSE;
	}
	return TRUE;
}

//������
int main(int argc, char *argv[])
{
	//�����׽��ֿ⣨���룩
	WORD wVersionRequested;
	WSADATA wsaData;
	//�׽��ּ���ʱ������ʾ
	int err;
	//�汾 2.2
	wVersionRequested = MAKEWORD(2, 2);
	//���� dll �ļ� Scoket ��
	err = WSAStartup(wVersionRequested, &wsaData);
	if (err != 0)
	{
		//�Ҳ��� winsock.dll
		printf("WSAStartup failed with error: %d\n", err);
		return -1;
	}
	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
	{
		printf("Could not find a usable version of Winsock.dll\n");
		WSACleanup();
	}
	else
	{
		printf("The Winsock 2.2 dll was found okay\n");
	}
	SOCKET sockServer = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	//�����׽���Ϊ������ģʽ
	int iMode = 1;											//1����������0������
	ioctlsocket(sockServer, FIONBIO, (u_long FAR *)&iMode); //����������
	SOCKADDR_IN addrServer;									//��������ַ
	//addrServer.sin_addr.S_un.S_addr = inet_addr(SERVER_IP);
	addrServer.sin_addr.S_un.S_addr = htonl(INADDR_ANY); //���߾���
	addrServer.sin_family = AF_INET;
	addrServer.sin_port = htons(SERVER_PORT);
	err = bind(sockServer, (SOCKADDR *)&addrServer, sizeof(SOCKADDR));
	if (err)
	{
		err = GetLastError();
		printf("Could not bind the port %d for socket. Error code is %d\n", SERVER_PORT, err);
		WSACleanup();
		return -1;
	}
	//��ʱ����Ϊ������ӣ�����ѭ����������
	srand((unsigned)time(NULL));
	SOCKADDR_IN addrClient; //�ͻ��˵�ַ
	int length = sizeof(SOCKADDR);
	char buffer[BUFFER_LENGTH]; //���ݷ��ͽ��ջ�����
	ZeroMemory(buffer, sizeof(buffer));
	//���������ݶ����ڴ�
	std::ifstream icin;
	icin.open("server_file.txt");
	icin.seekg(0, ios::end);
	int fileSize = (int)icin.tellg();
	icin.seekg(0, ios::beg);
	char data[fileSize + 1];
	icin.read(data, fileSize);
	data[fileSize] = 0;
	icin.close();
	totalPacket = ceil(sizeof(data) / 1024.0);
	printf("totalPacket is: %d\n\n", totalPacket);

	int recvSize;
	for (int i = 0; i < SEQ_SIZE; ++i)
	{
		ack[i] = FALSE;
	}
	while (true)
	{
		//���������գ���û���յ����ݣ�����ֵΪ-1
		recvSize = recvfrom(sockServer, buffer, BUFFER_LENGTH, 0, ((SOCKADDR *)&addrClient), &length);
		if (recvSize < 0)
		{
			Sleep(200);
			continue;
		}
		printf("recv from client: %s\n", buffer);
		if (strcmp(buffer, "-time") == 0)
		{
			getCurTime(buffer);
		}
		else if (strcmp(buffer, "-quit") == 0)
		{
			strcpy(buffer, "Good bye!");
		}
		else if (strcmp(buffer, "-testsr") == 0)
		{
			//���� gbn ���Խ׶�
			//���� server��server ���� 0 ״̬���� client ���� 205 ״̬�루server���� 1 ״̬��
			//server �ȴ� client �ظ� 200 ״̬�룬 ����յ� ��server ���� 2 ״̬�� ����ʼ�����ļ���������ʱ�ȴ�ֱ����ʱ
			//���ļ�����׶Σ�server ���ʹ��ڴ�С��Ϊ
			for (int i = 0; i < SEQ_SIZE; ++i)
			{
				ack[i] = FALSE;
			}
			ZeroMemory(buffer, sizeof(buffer));
			int recvSize;
			int waitCount = 0;
			printf("Begin to test SR protocol,please don't abort the process\n");
			//������һ�����ֽ׶�
			//���ȷ�������ͻ��˷���һ�� 205 ��С��״̬�루���Լ�����ģ���ʾ������׼�����ˣ����Է�������
			//�ͻ����յ� 205 ֮��ظ�һ�� 200 ��С��״̬�룬��ʾ�ͻ��˱����ˣ����Խ���������
			//�������յ� 200 ״̬��֮�󣬾Ϳ�ʼʹ�� GBN ����������
			printf("Shake hands stage\n");
			int stage = 0;
			bool runFlag = true;
			while (runFlag)
			{
				switch (stage)
				{
				case 0: //���� 205 �׶�
					buffer[0] = 205;
					sendto(sockServer, buffer, strlen(buffer) + 1, 0, (SOCKADDR *)&addrClient, sizeof(SOCKADDR));
					Sleep(100);
					stage = 1;
					break;
				case 1: //�ȴ����� 200 �׶Σ�û���յ��������+1����ʱ������˴Ρ����ӡ����ȴ��ӵ�һ����ʼ
					recvSize = recvfrom(sockServer, buffer, BUFFER_LENGTH, 0, ((SOCKADDR *)&addrClient), &length);
					if (recvSize < 0)
					{
						++waitCount;
						if (waitCount > 20)
						{
							runFlag = false;
							printf("Timeout error\n");
							break;
						}
						Sleep(500);
						continue;
					}
					else
					{
						if ((unsigned char)buffer[0] == 200)
						{
							printf("Begin a file transfer\n");
							printf("File size is %dB, each packet is 1024B  and packet total num is %d\n", sizeof(data), totalPacket);
							curSeq = 0;
							curAck = 0;
							totalSeq = 0;
							waitCount = 0;
							totalAck = 0;
							stage = 2;
						}
					}
					break;
				case 2: //���ݴ���׶�

					if (seqIsAvailable() == 1 && totalSeq <= (totalPacket - 1))
					{ //totalSeq<=(totalPacket-1)��δ�������һ�����ݰ�

						//���͸��ͻ��˵����кŴ� 1 ��ʼ
						buffer[0] = curSeq + 1;
						ack[curSeq] = FALSE;
						//���ݷ��͵Ĺ�����Ӧ���ж��Ƿ������
						memcpy(&buffer[1], data + 1024 * totalSeq, 1024);
						printf("send a packet with a seq of: %d \n", curSeq + 1);
						// printf("totalSeq now is: %d\n", totalSeq+1);
						sendto(sockServer, buffer, BUFFER_LENGTH, 0, (SOCKADDR *)&addrClient, sizeof(SOCKADDR));
						curSeq++;
						curSeq %= SEQ_SIZE;
						totalSeq++;
						Sleep(500);
					}
					else if (seqIsAvailable() == 2 && totalSeq <= (totalPacket - 1))
					{
						curSeq++;
						curSeq %= SEQ_SIZE;
						totalSeq++;
						break;
					}
					//�ȴ� Ack����û���յ����򷵻�ֵΪ-1��������+1
					recvSize = recvfrom(sockServer, buffer, BUFFER_LENGTH, 0, ((SOCKADDR *)&addrClient), &length);
					if (recvSize < 0)
					{
						waitCount++;
						//20 �εȴ� ack ��ʱ�ش�
						if (waitCount > 20)
						{
							timeoutHandler();
							waitCount = 0;
						}
					}
					else
					{
						//�յ� ack
						ackHandler(buffer[0]);
						waitCount = 0;

						if (totalAck == totalPacket)
						{ //���ݴ������
							printf("Data Transfer Complete\n");
							strcpy(buffer, "Data Transfer Complete\n");
							runFlag = false;
							break;
						}
					}
					Sleep(500);
					break;
				}
			}
		}

		sendto(sockServer, buffer, strlen(buffer) + 1, 0, (SOCKADDR *)&addrClient, sizeof(SOCKADDR));
		Sleep(500);
	}
	//�ر��׽��֣�ж�ؿ�
	closesocket(sockServer);
	WSACleanup();
	return 0;
}