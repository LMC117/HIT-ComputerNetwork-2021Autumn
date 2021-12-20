#include <stdlib.h>
#include <WinSock2.h>
#include <time.h>
#include <fstream>

// #pragma comment(lib,"ws2_32.lib")

#define SERVER_PORT 12340	  //�������ݵĶ˿ں�
#define SERVER_IP "127.0.0.1" // �������� IP ��ַ
const int BUFFER_LENGTH = 1026;
const int SEND_WIND_SIZE = 10; //���ʹ��ڴ�СΪ 10��GBN ��Ӧ���� W + 1 <=N��W Ϊ���ʹ��ڴ�С��N Ϊ���кŸ�����
//����ȡ���к� 0...19 �� 20 ��
//��������ڴ�С��Ϊ 1����Ϊͣ-��Э��
const int SEQ_SIZE = 20; //���кŵĸ������� 0~19 ���� 20 ��
//���ڷ������ݵ�һ���ֽ����ֵΪ 0�� �����ݻᷢ��ʧ��
//��˽��ն����к�Ϊ 1~20���뷢�Ͷ�һһ��Ӧ
BOOL ack[SEQ_SIZE]; //�յ� ack �������Ӧ 0~19 �� ack
char dataBuffer[SEQ_SIZE][BUFFER_LENGTH];

int curSeq; //��ǰ���ݰ��� seq
int curAck; //��ǰ�ȴ�ȷ�ϵ� ack

/****************************************************************/
/*  -time �ӷ������˻�ȡ��ǰʱ��
    -quit �˳��ͻ���
    -testgbn [X] ���� GBN Э��ʵ�ֿɿ����ݴ���
            [X] [0,1] ģ�����ݰ���ʧ�ĸ���
            [Y] [0,1] ģ�� ACK ��ʧ�ĸ���
*/
/****************************************************************/
void printTips()
{
	printf("*****************************************\n");
	printf("| -time to get current time             |\n");
	printf("| -quit to exit client                  |\n");
	printf("| -testsr [X] [Y] to test the SR        |\n");
	printf("*****************************************\n");
}

//************************************
// Method:    lossInLossRatio
// FullName:  lossInLossRatio
// Access:    public
// Returns:   BOOL
// Qualifier: ���ݶ�ʧ���������һ�����֣��ж��Ƿ�ʧ,��ʧ�򷵻� TRUE�����򷵻� FALSE
// Parameter: float lossRatio [0,1]
//************************************
BOOL lossInLossRatio(float lossRatio)
{
	int lossBound = (int)(lossRatio * 100);
	int r = rand() % 101;
	if (r <= lossBound)
	{
		return TRUE;
	}
	return FALSE;
}

//************************************
// Method: seqIsAvailable
// FullName: seqIsAvailable
// Access: public
// Returns: bool
// Qualifier: ��ǰ���к� curSeq �Ƿ����
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
		return 1;
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
	SOCKET socketClient = socket(AF_INET, SOCK_DGRAM, 0);
	SOCKADDR_IN addrServer;
	addrServer.sin_addr.S_un.S_addr = inet_addr(SERVER_IP);
	addrServer.sin_family = AF_INET;
	addrServer.sin_port = htons(SERVER_PORT);
	//���ջ�����
	char buffer[BUFFER_LENGTH];
	ZeroMemory(buffer, sizeof(buffer));
	int len = sizeof(SOCKADDR);
	//Ϊ�˲���������������ӣ�����ʹ�� -time ����ӷ������˻�õ�ǰʱ��
	//ʹ�� -testsr [X] [Y] ���� SR ����[X]��ʾ���ݰ���ʧ����
	//  [Y]��ʾ ACK ��������
	printTips();
	int ret;
	char cmd[128];
	float packetLossRatio = 0.2; //Ĭ�ϰ���ʧ�� 0.2
	float ackLossRatio = 0.2;	 //Ĭ�� ACK ��ʧ�� 0.2
	//��ʱ����Ϊ������ӣ�����ѭ����������
	srand((unsigned)time(NULL));

	for (int i = 0; i < SEQ_SIZE; ++i)
	{
		ack[i] = FALSE;
	}
	while (true)
	{
		gets(buffer);
		ret = sscanf(buffer, "%s%f%f", &cmd, &packetLossRatio, &ackLossRatio);
		//��ʼ SR ���ԣ�ʹ�� SR Э��ʵ�� UDP �ɿ��ļ�����
		if (!strcmp(cmd, "-testsr"))
		{
			for (int i = 0; i < SEQ_SIZE; ++i)
			{
				ack[i] = FALSE;
			}
			printf("Begin to test SR protocol, please don't abort the process\n");
			printf("The loss ratio of packet is %.2f, the loss ratio of ack is %.2f\n", packetLossRatio, ackLossRatio);
			int stage = 0;
			BOOL b;
			curAck = 0;
			for (int i = 0; i < SEQ_SIZE; ++i)
			{
				ack[i] = FALSE;
			}
			unsigned short seq;		//�������к�
			unsigned short recvSeq; //���մ��ڴ�СΪ 1����ȷ�ϵ����к�
			int next;
			sendto(socketClient, "-testsr", strlen("-testsr") + 1, 0, (SOCKADDR *)&addrServer, sizeof(SOCKADDR));
			// ���浽�ļ�
			std::ofstream out_result;
			out_result.open("result.txt", std::ios::out | std::ios::trunc);
			if (!out_result.is_open())
			{
				printf("File Open Error.\n");
				continue;
			}

			while (true)
			{
				//�ȴ� server �ظ����� UDP Ϊ����ģʽ
				recvfrom(socketClient, buffer, BUFFER_LENGTH, 0, (SOCKADDR *)&addrServer, &len);

				if (!strcmp(buffer, "Data Transfer Is Complete\n"))
				{
					break;
				}

				switch (stage)
				{
				case 0: //�ȴ����ֽ׶�
					if ((unsigned char)buffer[0] == 205)
					{
						printf("Ready for file transmission\n");
						buffer[0] = 200;
						buffer[1] = '\0';
						sendto(socketClient, buffer, 2, 0, (SOCKADDR *)&addrServer, sizeof(SOCKADDR));
						stage = 1;
						recvSeq = 0;
					}
					break;
				case 1: //�ȴ��������ݽ׶�
					seq = (unsigned short)buffer[0];
					//�����ģ����Ƿ�ʧ
					b = lossInLossRatio(packetLossRatio);
					if (b)
					{
						printf("The packet with a seq of %d loss\n", seq);
						continue;
					}
					printf("recv a packet with a seq of %d\n", seq);
					//������ڴ��İ�����ȷ���գ�����ȷ�ϼ���
					if (seqRecvAvailable(seq))
					{
						recvSeq = seq;
						ack[seq - 1] = TRUE;
						ZeroMemory(dataBuffer[seq - 1], sizeof(dataBuffer[seq - 1]));
						strcpy(dataBuffer[seq - 1], &buffer[1]);
						buffer[0] = recvSeq;
						buffer[1] = '\0';
						int tempt = curAck;
						if (seq - 1 == curAck)
						{
							for (int i = 0; i < SEQ_SIZE; i++)
							{
								next = (tempt + i) % SEQ_SIZE;
								if (ack[next])
								{
									//�������
									// printf("\n%s\n", dataBuffer[next]);
									out_result << dataBuffer[next];
									curAck = (next + 1) % SEQ_SIZE;
									ack[next] = FALSE;
								}
								else
								{
									break;
								}
							}
						}
					}
					else
					{
						recvSeq = seq;
						buffer[0] = recvSeq;
						buffer[1] = '\0';
					}

					b = lossInLossRatio(ackLossRatio);
					if (b)
					{
						printf("The ack of %d loss\n", (unsigned char)buffer[0]);
						continue;
					}
					sendto(socketClient, buffer, 2, 0, (SOCKADDR *)&addrServer, sizeof(SOCKADDR));
					printf("send a ack of %d\n", (unsigned char)buffer[0]);
					break;
				}
				Sleep(500);
			}
			out_result.close();
		}

		sendto(socketClient, buffer, strlen(buffer) + 1, 0, (SOCKADDR *)&addrServer, sizeof(SOCKADDR));
		ret = recvfrom(socketClient, buffer, BUFFER_LENGTH, 0, (SOCKADDR *)&addrServer, &len);
		printf("%s\n", buffer);
		if (!strcmp(buffer, "Good bye!"))
		{
			break;
		}
		printTips();
	}
	//�ر��׽���
	closesocket(socketClient);
	WSACleanup();
	return 0;
}