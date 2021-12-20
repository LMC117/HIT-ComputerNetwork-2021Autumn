// GBN_client.cpp : �������̨Ӧ�ó������ڵ㡣
// #include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>
#include <time.h>
#include <fstream>
#include <iostream>
#include <cmath>

using namespace std;

// #pragma comment(lib,"ws2_32.lib")

#define SERVER_PORT 12340     //�������ݵĶ˿ں�
#define SERVER_IP "127.0.0.1" // �������� IP ��ַ

const int BUFFER_LENGTH = 1026;
const int SEQ_SIZE = 20;       //���ն����кŸ�����Ϊ 1~20
const int SEND_WIND_SIZE = 10; //���ʹ��ڴ�СΪ 10��GBN ��Ӧ���� W + 1 <=N��W Ϊ���ʹ��ڴ�С��N Ϊ���кŸ�����

BOOL ack[SEQ_SIZE]; //�յ� ack �������Ӧ 0~19 �� ack
int curSeq;         //��ǰ���ݰ��� seq
int curAck;         //��ǰ�ȴ�ȷ�ϵ� ack
int totalPacket;    //��Ҫ���͵İ�����
int totalSeq;       //�ѷ��͵İ�������

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
    printf("************************************************\n");
    printf("|     -time to get current time                |\n");
    printf("|     -quit to exit client                     |\n");
    printf("|     -testgbn [X] [Y] to test the gbn         |\n");
    printf("|     -testgbn2 [X] [Y] to test the gbn        |\n");
    printf("************************************************\n");
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
bool seqIsAvailable()
{
    int step;
    step = curSeq - curAck;
    step = step >= 0 ? step : step + SEQ_SIZE;
    //���к��Ƿ��ڵ�ǰ���ʹ���֮��
    if (step >= SEND_WIND_SIZE)
    {
        return false;
    }
    if (ack[curSeq])
    {
        return true;
    }
    return false;
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
    printf("*****Time out\n");
    int index;
    for (int i = 0; i < SEND_WIND_SIZE; ++i)
    {
        index = (i + curAck) % SEQ_SIZE;
        ack[index] = TRUE;
    }

    int temp = curSeq - curAck;
    totalSeq -= temp > 0 ? temp : temp + SEQ_SIZE;
    curSeq = curAck;
    printf("*****Rensend from Packet %d\n\n", totalSeq);
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
    unsigned char index = (unsigned char)c - 1; //���кż�һ
    printf("Recv an ack of %d \n", index);
    // �ӽ��շ��յ���ȷ���յ������к�

    /*�ж����ݴ����Ƿ������ӻ��޸ĵ�*/
    if (curAck <= index)
    {
        for (int i = curAck; i <= index; ++i)
        {
            ack[i] = TRUE;
        }
        curAck = (index + 1) % SEQ_SIZE;
    }
    else
    {
        if (ack[index] == FALSE)
        {
            for (int i = curAck; i < SEQ_SIZE; ++i)
            {
                ack[i] = TRUE;
            }
            for (int i = 0; i <= index; ++i)
            {
                ack[i] = TRUE;
            }
            curAck = index + 1;
        }
    }
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
    //Ϊ�˲���������������ӣ�����ʹ�� -time ����ӷ������˻�õ�ǰ ʱ��
    //ʹ�� -testgbn [X] [Y] ���� GBN ����[X]��ʾ���ݰ���ʧ����
    //          [Y]��ʾ ACK ��������
    printTips();
    int ret;
    char cmd[128];

    int length = sizeof(SOCKADDR);

    float packetLossRatio = 0.2; // Ĭ�ϰ���ʧ�� 0.2
    float ackLossRatio = 0.2;    // Ĭ�� ACK ��ʧ�� 0.2
    //��ʱ����Ϊ������ӣ�����ѭ����������
    srand((unsigned)time(NULL));

    ZeroMemory(buffer, sizeof(buffer));
    //���������ݶ����ڴ�
    std::ifstream icin;
    icin.open("client_file.txt");
    icin.seekg(0, ios::end);
    int fileSize = (int)icin.tellg();
    icin.seekg(0, ios::beg);
    char data[fileSize + 1];
    icin.read(data, fileSize);
    data[fileSize] = 0;
    icin.close();
    totalPacket = ceil(sizeof(data) / 1024.0);
    printf("totalPacket is ��%d\n\n", totalPacket);
    for (int i = 0; i < SEQ_SIZE; ++i)
    {
        ack[i] = TRUE;
    }

    while (true)
    {
        gets(buffer);
        // printf("%s\n", buffer);
        ret = sscanf(buffer, "%s%f%f", &cmd, &packetLossRatio, &ackLossRatio);

        //��ʼ GBN ���ԣ�ʹ�� GBN Э��ʵ�� UDP �ɿ��ļ�����
        if (!strcmp(cmd, "-testgbn"))
        {
            printf("%s\n", "Begin to test GBN protocol, please don't abort the process");
            printf("The loss ratio of packet is %.2f, the loss ratio of ack is %.2f\n", packetLossRatio, ackLossRatio);
            int stage = 0;
            BOOL b;
            unsigned short seq;     //�������к�
            unsigned short recvSeq; //���մ��ڴ�СΪ 1����ȷ�ϵ����к�
            unsigned short waitSeq; //�ȴ������к�
            sendto(socketClient, "-testgbn", strlen("-testgbn") + 1, 0, (SOCKADDR *)&addrServer, sizeof(SOCKADDR));
            while (true)
            {
                //�ȴ� server �ظ����� UDP Ϊ����ģʽ
                recvfrom(socketClient, buffer, BUFFER_LENGTH, 0, (SOCKADDR *)&addrServer, &len);
                //////////////////////TODO
                if (strcmp(buffer, "Data Transfer Is Complete") == 0)
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
                        waitSeq = 1;
                    }
                    break;
                case 1: //�ȴ��������ݽ׶�
                    seq = (unsigned short)buffer[0];
                    //�����ģ����Ƿ�ʧ
                    b = lossInLossRatio(packetLossRatio);
                    printf("\nThe packet wished: %d\n", waitSeq - 1);
                    // ����ʧ
                    if (b)
                    {
                        printf("The packet with a seq of %d loss\n", seq - 1);
                        break;
                    }
                    // ��û�ж�ʧ
                    printf("recv a packet with a seq of %d\n", seq - 1);
                    //������ڴ��İ�����ȷ���գ�����ȷ�ϼ���
                    if (!(waitSeq - seq))
                    {
                        ++waitSeq;
                        if (waitSeq == 21)
                        {
                            waitSeq = 1;
                        }
                        //�������
                        // printf("\n\n\t%s\n\n",&buffer[1]);
                        buffer[0] = seq;
                        recvSeq = seq;
                        buffer[1] = '\0';
                    }
                    else
                    {
                        //�����ǰһ������û���յ�����ȴ� Seq Ϊ 1 �����ݰ��������򲻷��� ACK����Ϊ��û����һ����ȷ�� ACK��
                        if (!recvSeq)
                        {
                            continue;
                        }
                        buffer[0] = recvSeq;
                        buffer[1] = '\0';
                    }

                    // ACK �Ƿ�ʧ
                    b = lossInLossRatio(ackLossRatio);
                    if (b)
                    {
                        printf("The ack of %d loss\n", (unsigned char)buffer[0] - 1);
                        continue;
                    }
                    sendto(socketClient, buffer, 2, 0, (SOCKADDR *)&addrServer, sizeof(SOCKADDR));
                    printf("send a ack of %d\n", (unsigned char)buffer[0] - 1);
                    break;
                }
                Sleep(500);
            }
        }

        else if (!strcmp(cmd, "-testgbn2"))
        {

            for (int i = 0; i < SEQ_SIZE; ++i)
            {
                ack[i] = TRUE;
            }
            //���� gbn ���Խ׶�
            //���� server��server ���� 0 ״̬���� client ���� 205 ״̬�루server���� 1 ״̬��
            //server �ȴ� client �ظ� 200 ״̬�룬 ����յ� ��server ���� 2 ״̬�� ����ʼ�����ļ���������ʱ�ȴ�ֱ����ʱ
			//���ļ�����׶Σ�server ���ʹ��ڴ�С��Ϊ
            // ZeroMemory(buffer, sizeof(buffer));
            int recvSize;
            int waitCount = 0;
            printf("Begain to test GBN protocol, please don't abort the process\n");
            //������һ�����ֽ׶�
            //���ȷ�������ͻ��˷���һ�� 205 ��С��״̬�루���Լ�����ģ���ʾ������׼�����ˣ����Է�������
            //�ͻ����յ� 205 ֮��ظ�һ�� 200 ��С��״̬�룬��ʾ�ͻ��˱����ˣ����Խ���������
            //�������յ� 200 ״̬��֮�󣬾Ϳ�ʼʹ�� GBN ����������
            printf("Shake hands stage\n");
            int stage = 0;
            bool runFlag = true;

            sendto(socketClient, buffer, strlen(buffer) + 1, 0, (SOCKADDR *)&addrServer, sizeof(SOCKADDR));
            // sendto(socketClient, "-testgbn2", strlen("-testgbn2")+1, 0, (SOCKADDR*)&addrServer, sizeof(SOCKADDR));

            Sleep(100);
            recvfrom(socketClient, buffer, BUFFER_LENGTH, 0, ((SOCKADDR *)&addrServer), &length);
            // printf("\n%s\n\n", buffer);
            ZeroMemory(buffer, sizeof(buffer));
            int iMode = 1;                                            //1����������0������
            ioctlsocket(socketClient, FIONBIO, (u_long FAR *)&iMode); //����������
            while (runFlag)
            {
                switch (stage)
                {
                case 0: //���� 205 �׶�
                    buffer[0] = 205;
                    buffer[1] = '\0';
                    sendto(socketClient, buffer, strlen(buffer) + 1, 0, (SOCKADDR *)&addrServer, sizeof(SOCKADDR));
                    Sleep(100);
                    stage = 1;
                    break;
                case 1: //�ȴ����� 200 �׶Σ�û���յ��������+1����ʱ������˴Ρ����ӡ����ȴ��ӵ�һ����ʼ
                    recvSize = recvfrom(socketClient, buffer, BUFFER_LENGTH, 0, ((SOCKADDR *)&addrServer), &length);
                    if (recvSize < 0)
                    {
                        ++waitCount;
                        printf("recv: %d, waitCount: %d\n", recvSize, waitCount);
                        if (waitCount > 20)
                        {
                            runFlag = false;
                            printf("200 Timeout error\n");
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
                            printf("File size is %dB, each packet is 1024B  and packet total num is %d...\n\n", sizeof(data), totalPacket);
                            curSeq = 0;
                            curAck = 0;
                            totalSeq = 0;
                            waitCount = 0;
                            stage = 2;
                        }
                    }
                    break;
                case 2: //���ݴ���׶�

                    /*�ж����ݴ����Ƿ������ӻ��޸�*/
                    if (seqIsAvailable() && totalSeq < totalPacket)
                    { //totalSeq<=(totalPacket-1)��δ�������һ�����ݰ�
                        /*�ж����ݴ����Ƿ������ӻ��޸�*/

                        //���͸��ͻ��˵����кŴ� 1 ��ʼ
                        buffer[0] = curSeq + 1;
                        ack[curSeq] = FALSE;
                        //���ݷ��͵Ĺ�����Ӧ���ж��Ƿ������->���ڴ˴����Ѿ�ʵ����ok
                        //Ϊ�򻯹��̴˴���δʵ��->���ڴ˴����Ѿ�ʵ����ok
                        memcpy(&buffer[1], data + 1024 * totalSeq, 1024);
                        printf("send a packet with a seq of %d\n", curSeq);
                        sendto(socketClient, buffer, BUFFER_LENGTH, 0, (SOCKADDR *)&addrServer, sizeof(SOCKADDR));
                        ++curSeq;
                        curSeq %= SEQ_SIZE;
                        ++totalSeq;
                        Sleep(500);
                    }
                    //�ȴ� Ack����û���յ����򷵻�ֵΪ-1��������+1
                    recvSize = recvfrom(socketClient, buffer, BUFFER_LENGTH, 0, ((SOCKADDR *)&addrServer), &length);
                    if (recvSize < 0)
                    {
                        waitCount++;
                        //20 �εȴ� ack ��ʱ�ش�
                        if (waitCount > 20)
                        {
                            waitCount = 0;
                            timeoutHandler();
                            // printf("\t----totalSeq Now is : %d\n",totalSeq);
                        }
                    }
                    else
                    {
                        //�յ� ack
                        ackHandler(buffer[0]);
                        waitCount = 0;
                    }
                    Sleep(500);
                    break;
                }

                // �����꣬��֤�Ƿ���յ�ȫ��ACK
                if (totalSeq == totalPacket)
                {
                    BOOL isFinish = TRUE;
                    for (int i = 0; i < SEQ_SIZE; ++i)
                    {
                        if (ack[i] == FALSE)
                        {
                            isFinish = FALSE;
                        }
                    }
                    // �յ���ȫ��ACK����������źţ��˳����У�runFlag = false��
                    if (isFinish == TRUE)
                    {
                        // printf("Data Transfer Is Complete\n");
                        strcpy(buffer, "Data Transfer Is Complete");
                        sendto(socketClient, buffer, strlen(buffer) + 1, 0, (SOCKADDR *)&addrServer, sizeof(SOCKADDR));
                        // break;
                        totalSeq = 0;
                        runFlag = false;
                    }
                }
            }
            iMode = 0;                                                //1����������0������
            ioctlsocket(socketClient, FIONBIO, (u_long FAR *)&iMode); // ��������
        }

        // -time -quit �����
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