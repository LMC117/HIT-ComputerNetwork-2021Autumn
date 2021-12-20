//#include "stdafx.h"
#include <stdio.h>
#include <Windows.h>
#include <process.h>
#include <string.h>
#include <tchar.h>
#include <fstream>
#include <map>
#include <string>

#include <iostream>
using namespace std;

#pragma comment(lib, "Ws2_32.lib")
#define MAXSIZE 65507 //�������ݱ��ĵ���󳤶�
#define HTTP_PORT 80  //http �������˿�

#define BANNED_WEB "http://today.hit.edu.cn/"		//������վ
#define PHISHING_WEB_SRC "http://jwc.hit.edu.cn/"	// ����ԭ��ַ
#define PHISHING_WEB_DEST "http://jwts.hit.edu.cn/" // ����Ŀ����ַ

//Http ͷ������
struct HttpHeader
{
	char method[4];			// POST ���� GET��ע����ЩΪ CONNECT����ʵ���ݲ�����
	char url[1024];			// ����� url
	char host[1024];		// Ŀ������
	char cookie[1024 * 10]; //cookie
	HttpHeader()
	{
		ZeroMemory(this, sizeof(HttpHeader));
	}
};

// �ṹ��cache
map<string, char *> cache;
struct HttpCache
{
	char url[1024];
	char host[1024];
	char last_modified[200];
	char status[4];
	char buffer[MAXSIZE];
	HttpCache()
	{
		ZeroMemory(this, sizeof(HttpCache)); // ��ʼ��cache
	}
};
HttpCache Cache[1024];
int cached_number = 0; //�Ѿ������url��
int last_cache = 0;	   //��һ�λ��������

BOOL InitSocket();
int ParseHttpHead(char *buffer, HttpHeader *httpHeader);
BOOL ConnectToServer(SOCKET *serverSocket, char *host);
unsigned int __stdcall ProxyThread(LPVOID lpParameter);
void ParseCache(char *buffer, char *status, char *last_modified);

//������ز���
SOCKET ProxyServer;
sockaddr_in ProxyServerAddr;
const int ProxyPort = 10240;

//�����µ����Ӷ�ʹ�����߳̽��д������̵߳�Ƶ���Ĵ����������ر��˷���Դ
//����ʹ���̳߳ؼ�����߷�����Ч��
//const int ProxyThreadMaxNum = 20;
//HANDLE ProxyThreadHandle[ProxyThreadMaxNum] = {0};
//DWORD ProxyThreadDW[ProxyThreadMaxNum] = {0};

struct ProxyParam
{
	SOCKET clientSocket;
	SOCKET serverSocket;
};

int main(int argc, char *argv[])
{
	printf("�����������������\n");
	printf("��ʼ��...\n");
	if (!InitSocket())
	{
		printf("socket ��ʼ��ʧ��\n");
		return -1;
	}
	printf("����������������У������˿� %d\n", ProxyPort);
	SOCKET acceptSocket = INVALID_SOCKET;
	SOCKADDR_IN acceptAddr;
	ProxyParam *lpProxyParam;
	HANDLE hThread;
	DWORD dwThreadID;

	//������������ϼ���
	while (true)
	{
		acceptSocket = accept(ProxyServer, (SOCKADDR *)&acceptAddr, NULL);

		lpProxyParam = new ProxyParam;
		if (lpProxyParam == NULL)
		{
			continue;
		}
		lpProxyParam->clientSocket = acceptSocket;
		hThread = (HANDLE)_beginthreadex(NULL, 0,
										 &ProxyThread, (LPVOID)lpProxyParam, 0, 0);
		CloseHandle(hThread);
		Sleep(200);
	}
	closesocket(ProxyServer);
	WSACleanup();
	return 0;
}

//************************************
// Method: InitSocket
// FullName: InitSocket
// Access: public
// Returns: BOOL
// Qualifier: ��ʼ���׽���
//************************************
BOOL InitSocket()
{
	//�����׽��ֿ⣨���룩
	WORD wVersionRequested;
	WSADATA wsaData;
	//�׽��ּ���ʱ������ʾ
	int err;
	//�汾 2.2
	wVersionRequested = MAKEWORD(2, 2);
	//���� dll �ļ� Socket ��
	err = WSAStartup(wVersionRequested, &wsaData);
	if (err != 0)
	{
		//�Ҳ��� winsock.dll
		printf("���� winsock ʧ�ܣ� �������Ϊ: %d\n", WSAGetLastError());
		return FALSE;
	}
	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
	{
		printf("�����ҵ���ȷ�� winsock �汾\n");
		WSACleanup();
		return FALSE;
	}
	ProxyServer = socket(AF_INET, SOCK_STREAM, 0); // ����һ��TCP/IPЭ��������׽���
	if (INVALID_SOCKET == ProxyServer)
	{
		printf("�����׽���ʧ�ܣ��������Ϊ��%d\n", WSAGetLastError());
		return FALSE;
	}
	ProxyServerAddr.sin_family = AF_INET;
	ProxyServerAddr.sin_port = htons(ProxyPort);
	// ProxyServerAddr.sin_addr.S_un.S_addr = INADDR_ANY;
	ProxyServerAddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1"); //ֻ�������û����ʷ�����

	if (bind(ProxyServer, (SOCKADDR *)&ProxyServerAddr, sizeof(SOCKADDR)) == SOCKET_ERROR)
	{
		printf("���׽���ʧ��\n");
		return FALSE;
	}
	if (listen(ProxyServer, SOMAXCONN) == SOCKET_ERROR)
	{
		printf("�����˿�%d ʧ��", ProxyPort);
		return FALSE;
	}
	return TRUE;
}

//************************************
// Method: ProxyThread
// FullName: ProxyThread
// Access: public
// Returns: unsigned int __stdcall
// Qualifier: �߳�ִ�к���
// Parameter: LPVOID lpParameter
//************************************
unsigned int __stdcall ProxyThread(LPVOID lpParameter)
{
	char Buffer[MAXSIZE];
	char sendBuffer[MAXSIZE];
	char phishBuffer[MAXSIZE];
	char *CacheBuffer;

	ZeroMemory(Buffer, MAXSIZE);
	ZeroMemory(sendBuffer, MAXSIZE);
	ZeroMemory(phishBuffer, MAXSIZE);

	SOCKADDR_IN clientAddr;
	int length = sizeof(SOCKADDR_IN);
	int recvSize;
	int ret;
	int Have_cache;

	//���տͻ��˵�����
	recvSize = recv(((ProxyParam *)lpParameter)->clientSocket, Buffer, MAXSIZE, 0);

	// Ϊ���ⱨjump to label 'error'�Ĵ��󣬽���ע��
	// if (recvSize <= 0)
	// {
	// 	goto error;
	// }

	HttpHeader *httpHeader = new HttpHeader();
	memcpy(sendBuffer, Buffer, recvSize);
	CacheBuffer = new char[recvSize + 1];
	ZeroMemory(CacheBuffer, recvSize + 1);
	memcpy(CacheBuffer, Buffer, recvSize);
	//ParseHttpHead(CacheBuffer, httpHeader);
	Have_cache = ParseHttpHead(CacheBuffer, httpHeader);
	delete CacheBuffer;

	if (!ConnectToServer(&((ProxyParam *)lpParameter)->serverSocket, httpHeader->host))
	{
		printf("������������ %s ʧ��\n", httpHeader->host);
		goto error;
	}
	printf("������������ %s �ɹ�\n", httpHeader->host);

	// ��վ����
	if (strcmp(httpHeader->url, BANNED_WEB) == 0)
	{
		printf("��վ %s �ѱ�����\n", BANNED_WEB);
		goto error;
	}

	//��վ����  ����jwc.hit.edu.cn  �ض���jwts.hit.edu.cn
	if (strstr(httpHeader->url, PHISHING_WEB_SRC) != NULL)
	{
		char *pr;
		int phishing_len;
		// ��ӡ��Ϣ
		printf("��վ %s �ѱ��ɹ��ض����� %s\n", PHISHING_WEB_SRC, PHISHING_WEB_DEST);
		// ���챨��
		char head1[] = "HTTP/1.1 302 Moved Temporarily\r\n";
		phishing_len = strlen(head1);
		memcpy(phishBuffer, head1, phishing_len);
		pr = phishBuffer + phishing_len;

		char head2[] = "Connection:keep-alive\r\n";
		phishing_len = strlen(head2);
		memcpy(pr, head2, phishing_len);
		pr += phishing_len;

		char head3[] = "Cache-Control:max-age=0\r\n";
		phishing_len = strlen(head3);
		memcpy(pr, head3, phishing_len);
		pr += phishing_len;

		//�ض���jwts.hit.edu.cn
		char phishing_dest[] = "Location: ";
		strcat(phishing_dest, PHISHING_WEB_DEST);
		strcat(phishing_dest, "\r\n\r\n");
		phishing_len = strlen(phishing_dest);
		memcpy(pr, phishing_dest, phishing_len);

		//��302���ķ��ظ��ͻ���
		ret = send(((ProxyParam *)lpParameter)->clientSocket, phishBuffer, sizeof(phishBuffer), 0);
		goto error;
	}

	//ʵ��cache����
	if (Have_cache) //�����ҳ���ڷ������л���
	{
		char cached_buffer[MAXSIZE];
		ZeroMemory(cached_buffer, MAXSIZE);
		memcpy(cached_buffer, Buffer, recvSize);

		//���컺��ı���ͷ
		char *pr = cached_buffer + recvSize;
		printf(",,");
		memcpy(pr, "If-modified-since: ", 19);
		pr += 19;
		int length = strlen(Cache[last_cache].last_modified);
		memcpy(pr, Cache[last_cache].last_modified, length);
		pr += length;

		//���ͻ��˷��͵� HTTP ���ݱ���ֱ��ת����Ŀ�������
		ret = send(((ProxyParam *)lpParameter)->serverSocket, cached_buffer, strlen(cached_buffer) + 1, 0);
		//�ȴ�Ŀ���������������
		recvSize = recv(((ProxyParam *)lpParameter)->serverSocket, cached_buffer, MAXSIZE, 0);
		if (recvSize <= 0)
		{
			goto error;
		}

		//��������������Ϣ��HTTP����ͷ
		CacheBuffer = new char[recvSize + 1];
		ZeroMemory(CacheBuffer, recvSize + 1);
		memcpy(CacheBuffer, cached_buffer, recvSize);

		char last_status[4];	//��¼�������ص�״̬��
		char last_modified[30]; //��¼����ҳ����޸�ʱ��
		ParseCache(CacheBuffer, last_status, last_modified);

		delete CacheBuffer;

		//����cache��״̬��
		if (strcmp(last_status, "304") == 0) //304״̬�룬�ļ�û�б��޸�
		{
			printf("ҳ��δ���޸�,����URL:%s\n", Cache[last_cache].url);
			//ֱ�ӽ���������ת�����ͻ���
			ret = send(((ProxyParam *)lpParameter)->clientSocket, Cache[last_cache].buffer, sizeof(Cache[last_cache].buffer), 0);
			if (ret != SOCKET_ERROR)
				printf("�ɻ��淢��\n");
		}
		else if (strcmp(last_status, "200") == 0) //200״̬�룬��ʾ�ļ��ѱ��޸�
		{
			//�����޸Ļ�������
			printf("ҳ�汻�޸�,����URL:%s\n", Cache[last_cache].url);
			memcpy(Cache[last_cache].buffer, cached_buffer, strlen(cached_buffer));
			memcpy(Cache[last_cache].last_modified, last_modified, strlen(last_modified));

			//��Ŀ����������ص�����ֱ��ת�����ͻ���
			ret = send(((ProxyParam *)lpParameter)->clientSocket, cached_buffer, sizeof(cached_buffer), 0);
			if (ret != SOCKET_ERROR)
				printf("�ɻ��淢�ͣ����޸�\n");
		}
	}
	else //û�л������ҳ��
	{
		//���ͻ��˷��͵� HTTP ���ݱ���ֱ��ת����Ŀ�������
		ret = send(((ProxyParam *)lpParameter)->serverSocket, Buffer, strlen(Buffer) + 1, 0);
		//�ȴ�Ŀ���������������
		recvSize = recv(((ProxyParam *)lpParameter)->serverSocket, Buffer, MAXSIZE, 0);
		if (recvSize <= 0)
		{
			goto error;
		}

		//����ҳ�滺�浽cache��

		//��Ŀ����������ص�����ֱ��ת�����ͻ���
		ret = send(((ProxyParam *)lpParameter)->clientSocket, Buffer, sizeof(Buffer), 0);
		if (ret != SOCKET_ERROR)
		{
			printf("���Է�����\n�ɹ����͸��ͻ��˵ı���(Ŀ����������ص�)buffer ret = %d \n", ret);
		}
	}
	//������
error:
	printf("�ر��׽���\n\n");
	Sleep(200);
	closesocket(((ProxyParam *)lpParameter)->clientSocket);
	closesocket(((ProxyParam *)lpParameter)->serverSocket);
	delete lpParameter;
	_endthreadex(0);
	return 0;
}

//*************************
//Method: ParseCache
//FullName: ParseCache
//Access: public
//Returns: void
//Qualifier: ���� TCP �����е� HTTP ͷ��,���Ѿ�cache���е�ʱ��ʹ��
//Parameter: char *buffer
//Parameter: char * status
//Parameter: HttpHeader *httpHeader
//*************************
void ParseCache(char *buffer, char *status, char *last_modified)
{
	char *p;
	char *ptr;
	const char *delim = "\r\n";
	p = strtok_s(buffer, delim, &ptr); //��ȡ��һ��
	memcpy(status, &p[9], 3);
	status[3] = '\0';
	p = strtok_s(NULL, delim, &ptr);
	while (p)
	{
		if (strstr(p, "Last-Modified") != NULL)
		{
			memcpy(last_modified, &p[15], strlen(p) - 15);
			break;
		}
		p = strtok_s(NULL, delim, &ptr);
	}
}

//*************************
//Method: ParseHttpHead
//FullName: ParseHttpHead
//Access: public
//Returns: int
//Qualifier: ���� TCP �����е� HTTP ͷ��
//Parameter: char *buffer
//Parameter: HttpHeader *httpHeader
//*************************
int ParseHttpHead(char *buffer, HttpHeader *httpHeader)
{
	int flag = 0; //���ڱ�ʾCache�Ƿ����У�����Ϊ1��������Ϊ0
	char *p;
	char *ptr;
	const char *delim = "\r\n"; //�س����з�
	p = strtok_s(buffer, delim, &ptr);
	if (p[0] == 'G')
	{ //GET��ʽ
		memcpy(httpHeader->method, "GET", 3);
		memcpy(httpHeader->url, &p[4], strlen(p) - 13);
		printf("url��%s\n", httpHeader->url); //url
		for (int i = 0; i < 1024; i++)
		{ //����cache������ǰ���ʵ�url�Ƿ��Ѿ�����cache����
			if (strcmp(Cache[i].url, httpHeader->url) == 0)
			{ //˵��url��cache���Ѿ�����
				flag = 1;
				break;
			}
		}
		if (!flag && cached_number != 1023) //˵��urlû����cache��cacheû����, �����urlֱ�Ӵ��ȥ
		{
			memcpy(Cache[cached_number].url, &p[4], strlen(p) - 13);
			last_cache = cached_number;
		}
		else if (!flag && cached_number == 1023) //˵��urlû����cache��cache����,�ѵ�һ��cache����
		{
			memcpy(Cache[0].url, &p[4], strlen(p) - 13);
			last_cache = 0;
		}
	}
	else if (p[0] == 'P') //POST��ʽ
	{
		memcpy(httpHeader->method, "POST", 4);
		memcpy(httpHeader->url, &p[5], strlen(p) - 14);
		for (int i = 0; i < 1024; i++)
		{
			if (strcmp(Cache[i].url, httpHeader->url) == 0)
			{
				flag = 1;
				break;
			}
		}
		if (!flag && cached_number != 1023)
		{
			memcpy(Cache[cached_number].url, &p[5], strlen(p) - 14);
			last_cache = cached_number;
		}
		else if (!flag && cached_number == 1023)
		{
			memcpy(Cache[0].url, &p[4], strlen(p) - 13);
			last_cache = 0;
		}
	}

	p = strtok_s(NULL, delim, &ptr);
	while (p)
	{
		switch (p[0])
		{
		case 'H': //HOST
			memcpy(httpHeader->host, &p[6], strlen(p) - 6);
			if (!flag && cached_number != 1023)
			{
				memcpy(Cache[last_cache].host, &p[6], strlen(p) - 6);
				cached_number++;
			}
			else if (!flag && cached_number == 1023)
			{
				memcpy(Cache[last_cache].host, &p[6], strlen(p) - 6);
			}
			break;
		case 'C': //Cookie
			if (strlen(p) > 8)
			{
				char header[8];
				ZeroMemory(header, sizeof(header));
				memcpy(header, p, 6);
				if (!strcmp(header, "Cookie"))
				{
					memcpy(httpHeader->cookie, &p[8], strlen(p) - 8);
				}
			}
			break;
			//case '':
		default:
			break;
		}
		p = strtok_s(NULL, delim, &ptr);
	}
	return flag;
}

//************************************
// Method: ConnectToServer
// FullName: ConnectToServer
// Access: public
// Returns: BOOL
// Qualifier: ������������Ŀ��������׽��֣�������
// Parameter: SOCKET * serverSocket
// Parameter: char * host
//************************************
BOOL ConnectToServer(SOCKET *serverSocket, char *host)
{
	sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(HTTP_PORT);
	HOSTENT *hostent = gethostbyname(host);
	if (!hostent)
	{
		return FALSE;
	}
	in_addr Inaddr = *((in_addr *)*hostent->h_addr_list);
	serverAddr.sin_addr.s_addr = inet_addr(inet_ntoa(Inaddr));
	*serverSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (*serverSocket == INVALID_SOCKET)
	{
		return FALSE;
	}
	if (connect(*serverSocket, (SOCKADDR *)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
	{
		closesocket(*serverSocket);
		return FALSE;
	}
	return TRUE;
}