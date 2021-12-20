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
#define MAXSIZE 65507 //发送数据报文的最大长度
#define HTTP_PORT 80  //http 服务器端口

#define BANNED_WEB "http://today.hit.edu.cn/"		//屏蔽网站
#define PHISHING_WEB_SRC "http://jwc.hit.edu.cn/"	// 钓鱼原网址
#define PHISHING_WEB_DEST "http://jwts.hit.edu.cn/" // 钓鱼目的网址

//Http 头部数据
struct HttpHeader
{
	char method[4];			// POST 或者 GET，注意有些为 CONNECT，本实验暂不考虑
	char url[1024];			// 请求的 url
	char host[1024];		// 目标主机
	char cookie[1024 * 10]; //cookie
	HttpHeader()
	{
		ZeroMemory(this, sizeof(HttpHeader));
	}
};

// 结构体cache
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
		ZeroMemory(this, sizeof(HttpCache)); // 初始化cache
	}
};
HttpCache Cache[1024];
int cached_number = 0; //已经缓存的url数
int last_cache = 0;	   //上一次缓存的索引

BOOL InitSocket();
int ParseHttpHead(char *buffer, HttpHeader *httpHeader);
BOOL ConnectToServer(SOCKET *serverSocket, char *host);
unsigned int __stdcall ProxyThread(LPVOID lpParameter);
void ParseCache(char *buffer, char *status, char *last_modified);

//代理相关参数
SOCKET ProxyServer;
sockaddr_in ProxyServerAddr;
const int ProxyPort = 10240;

//由于新的连接都使用新线程进行处理，对线程的频繁的创建和销毁特别浪费资源
//可以使用线程池技术提高服务器效率
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
	printf("代理服务器正在启动\n");
	printf("初始化...\n");
	if (!InitSocket())
	{
		printf("socket 初始化失败\n");
		return -1;
	}
	printf("代理服务器正在运行，监听端口 %d\n", ProxyPort);
	SOCKET acceptSocket = INVALID_SOCKET;
	SOCKADDR_IN acceptAddr;
	ProxyParam *lpProxyParam;
	HANDLE hThread;
	DWORD dwThreadID;

	//代理服务器不断监听
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
// Qualifier: 初始化套接字
//************************************
BOOL InitSocket()
{
	//加载套接字库（必须）
	WORD wVersionRequested;
	WSADATA wsaData;
	//套接字加载时错误提示
	int err;
	//版本 2.2
	wVersionRequested = MAKEWORD(2, 2);
	//加载 dll 文件 Socket 库
	err = WSAStartup(wVersionRequested, &wsaData);
	if (err != 0)
	{
		//找不到 winsock.dll
		printf("加载 winsock 失败， 错误代码为: %d\n", WSAGetLastError());
		return FALSE;
	}
	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
	{
		printf("不能找到正确的 winsock 版本\n");
		WSACleanup();
		return FALSE;
	}
	ProxyServer = socket(AF_INET, SOCK_STREAM, 0); // 创建一个TCP/IP协议族的流套接字
	if (INVALID_SOCKET == ProxyServer)
	{
		printf("创建套接字失败，错误代码为：%d\n", WSAGetLastError());
		return FALSE;
	}
	ProxyServerAddr.sin_family = AF_INET;
	ProxyServerAddr.sin_port = htons(ProxyPort);
	// ProxyServerAddr.sin_addr.S_un.S_addr = INADDR_ANY;
	ProxyServerAddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1"); //只允许本机用户访问服务器

	if (bind(ProxyServer, (SOCKADDR *)&ProxyServerAddr, sizeof(SOCKADDR)) == SOCKET_ERROR)
	{
		printf("绑定套接字失败\n");
		return FALSE;
	}
	if (listen(ProxyServer, SOMAXCONN) == SOCKET_ERROR)
	{
		printf("监听端口%d 失败", ProxyPort);
		return FALSE;
	}
	return TRUE;
}

//************************************
// Method: ProxyThread
// FullName: ProxyThread
// Access: public
// Returns: unsigned int __stdcall
// Qualifier: 线程执行函数
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

	//接收客户端的请求
	recvSize = recv(((ProxyParam *)lpParameter)->clientSocket, Buffer, MAXSIZE, 0);

	// 为避免报jump to label 'error'的错误，将其注释
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
		printf("代理连接主机 %s 失败\n", httpHeader->host);
		goto error;
	}
	printf("代理连接主机 %s 成功\n", httpHeader->host);

	// 网站屏蔽
	if (strcmp(httpHeader->url, BANNED_WEB) == 0)
	{
		printf("网站 %s 已被屏蔽\n", BANNED_WEB);
		goto error;
	}

	//网站钓鱼  访问jwc.hit.edu.cn  重定向到jwts.hit.edu.cn
	if (strstr(httpHeader->url, PHISHING_WEB_SRC) != NULL)
	{
		char *pr;
		int phishing_len;
		// 打印信息
		printf("网站 %s 已被成功重定向至 %s\n", PHISHING_WEB_SRC, PHISHING_WEB_DEST);
		// 构造报文
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

		//重定向到jwts.hit.edu.cn
		char phishing_dest[] = "Location: ";
		strcat(phishing_dest, PHISHING_WEB_DEST);
		strcat(phishing_dest, "\r\n\r\n");
		phishing_len = strlen(phishing_dest);
		memcpy(pr, phishing_dest, phishing_len);

		//将302报文返回给客户端
		ret = send(((ProxyParam *)lpParameter)->clientSocket, phishBuffer, sizeof(phishBuffer), 0);
		goto error;
	}

	//实现cache功能
	if (Have_cache) //请求的页面在服务器有缓存
	{
		char cached_buffer[MAXSIZE];
		ZeroMemory(cached_buffer, MAXSIZE);
		memcpy(cached_buffer, Buffer, recvSize);

		//构造缓存的报文头
		char *pr = cached_buffer + recvSize;
		printf(",,");
		memcpy(pr, "If-modified-since: ", 19);
		pr += 19;
		int length = strlen(Cache[last_cache].last_modified);
		memcpy(pr, Cache[last_cache].last_modified, length);
		pr += length;

		//将客户端发送的 HTTP 数据报文直接转发给目标服务器
		ret = send(((ProxyParam *)lpParameter)->serverSocket, cached_buffer, strlen(cached_buffer) + 1, 0);
		//等待目标服务器返回数据
		recvSize = recv(((ProxyParam *)lpParameter)->serverSocket, cached_buffer, MAXSIZE, 0);
		if (recvSize <= 0)
		{
			goto error;
		}

		//解析包含缓存信息的HTTP报文头
		CacheBuffer = new char[recvSize + 1];
		ZeroMemory(CacheBuffer, recvSize + 1);
		memcpy(CacheBuffer, cached_buffer, recvSize);

		char last_status[4];	//记录主机返回的状态字
		char last_modified[30]; //记录返回页面的修改时间
		ParseCache(CacheBuffer, last_status, last_modified);

		delete CacheBuffer;

		//分析cache的状态字
		if (strcmp(last_status, "304") == 0) //304状态码，文件没有被修改
		{
			printf("页面未被修改,缓存URL:%s\n", Cache[last_cache].url);
			//直接将缓存数据转发给客户端
			ret = send(((ProxyParam *)lpParameter)->clientSocket, Cache[last_cache].buffer, sizeof(Cache[last_cache].buffer), 0);
			if (ret != SOCKET_ERROR)
				printf("由缓存发送\n");
		}
		else if (strcmp(last_status, "200") == 0) //200状态码，表示文件已被修改
		{
			//首先修改缓存内容
			printf("页面被修改,缓存URL:%s\n", Cache[last_cache].url);
			memcpy(Cache[last_cache].buffer, cached_buffer, strlen(cached_buffer));
			memcpy(Cache[last_cache].last_modified, last_modified, strlen(last_modified));

			//将目标服务器返回的数据直接转发给客户端
			ret = send(((ProxyParam *)lpParameter)->clientSocket, cached_buffer, sizeof(cached_buffer), 0);
			if (ret != SOCKET_ERROR)
				printf("由缓存发送，已修改\n");
		}
	}
	else //没有缓存过该页面
	{
		//将客户端发送的 HTTP 数据报文直接转发给目标服务器
		ret = send(((ProxyParam *)lpParameter)->serverSocket, Buffer, strlen(Buffer) + 1, 0);
		//等待目标服务器返回数据
		recvSize = recv(((ProxyParam *)lpParameter)->serverSocket, Buffer, MAXSIZE, 0);
		if (recvSize <= 0)
		{
			goto error;
		}

		//将该页面缓存到cache中

		//将目标服务器返回的数据直接转发给客户端
		ret = send(((ProxyParam *)lpParameter)->clientSocket, Buffer, sizeof(Buffer), 0);
		if (ret != SOCKET_ERROR)
		{
			printf("来自服务器\n成功发送给客户端的报文(目标服务器返回的)buffer ret = %d \n", ret);
		}
	}
	//错误处理
error:
	printf("关闭套接字\n\n");
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
//Qualifier: 解析 TCP 报文中的 HTTP 头部,在已经cache命中的时候使用
//Parameter: char *buffer
//Parameter: char * status
//Parameter: HttpHeader *httpHeader
//*************************
void ParseCache(char *buffer, char *status, char *last_modified)
{
	char *p;
	char *ptr;
	const char *delim = "\r\n";
	p = strtok_s(buffer, delim, &ptr); //提取第一行
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
//Qualifier: 解析 TCP 报文中的 HTTP 头部
//Parameter: char *buffer
//Parameter: HttpHeader *httpHeader
//*************************
int ParseHttpHead(char *buffer, HttpHeader *httpHeader)
{
	int flag = 0; //用于表示Cache是否命中，命中为1，不命中为0
	char *p;
	char *ptr;
	const char *delim = "\r\n"; //回车换行符
	p = strtok_s(buffer, delim, &ptr);
	if (p[0] == 'G')
	{ //GET方式
		memcpy(httpHeader->method, "GET", 3);
		memcpy(httpHeader->url, &p[4], strlen(p) - 13);
		printf("url：%s\n", httpHeader->url); //url
		for (int i = 0; i < 1024; i++)
		{ //搜索cache，看当前访问的url是否已经存在cache中了
			if (strcmp(Cache[i].url, httpHeader->url) == 0)
			{ //说明url在cache中已经存在
				flag = 1;
				break;
			}
		}
		if (!flag && cached_number != 1023) //说明url没有在cache且cache没有满, 把这个url直接存进去
		{
			memcpy(Cache[cached_number].url, &p[4], strlen(p) - 13);
			last_cache = cached_number;
		}
		else if (!flag && cached_number == 1023) //说明url没有在cache且cache满了,把第一个cache覆盖
		{
			memcpy(Cache[0].url, &p[4], strlen(p) - 13);
			last_cache = 0;
		}
	}
	else if (p[0] == 'P') //POST方式
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
// Qualifier: 根据主机创建目标服务器套接字，并连接
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