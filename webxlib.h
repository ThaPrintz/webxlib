#pragma once
#define WIN32_LEAN_AND_MEAN  

#ifndef WEBXLIB_H
#define WEBXLIB_H

#include <ws2tcpip.h>
#include "wolfssl/ssl.h"

#include <string>
#include <map>
#include <vector>

/**********************************************************
webxlib::webxsock enums, return types & data structures
***********************************************************/
enum WEBXSOCK_PROPERTY
{
	TCPSOCK			= 0,
	UDPSOCK			= 1,

	IPV4SOCK		= 2,
	IPV6SOCK		= 3,

	STANDARDSOCK	= 4,
	SECURESOCK		= 5
};

//return types
static constexpr int WEBXSOCK_ERROR   = -1;
static constexpr int INVALID_WEBXSOCK = 0;
static constexpr int WEBXSOCK_SUCCESS = 1;

//webxsock initialization struct
typedef struct webxsockdata
{
	std::string address;
	std::string port;

	WEBXSOCK_PROPERTY ipprotocol;
	WEBXSOCK_PROPERTY dataprotocol;
	WEBXSOCK_PROPERTY socktype;
} webxsockdata;

//struct for building http response
typedef struct HTTP_packet
{
	std::string responsecode;
	std::string server;
	std::string date;
	std::string content_length;
	std::string content_type;
	std::string connection;
	std::string response_content;
} HTTP_packet;

//namespace encompassing all webxlib functionality
class webxlib
{
public:
	class webxsocket;
	class webhook;
	class HTTPEvent;

	std::vector<std::string> strExplode(std::string const& s, char delim);
	std::map<std::string, std::string> GetMimetypesTable();

	uint8_t* LoadFile(char* fname, size_t* fsize);
	bool fileIsValid(const char* fname);
	char* systime();
};

//sockets class
class webxlib::webxsocket
{
public:
	webxsocket(webxsockdata* sockinfo);
	webxsocket(const webxsocket&) = default;
	virtual ~webxsocket();

	int SSL_Init(const char* cert, const char* key);

	static int WSAInit();
	static int WSAExit();
	int WSAError();

	int Bind();
	int SSLBind();

	int Listen();

	int Connect();
	int SSLConnect();

	webxsocket* Accept();
	int SSLAccept();

	int SelectReadable(const timeval timeout);
	int SelectWriteable(const timeval timeout);
	int SSLWantRead();
	int SSLWantWrite();

	int SetSockOpt(int lvl, int optname, const char* optval, int optlen);
	int IOCtrlSocket(long cmd, u_long* argp);

	void SetType(WEBXSOCK_PROPERTY type);
	bool IsValid();
	int CheckType();

	int Send(const char* data, int size);
	int Recv(char* data, int size);

	inline bool operator==(const webxsocket* other)
	{return this->webxsock_handle == other->webxsock_handle;};
protected:
	webxsocket();
	webxsocket(SOCKET);

	SOCKET webxsock_handle = INVALID_WEBXSOCK;

	addrinfo* result   = nullptr;
	sockaddr_in remloc = { 0 };

	WOLFSSL_CTX* csocket_context = nullptr;
	WOLFSSL* csocket_ssl		 = nullptr;

	int dataprotocol	= 0;
	int ipprotocol		= 0;
	int socktype		= 0;
};

//webhook class
class webxlib::webhook
{
public:
	void RegisterWebhook(std::string id, void* funcptr);
	void CallWebhook(std::string id, void* param, void* param2);

	bool hookIsValid(std::string id);
protected:
	static void _catalyst(void* pParam, void* pparam2);

	std::map<std::string, void*> hooktable;
};

class webxlib::HTTPEvent
{
public:
	HTTPEvent(void* funcptr);
	virtual ~HTTPEvent();

	void Run(void* arg, void* argg);
protected:
	static void _catalyst(void* pParam, void* pparam2);
	void* routine = nullptr;
};

#endif //WEBXLIB_H