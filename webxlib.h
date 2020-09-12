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
webxlib::csocket enums, return types & data structures
***********************************************************/
enum CSOCK_PROPERTY
{
	TCPSOCK,
	UDPSOCK,

	IPV4SOCK,
	IPV6SOCK,

	STANDARDSOCK,
	SECURESOCK
};

//return types
static constexpr int CSOCKET_ERROR   = -1;
static constexpr int CSOCKET_INVALID = 0;
static constexpr int CSOCKET_SUCCESS = 1;

//csock data struct
typedef struct csocketinfo
{
	std::string address;
	std::string port;

	CSOCK_PROPERTY ipprotocol;
	CSOCK_PROPERTY dataprotocol;
	CSOCK_PROPERTY socktype;
} csockdata;

//webxlib class
class webxlib
{
public:
	class csocket;
	class webhook;
	class HTTPEvent;

	std::vector<std::string> strExplode(std::string const& s, char delim);
	std::map<std::string, std::string> GetMimetypesTable();

	uint8_t* LoadFile(char* fname, size_t* fsize);
	bool fileIsValid(const char* fname);
	char* systime();
};

//socket class
class webxlib::csocket
{
public:
	csocket(csockdata* sockinfo);
	csocket(const csocket&) = default;
	virtual ~csocket();

	int SSL_Init(const char* cert, const char* key);

	static int WSAInit();
	static int WSAExit();
	int WSAError();

	int Bind();
	int SSLBind();

	int Listen();

	int Connect();
	int SSLConnect();

	csocket* Accept();
	int SSLAccept();

	int SelectReadable(const timeval timeout);
	int SelectWriteable(const timeval timeout);
	int SSLWantRead();
	int SSLWantWrite();

	int SetSockOpt(int lvl, int optname, const char* optval, int optlen);
	int IOCtrlSocket(long cmd, u_long* argp);

	void SetType(CSOCK_PROPERTY type);
	CSOCK_PROPERTY CheckType();

	bool IsValid();

	int Send(const char* data, int size);
	int Recv(char* data, int size);

	inline bool operator==(const csocket* other)
	{return this->webxsock_handle == other->webxsock_handle;};
protected:
	csocket();
	csocket(SOCKET);

	SOCKET webxsock_handle = CSOCKET_INVALID;

	addrinfo* result	= nullptr;
	sockaddr_in remloc	= { 0 };

	WOLFSSL_CTX* csocket_context = nullptr;
	WOLFSSL* csocket_ssl		 = nullptr;

	csockdata* _data = nullptr;
};

/**********************************************************
webxlib::webhook class
***********************************************************/
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

/**********************************************************
webxlib::HTTPEvent class
***********************************************************/
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
#endif  //WEBXLIB_H
