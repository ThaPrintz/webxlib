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
static constexpr int TCPSOCK		= 0;
static constexpr int UDPSOCK		= 1;
								 
static constexpr int IPV4SOCK		= 2;
static constexpr int IPV6SOCK		= 3;

static constexpr int WEBSOCK		= 5;

//return types
static constexpr int CSOCKET_ERROR   = -1;
static constexpr int CSOCKET_INVALID = 0;
static constexpr int CSOCKET_SUCCESS = 1;

//csock data struct
typedef struct csocketinfo
{
	std::string address;
	std::string port;

	int ipprotocol;
	int dataprotocol;
} csockdata;

//webxlib class
class webxlib
{
public:
	class csocket;
	class webhook;
	class HTTPServer;

	static std::map<std::string, std::string> ParseHTTPRequest(char* data);
	static std::vector<std::string> strExplode(std::string const& s, char delim);
	static std::map<std::string, std::string> GetMimetypesTable();
	static std::string BuildResponsePacket(std::string resp, std::string sv, std::string clength, std::string ctype, std::string svcon, std::string respcon);
	
	static uint8_t* LoadFile(char* fname, size_t* fsize);
	static bool fileIsValid(const char* fname);
	static char* systime();
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

	bool SetSecure(bool sec);
	bool CheckType();

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
	bool _secure = false;
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
webxlib::HTTPServer class
***********************************************************/
typedef struct request_data
{
	webxlib::csocket* cl;
	std::map<std::string, std::string> request_headers;
} cl_data;

typedef struct request_pkg
{
	webxlib::HTTPServer* sv;
	webxlib::csocket* cl;
} conpkg;

static constexpr int SVPOWEROFF		= 0;
static constexpr int SVPOWERON		= 1;
static constexpr int SVPOWERPAUSE	= 2;

class webxlib::HTTPServer
{
public:
	HTTPServer();
	virtual ~HTTPServer();

	bool Start();
	bool Pause();
	webxlib::HTTPServer* Restart();
	bool Stop();

	void SetSSLCert(std::string certificate, std::string key);
	void EnableSSL();

	void RegisterRequestHandler(std::string id, void* funcptr);
	void CallRequestHandler(std::string id, void* arg, void* argg);
	bool ValidateReqHandler(std::string id);
protected:
	bool _SSL			= false;
	int _svpower	= SVPOWEROFF;

	std::string certificate_file;
	std::string key_file;

	csockdata http_data;
	csockdata https_data;

	webxlib::csocket* httpsv					   = nullptr;
	webxlib::csocket* httpssv				   = nullptr;

	webxlib::webhook* request_handlers = nullptr;
	webxlib* webxif								   = nullptr;

	static DWORD WINAPI _primaryrequesthandler(LPVOID _arg);
};

#endif  //WEBXLIB_H