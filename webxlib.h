#define WIN32_LEAN_AND_MEAN
#include <libcsock.h>

#include <string>
#include <map>
#include <vector>

#ifndef WEBXLIB_H
#define WEBXLIB_H

typedef int WEBXLIB_ENUM;

/****************************************************
webxlib::socket enums
****************************************************/
WEBXLIB_ENUM TCPWEBSOCK			= CSOCKET_TCP;
WEBXLIB_ENUM UDPWEBSOCK			= CSOCKET_UDP;

WEBXLIB_ENUM IPV4WEBSOCK		= CSOCKET_IPV4;
WEBXLIB_ENUM IPV6WEBSOCK		= CSOCKET_IPV6;

WEBXLIB_ENUM SIMPLEWEBSOCK		= CSOCKET_SIMPLE;
WEBXLIB_ENUM SSLWEBSOCK			= CSOCKET_SSL;

WEBXLIB_ENUM WEBSOCK_ERROR		= CSOCKET_FATAL_ERROR;
WEBXLIB_ENUM WEBSOCK_SUCCESS	= CSOCKET_SOCK_SUCCESS;
WEBXLIB_ENUM WEBSOCK_INVALID	= CSOCKET_INVALID_SOCKET;

/****************************************************
webxlib::webqueue enums & datastruct
****************************************************/
WEBXLIB_ENUM WEBCLIENT_BUSY				= 0;
WEBXLIB_ENUM WEBCLIENT_WANTREAD			= 1;
WEBXLIB_ENUM WEBCLIENT_WANTWRITE		= 2;
WEBXLIB_ENUM WEBCLIENT_WANTCONNECT		= 3;
WEBXLIB_ENUM WEBCLIENT_WANTACCEPT		= 4;
WEBXLIB_ENUM WEBCLIENT_WANTSSLACCEPT	= 5;

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

class webxlib
{
public:
	class socket;
	class webhook;
	class webqueue;
	class lockz;

	socket* NewWebsock(csockdata* data);
	webhook* NewWebhookInterface();

	std::map<std::string, std::string> ParseHTTPRequest(char* data);
	std::string BuildResponsePacket(HTTP_packet sv);

	std::vector<std::string> stringExp(std::string const& s, char delim);
	std::map<std::string, std::string> GetMimetypesTable();
	uint8_t* LoadFiletoMem(char* filename, size_t* fsize);
	bool fileExists(const char* filename);
	char* systime();
};

typedef struct qpair
{
	WEBXLIB_ENUM status;
	webxlib::socket* client;

	bool operator==(const qpair& other) { return client == other.client; };
} qpair;

class webxlib::socket
{
public:
	socket(csockdata*);
	~socket();

	int Bind();
	int Listen();
	socket* Accept();
	int Connect();

	int SSLInit(const char* cert, const char* key);
	int SSLBind();
	int SSLAccept();
	int SSLConnect();
	int SSLWantRead();
	int SSLWantWrite();

	bool IsValid();
	int CheckType();
	int SelectReadable(const timeval timeout);
	int SelectWriteable(const timeval timeout);
	void SetType(WEBXLIB_ENUM type);
	int SetSockOpt(int lvl, int optname, const char* optval, int optlen);
	int IOCtrlSock(long cmd, u_long* argp);


	int Send(const char* data, int sz);
	int Recv(char* data, int sz);

	inline bool operator==(const socket* other) { return this->websock == other->websock; };
protected:
	socket(CSOCKET*);
	CSOCKET* websock = nullptr;
};

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

class webxlib::webqueue
{
public:
	void PushQueue(qpair cl);
	void PopQueue(const qpair& cl);

	void UpdateStatus(qpair cl, WEBXLIB_ENUM status);
	void ClearQueue();

	int QueueCount();

	std::vector<qpair> GetQueue();
protected:
	std::vector<qpair> webq;
};

class webxlib::lockz
{
public:
	lockz();
	~lockz();

	void Acquire();
	void Release();
protected:
	CRITICAL_SECTION m_criticalSection;
};

webxlib* CreateWEBXInterface()
{
	return new webxlib();
}

#endif //WEBXLIB_H
