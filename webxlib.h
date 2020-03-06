//extern WEBXLIB_API int nwebxlib;
//WEBXLIB_API int fnwebxlib(void);
#include <csocket.h>

#include <map>
#include <vector>
#include <string>

#ifdef WEBXLIB_EXPORTS
#define WEBXLIB_API __declspec(dllexport)
#else
#define WEBXLIB_API __declspec(dllimport)
#endif

typedef int WEBXLIB_ENUM;

/****************************************************
webxlib::socket enums
****************************************************/
extern WEBXLIB_API WEBXLIB_ENUM TCPWEBSOCK;
extern WEBXLIB_API WEBXLIB_ENUM UDPWEBSOCK;

extern WEBXLIB_API WEBXLIB_ENUM IPV4WEBSOCK;
extern WEBXLIB_API WEBXLIB_ENUM IPV6WEBSOCK;

extern WEBXLIB_API WEBXLIB_ENUM HTTPWEBSOCK;
extern WEBXLIB_API WEBXLIB_ENUM HTTPSWEBSOCK;

extern WEBXLIB_API WEBXLIB_ENUM WEBSOCK_ERROR;
extern WEBXLIB_API WEBXLIB_ENUM WEBSOCK_SUCCESS;
extern WEBXLIB_API WEBXLIB_ENUM WEBSOCK_INVALID;

/****************************************************
webxlib::webqueue enums
****************************************************/
extern WEBXLIB_API WEBXLIB_ENUM WEBCLIENT_BUSY;
extern WEBXLIB_API WEBXLIB_ENUM WEBCLIENT_WANTREAD;
extern WEBXLIB_API WEBXLIB_ENUM WEBCLIENT_WANTWRITE;
extern WEBXLIB_API WEBXLIB_ENUM WEBCLIENT_WANTCONNECT;
extern WEBXLIB_API WEBXLIB_ENUM WEBCLIENT_WANTACCEPT;
extern WEBXLIB_API WEBXLIB_ENUM WEBCLIENT_WANTSSLACCEPT;

typedef struct websockdata
{
	const char* address;
	const char* port;

	WEBXLIB_ENUM dataprotocol;
	WEBXLIB_ENUM ipprotocol;
	WEBXLIB_ENUM secure;
} websockdata;

typedef struct HTTP_packet
{
	const char* httpversion;
	const char* responsecode;
	const char* server;
	const char* date;
	const char* content_security_policy = "Content-Security-Policy: default-src 'self'\r\n";
	const char* content_length;
	const char* content_type;
	const char* connection;
	char* response_content;
} HTTP_packet;

class WEBXLIB_API webxlib 
{
public:	
	class socket;
	class webhook;
	class webqueue;
	class lockz;
	
	socket* NewWebsock(websockdata* data);
	webhook* NewWebhookInterface();

	std::map<std::string, std::string> ParseHTTPRequest(char* data);
	std::string BuildResponsePacket(HTTP_packet sv);

	std::vector<std::string> stringExp(std::string const& s, char delim);
	std::map<std::string, std::string> GetMimetypesTable();
	uint8_t* LoadFiletoMem(char* filename, size_t* fsize);
	bool fileExists(const char* filename);
	char* systime();
};

class WEBXLIB_API webxlib::socket
{
public:
	socket(websockdata*);
	~socket();

	int Bind();
	int Listen();
	socket* Accept();
	int Connect();

	int SSLInit(const char* cert, const char* key);
	int SSLBind();
	int SSLAccept();
	int SSLWantRead();
	int SSLWantWrite();

	bool IsValid();
	bool IsSecure();
	int SelectReadable(const timeval timeout);
	int SelectWriteable(const timeval timeout);
	void SetSecure(bool opt);
	int SetSockOpt(int lvl, int optname, const char* optval, int optlen);
	int IOCtrlSock(long cmd, u_long* argp);


	int Send(const char* data, int sz);
	int Recv(char* data, int sz);

	inline bool operator==(const socket* other) { return this->websock == other->websock; };
protected:
	socket(CSOCKET*);
	CSOCKET* websock = nullptr;
};

class WEBXLIB_API webxlib::webhook
{
public:
	void RegisterWebhook(const char* id, void* funcptr);
	void CallWebhook(const char* id, void* param, void* param2);

	std::map<std::string, void*>* GetHookTable();
protected:
	std::map<std::string, void*> hooktable;
};

typedef struct qpair
{
	WEBXLIB_ENUM status;
	webxlib::socket* client;

	bool operator==(const qpair& other) { return client == other.client; };
} qpair;

class WEBXLIB_API webxlib::webqueue
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

class WEBXLIB_API webxlib::lockz
{
public:
	lockz();
	~lockz();

	void Acquire();
	void Release();
protected:
	CRITICAL_SECTION m_criticalSection;
};

WEBXLIB_API webxlib* CreateWEBXInterface();