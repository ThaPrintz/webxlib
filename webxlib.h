//extern WEBXLIB_API int nwebxlib;
//WEBXLIB_API int fnwebxlib(void);

#include <map>
#include <vector>
#include <string>
#include <csocket.h>

#ifdef WEBXLIB_EXPORTS
#define WEBXLIB_API __declspec(dllexport)
#else
#define WEBXLIB_API __declspec(dllimport)
#endif

typedef int WEBXLIB_ENUM;
extern WEBXLIB_API WEBXLIB_ENUM TCPWEBSOCK;
extern WEBXLIB_API WEBXLIB_ENUM UDPWEBSOCK;

extern WEBXLIB_API WEBXLIB_ENUM IPV4WEBSOCK;
extern WEBXLIB_API WEBXLIB_ENUM IPV6WEBSOCK;

extern WEBXLIB_API WEBXLIB_ENUM HTTPWEBSOCK;
extern WEBXLIB_API WEBXLIB_ENUM HTTPSWEBSOCK;

extern WEBXLIB_API WEBXLIB_ENUM WEBSOCK_ERROR;
extern WEBXLIB_API WEBXLIB_ENUM WEBSOCK_SUCCESS;
extern WEBXLIB_API WEBXLIB_ENUM WEBSOCK_INVALID;

typedef struct websockdata
{
	const char* address;
	const char* port;

	WEBXLIB_ENUM dataprotocol;
	WEBXLIB_ENUM ipprotocol;
	WEBXLIB_ENUM secure;
} websockdata;

typedef WEBXLIB_API struct HTTP_packet
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
	webxlib(std::string sv_name) 
	{ server = sv_name; };
	
	class socket;
	class webhook;
	
	socket* NewWebsock(websockdata* data);
	webhook* NewWebhookInterface();

	std::map<std::string, std::string> ParseHTTPRequest(char* data);
	std::string BuildResponsePacket(HTTP_packet sv);

	std::vector<std::string> stringExp(std::string const& s, char delim);
	std::map<std::string, std::string> GetMimetypesTable();
	uint8_t* LoadFiletoMem(char* filename, size_t* fsize);
	bool fileExists(const char* filename);
	char* systime();
protected:
	std::string server;
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
	int SelectReadable(const timeval timeout);
	int SelectWriteable(const timeval timeout);
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
