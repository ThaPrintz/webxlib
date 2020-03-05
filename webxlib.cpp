#include "webxlib.h"
#include <io.h>
#include <chrono>
#include <ctime>

/************************************************
webxlib::socket library enum defitions
*************************************************/
WEBXLIB_ENUM TCPWEBSOCK		 = 0;
WEBXLIB_ENUM UDPWEBSOCK		 = 1;

WEBXLIB_ENUM IPV4WEBSOCK	 = 2;
WEBXLIB_ENUM IPV6WEBSOCK	 = 3;

WEBXLIB_ENUM HTTPWEBSOCK	 = 4;
WEBXLIB_ENUM HTTPSWEBSOCK	 = 5;

WEBXLIB_ENUM WEBSOCK_ERROR	 = -1;
WEBXLIB_ENUM WEBSOCK_SUCCESS = 1;
WEBXLIB_ENUM WEBSOCK_INVALID = 0;

/************************************************
webxlib::socket library funcs
*************************************************/
webxlib::socket::socket(websockdata* data)
{
	this->websock = new CSOCKET((csockdata*)data);
}

webxlib::socket::socket(CSOCKET* cl)
{
	this->websock = cl;
}

webxlib::socket::~socket()
{
	delete this->websock;
}

int webxlib::socket::Bind()
{
	return this->websock->Bind();
}

int webxlib::socket::Listen()
{
	return this->websock->Listen();
}

webxlib::socket* webxlib::socket::Accept()
{
	return new webxlib::socket(this->websock->Accept());
}

int webxlib::socket::Connect()
{
	return this->websock->Connect();
}

int webxlib::socket::SSLInit(const char* cert, const char* key)
{
	return this->websock->SSL_Init(cert, key);
}

int webxlib::socket::SSLBind()
{
	return this->websock->SSLBindSocket();
}

int webxlib::socket::SSLAccept()
{
	return this->websock->SSLAccept();
}

int webxlib::socket::SSLWantRead()
{
	return this->websock->SSLWantRead();
}

int webxlib::socket::SSLWantWrite()
{
	return this->websock->SSLWantWrite();
}

bool webxlib::socket::IsValid()
{
	return this->websock->IsValid();
}

int webxlib::socket::SelectReadable(const timeval timeout)
{
	return this->websock->SelectReadable(timeout);
}

int webxlib::socket::SelectWriteable(const timeval timeout)
{
	return this->websock->SelectWriteable(timeout);
}

int webxlib::socket::SetSockOpt(int lvl, int optname, const char* optval, int optlen)
{
	return this->websock->SetSockOpt(lvl, optname, optval, optlen);
}

int webxlib::socket::IOCtrlSock(long cmd, u_long* argp)
{
	return this->websock->IOCtrlSocket(cmd, argp);
}

int webxlib::socket::Send(const char* data, int sz)
{
	return this->websock->Send(data, sz);
}

int webxlib::socket::Recv(char* data, int sz)
{
	return this->websock->Recv(data, sz);
}

/************************************************
webxlib::webhook library funcs
*************************************************/

//catalyst function
static void _default(void* ptr, void* pParam);

void webxlib::webhook::RegisterWebhook(const char* id, void* ptr)
{
	this->hooktable[id] = ptr;
}

void webxlib::webhook::CallWebhook(const char* id, void* param, void* param2)
{
	(decltype(&_default)(this->hooktable[id]))(param, param2);
}

std::map<std::string, void*>* webxlib::webhook::GetHookTable()
{
	return &this->hooktable;
}

/************************************************
webxlib interface funcs
*************************************************/
webxlib::socket* webxlib::NewWebsock(websockdata* data)
{
	return new webxlib::socket(data);
}

webxlib::webhook* webxlib::NewWebhookInterface()
{
	return new webxlib::webhook();
}

std::map<std::string, std::string> webxlib::ParseHTTPRequest(char* data)
{
	auto buff = stringExp(data, '\r\n');
	auto reqs = stringExp(buff[0], ' ');

	std::map<std::string, std::string> ret;
	ret["METHOD"]	= reqs[0];
	ret["DATA"]		= reqs[1];
	ret["VERSION"]  = reqs[2];

	std::vector<std::string> lines;
	for (int i = 0; i <= buff.size() - 3; i++) {
		lines.push_back(buff[i]);
	}

	for (int k = 1; k < (int)lines.size(); k++) {
		auto req_data = stringExp(lines[k], ':');

		std::string value, prev;
		for (auto& g : req_data) {
			value = g.substr(1, g.size());

			if (g[0] != ' ') {
				prev = value;
			} else {
				ret.emplace(prev, value);
			}
		}
	}

	return ret;
}

std::string webxlib::BuildResponsePacket(HTTP_packet sv)
{
	return sv.httpversion + std::string(" ") + sv.responsecode + "\r\n"
		+ sv.server + "\r\n"
		+ "Date: " + systime() + "\r\n"
		+ sv.content_security_policy + "\r\n"
		+ "Content-Length: " + sv.content_length + "\r\n"
		+ "Content-Type: " + sv.content_type + "\r\n"
		+ "Connection:" + sv.connection + "\r\n\r\n"
		+ sv.response_content;
}

std::vector<std::string> webxlib::stringExp(std::string const& s, char delim)
{
	std::string buff{ "" };
	std::vector<std::string> v;

	for (auto n : s) {
		if (n != delim) buff += n; else
			if (n == delim && buff != "") { v.push_back(buff); buff = ""; }
	}

	if (buff != "") v.push_back(buff);

	return v;
}

uint8_t* webxlib::LoadFiletoMem(char* filename, size_t* fsize)
{
	FILE* f = fopen(filename, "rb");
	fseek(f, 0, SEEK_END);
	*fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	uint8_t* buffer = (uint8_t*)malloc(*fsize + 1);
	fread(buffer, *fsize, 1, f);
	fclose(f);

	return buffer;
}

bool webxlib::fileExists(const char* filename)
{
	return (_access(filename, 0) != -1);
}

char* webxlib::systime()
{
	auto end = std::chrono::system_clock::now();
	std::time_t end_time = std::chrono::system_clock::to_time_t(end);

	char* time = std::ctime(&end_time);
	time[strlen(time) - 1] = '\0';
	time[strlen(time)] = '\0';

	return time;
}

std::map<std::string, std::string> webxlib::GetMimetypesTable()
{
	std::map<std::string, std::string> autotype;

	autotype["el"] = "text/x-script.elisp";
	autotype["wmv"] = "video/x-ms-wmv";
	autotype["idc"] = "text/plain";
	autotype["oth"] = "application/vnd.oasis.opendocument.text-web";
	autotype["jpgm"] = "video/jpm";
	autotype["txd"] = "application/vnd.genomatix.tuxedo";
	autotype["tcl"] = "text/x-script.tcl";
	autotype["m4a"] = "audio/mp4";
	autotype["icm"] = "application/vnd.iccprofile";
	autotype["dll"] = "application/x-msdownload";
	autotype["kpr"] = "application/vnd.kde.kpresenter";
	autotype["lsx"] = "text/x-la-asf";
	autotype["acgi"] = "text/html";
	autotype["mp2"] = "video/x-mpeq2a";
	autotype["m14"] = "application/x-msmediaview";
	autotype["xll"] = "application/x-excel";
	autotype["c4g"] = "application/vnd.clonk.c4group";
	autotype["st"] = "application/vnd.sailingtracker.track";
	autotype["oda"] = "application/oda";
	autotype["cco"] = "application/x-cocoa";
	autotype["sda"] = "application/vnd.stardivision.draw";
	autotype["rms"] = "application/vnd.jcp.javame.midlet-rms";
	autotype["cab"] = "application/vnd.ms-cab-compressed";
	autotype["cb7"] = "application/x-cbr";
	autotype["uvf"] = "application/vnd.dece.data";
	autotype["dtshd"] = "audio/vnd.dts.hd";
	autotype["ccxml"] = "application/ccxml+xml";
	autotype["uvvd"] = "application/vnd.dece.data";
	autotype["abw"] = "application/x-abiword";
	autotype["gex"] = "application/vnd.geometry-explorer";
	autotype["es3"] = "application/vnd.eszigno3+xml";
	autotype["wgt"] = "application/widget";
	autotype["omcr"] = "application/x-omcregerator";
	autotype["gram"] = "application/srgs";
	autotype["p7m"] = "application/x-pkcs7-mime";
	autotype["silo"] = "model/mesh";
	autotype["mts"] = "model/vnd.mts";
	autotype["cxx"] = "text/x-c";
	autotype["w6w"] = "application/msword";
	autotype["uvvf"] = "application/vnd.dece.data";
	autotype["part"] = "application/pro_eng";
	autotype["3g2"] = "video/3gpp2";
	autotype["odm"] = "application/vnd.oasis.opendocument.text-master";
	autotype["uvvh"] = "video/vnd.dece.hd";
	autotype["ustar"] = "multipart/x-ustar";
	autotype["mesh"] = "model/mesh";
	autotype["imp"] = "application/vnd.accpac.simply.imp";
	autotype["wri"] = "application/x-wri";
	autotype["m"] = "text/x-m";
	autotype["prf"] = "application/pics-rules";
	autotype["ggt"] = "application/vnd.geogebra.tool";
	autotype["scs"] = "application/scvp-cv-response";
	autotype["kmz"] = "application/vnd.google-earth.kmz";
	autotype["mpt"] = "application/vnd.ms-project";
	autotype["caf"] = "audio/x-caf";
	autotype["w61"] = "application/wordperfect6.1";
	autotype["lrf"] = "application/octet-stream";
	autotype["qbo"] = "application/vnd.intu.qbo";
	autotype["nml"] = "application/vnd.enliven";
	autotype["ccad"] = "application/clariscad";
	autotype["hpid"] = "application/vnd.hp-hpid";
	autotype["kwd"] = "application/vnd.kde.kword";
	autotype["si"] = "text/vnd.wap.si";
	autotype["acu"] = "application/vnd.acucobol";
	autotype["fm"] = "application/vnd.framemaker";
	autotype["bm"] = "image/bmp";
	autotype["mvb"] = "application/x-msmediaview";
	autotype["rp9"] = "application/vnd.cloanto.rp9";
	autotype["xhtml"] = "application/xhtml+xml";
	autotype["dssc"] = "application/dssc+der";
	autotype["onetoc2"] = "application/onenote";
	autotype["rm"] = "audio/x-pn-realaudio";
	autotype["dae"] = "model/vnd.collada+xml";
	autotype["esa"] = "application/vnd.osgi.subsystem";
	autotype["yin"] = "application/yin+xml";
	autotype["nnw"] = "application/vnd.noblenet-web";
	autotype["pcx"] = "image/x-pcx";
	autotype["book"] = "application/vnd.framemaker";
	autotype["wsc"] = "text/scriplet";
	autotype["kil"] = "application/x-killustrator";
	autotype["nbp"] = "application/vnd.wolfram.player";
	autotype["m2v"] = "video/mpeg";
	autotype["n-gage"] = "application/vnd.nokia.n-gage.symbian.install";
	autotype["lostxml"] = "application/lost+xml";
	autotype["mpx"] = "application/x-project";
	autotype["blb"] = "application/x-blorb";
	autotype["3gp"] = "video/3gpp";
	autotype["sil"] = "audio/silk";
	autotype["pict"] = "image/pict";
	autotype["fe_launch"] = "application/vnd.denovo.fcselayout-link";
	autotype["geo"] = "application/vnd.dynageo";
	autotype["buffer"] = "application/octet-stream";
	autotype["nsf"] = "application/vnd.lotus-notes";
	autotype["dwg"] = "image/x-dwg";
	autotype["teicorpus"] = "application/tei+xml";
	autotype["sus"] = "application/vnd.sus-calendar";
	autotype["uvvz"] = "application/vnd.dece.zip";
	autotype["psd"] = "image/vnd.adobe.photoshop";
	autotype["nb"] = "application/mathematica";
	autotype["nzb"] = "application/x-nzb";
	autotype["tsd"] = "application/timestamped-data";
	autotype["f"] = "text/x-fortran";
	autotype["c11amc"] = "application/vnd.cluetrust.cartomobile-config";
	autotype["nns"] = "application/vnd.noblenet-sealer";
	autotype["dic"] = "text/x-c";
	autotype["rpss"] = "application/vnd.nokia.radio-presets";
	autotype["smi"] = "application/smil+xml";
	autotype["x-png"] = "image/png";
	autotype["rtx"] = "text/richtext";
	autotype["cdbcmsg"] = "application/vnd.contact.cmsg";
	autotype["pic"] = "image/x-pict";
	autotype["vsf"] = "application/vnd.vsf";
	autotype["lbe"] = "application/vnd.llamagraphics.life-balance.exchange+xml";
	autotype["gnumeric"] = "application/x-gnumeric";
	autotype["fxpl"] = "application/vnd.adobe.fxp";
	autotype["x3db"] = "model/x3d+binary";
	autotype["mbd"] = "application/mbedlet";
	autotype["ttf"] = "application/x-font-ttf";
	autotype["eot"] = "application/vnd.ms-fontobject";
	autotype["oxt"] = "application/vnd.openofficeorg.extension";
	autotype["mif"] = "application/x-mif";
	autotype["mk3d"] = "video/x-matroska";
	autotype["mrc"] = "application/marc";
	autotype["cxt"] = "application/x-director";
	autotype["vmd"] = "application/vocaltec-media-desc";
	autotype["gxt"] = "application/vnd.geonext";
	autotype["irp"] = "application/vnd.irepository.package+xml";
	autotype["lasxml"] = "application/vnd.las.las+xml";
	autotype["jpg"] = "image/pjpeg";
	autotype["flac"] = "audio/flac";
	autotype["mv"] = "video/x-sgi-movie";
	autotype["cpio"] = "application/x-cpio";
	autotype["ppa"] = "application/vnd.ms-powerpoint";
	autotype["ani"] = "application/x-navi-animation";
	autotype["cryptonote"] = "application/vnd.rig.cryptonote";
	autotype["cdmio"] = "application/cdmi-object";
	autotype["atc"] = "application/vnd.acucorp";
	autotype["smzip"] = "application/vnd.stepmania.package";
	autotype["ogx"] = "application/ogg";
	autotype["xz"] = "application/x-xz";
	autotype["uni"] = "text/uri-list";
	autotype["iv"] = "application/x-inventor";
	autotype["spf"] = "application/vnd.yamaha.smaf-phrase";
	autotype["ahead"] = "application/vnd.ahead.space";
	autotype["taglet"] = "application/vnd.mynfc";
	autotype["list"] = "text/plain";
	autotype["sid"] = "image/x-mrsid-image";
	autotype["pfb"] = "application/x-font-type1";
	autotype["ras"] = "image/x-cmu-raster";
	autotype["car"] = "application/vnd.curl.car";
	autotype["mgz"] = "application/vnd.proteus.magazine";
	autotype["sbml"] = "application/sbml+xml";
	autotype["art"] = "image/x-jg";
	autotype["cc"] = "text/x-c";
	autotype["kar"] = "music/x-karaoke";
	autotype["opf"] = "application/oebps-package+xml";
	autotype["asm"] = "text/x-asm";
	autotype["wav"] = "audio/x-wav";
	autotype["plx"] = "application/x-pixclscript";
	autotype["step"] = "application/step";
	autotype["dtb"] = "application/x-dtbook+xml";
	autotype["xsl"] = "application/xml";
	autotype["sldm"] = "application/vnd.ms-powerpoint.slide.macroenabled.12";
	autotype["sc"] = "application/vnd.ibm.secure-container";
	autotype["uvs"] = "video/vnd.dece.sd";
	autotype["wma"] = "audio/x-ms-wma";
	autotype["obj"] = "application/x-tgif";
	autotype["rmvb"] = "application/vnd.rn-realmedia-vbr";
	autotype["grv"] = "application/vnd.groove-injector";
	autotype["avs"] = "video/avs-video";
	autotype["ogg"] = "audio/ogg";
	autotype["hpgl"] = "application/vnd.hp-hpgl";
	autotype["mcd"] = "application/x-mathcad";
	autotype["slc"] = "application/vnd.wap.slc";
	autotype["pbm"] = "image/x-portable-bitmap";
	autotype["com"] = "text/plain";
	autotype["asp"] = "text/asp";
	autotype["xbm"] = "image/xbm";
	autotype["gtm"] = "application/vnd.groove-tool-message";
	autotype["w3d"] = "application/x-director";
	autotype["odft"] = "application/vnd.oasis.opendocument.formula-template";
	autotype["xmz"] = "xgl/movie";
	autotype["otm"] = "application/vnd.oasis.opendocument.text-master";
	autotype["xo"] = "application/vnd.olpc-sugar";
	autotype["xlt"] = "application/x-excel";
	autotype["p12"] = "application/x-pkcs12";
	autotype["gqf"] = "application/vnd.grafeq";
	autotype["qxb"] = "application/vnd.quark.quarkxpress";
	autotype["manifest"] = "text/cache-manifest";
	autotype["wrz"] = "x-world/x-vrml";
	autotype["rss"] = "application/rss+xml";
	autotype["mwf"] = "application/vnd.mfer";
	autotype["uue"] = "text/x-uuencode";
	autotype["xpi"] = "application/x-xpinstall";
	autotype["rgb"] = "image/x-rgb";
	autotype["vcg"] = "application/vnd.groove-vcard";
	autotype["cdy"] = "application/vnd.cinderella";
	autotype["jfif-tbnl"] = "image/jpeg";
	autotype["gzip"] = "multipart/x-gzip";
	autotype["mjf"] = "audio/x-vnd.audioexplosion.mjuicemediafile";
	autotype["z1"] = "application/x-zmachine";
	autotype["weba"] = "audio/webm";
	autotype["m13"] = "application/x-msmediaview";
	autotype["cww"] = "application/prs.cww";
	autotype["odf"] = "application/vnd.oasis.opendocument.formula";
	autotype["svgz"] = "image/svg+xml";
	autotype["oti"] = "application/vnd.oasis.opendocument.image-template";
	autotype["hlp"] = "application/x-winhelp";
	autotype["pko"] = "application/vnd.ms-pki.pko";
	autotype["h"] = "text/x-h";
	autotype["cbr"] = "application/x-cbr";
	autotype["lwp"] = "application/vnd.lotus-wordpro";
	autotype["gbr"] = "application/rpki-ghostbusters";
	autotype["zirz"] = "application/vnd.zul";
	autotype["m3u8"] = "application/x-mpegURL";
	autotype["dra"] = "audio/vnd.dra";
	autotype["dis"] = "application/vnd.mobius.dis";
	autotype["ppm"] = "image/x-portable-pixmap";
	autotype["vsw"] = "application/vnd.visio";
	autotype["mxf"] = "application/mxf";
	autotype["wps"] = "application/vnd.ms-works";
	autotype["fbs"] = "image/vnd.fastbidsheet";
	autotype["susp"] = "application/vnd.sus-calendar";
	autotype["air"] = "application/vnd.adobe.air-application-installer-package+zip";
	autotype["pm4"] = "application/x-pagemaker";
	autotype["sti"] = "application/vnd.sun.xml.impress.template";
	autotype["sema"] = "application/vnd.sema";
	autotype["xbap"] = "application/x-ms-xbap";
	autotype["dotx"] = "application/vnd.openxmlformats-officedocument.wordprocessingml.template";
	autotype["mp3"] = "video/x-mpeg";
	autotype["tex"] = "application/x-tex";
	autotype["odb"] = "application/vnd.oasis.opendocument.database";
	autotype["rl"] = "application/resource-lists+xml";
	autotype["wdb"] = "application/vnd.ms-works";
	autotype["tra"] = "application/vnd.trueapp";
	autotype["map"] = "application/x-navimap";
	autotype["ppsx"] = "application/vnd.openxmlformats-officedocument.presentationml.slideshow";
	autotype["twds"] = "application/vnd.simtech-mindmapper";
	autotype["qcp"] = "audio/vnd.qcelp";
	autotype["sit"] = "application/x-stuffit";
	autotype["ip"] = "application/x-ip2";
	autotype["pyc"] = "applicaiton/x-bytecode.python";
	autotype["xlk"] = "application/x-excel";
	autotype["chm"] = "application/vnd.ms-htmlhelp";
	autotype["ims"] = "application/vnd.ms-ims";
	autotype["fh7"] = "image/x-freehand";
	autotype["aac"] = "audio/x-aac";
	autotype["m21"] = "application/mp21";
	autotype["p7b"] = "application/x-pkcs7-certificates";
	autotype["mny"] = "application/x-msmoney";
	autotype["fli"] = "video/x-fli";
	autotype["java"] = "text/x-java-source";
	autotype["xlsm"] = "application/vnd.ms-excel.sheet.macroenabled.12";
	autotype["vdo"] = "video/vdo";
	autotype["xul"] = "application/vnd.mozilla.xul+xml";
	autotype["uvg"] = "image/vnd.dece.graphic";
	autotype["str"] = "application/vnd.pg.format";
	autotype["pre"] = "application/vnd.lotus-freelance";
	autotype["flv"] = "video/x-flv";
	autotype["ra"] = "audio/x-realaudio";
	autotype["tpt"] = "application/vnd.trid.tpt";
	autotype["cbz"] = "application/x-cbr";
	autotype["mcp"] = "application/netmc";
	autotype["yang"] = "application/yang";
	autotype["mets"] = "application/mets+xml";
	autotype["ktr"] = "application/vnd.kahootz";
	autotype["fcs"] = "application/vnd.isac.fcs";
	autotype["bmp"] = "image/x-windows-bmp";
	autotype["daf"] = "application/vnd.mobius.daf";
	autotype["cha"] = "application/x-chat";
	autotype["me"] = "text/troff";
	autotype["xdm"] = "application/vnd.syncml.dm+xml";
	autotype["chrt"] = "application/vnd.kde.kchart";
	autotype["vcs"] = "text/x-vcalendar";
	autotype["pgp"] = "application/pgp-encrypted";
	autotype["mjp2"] = "video/mj2";
	autotype["pvb"] = "application/vnd.3gpp.pic-bw-var";
	autotype["kml"] = "application/vnd.google-earth.kml+xml";
	autotype["gml"] = "application/gml+xml";
	autotype["itp"] = "application/vnd.shana.informed.formtemplate";
	autotype["dvb"] = "video/vnd.dvb.file";
	autotype["cml"] = "chemical/x-cml";
	autotype["rq"] = "application/sparql-query";
	autotype["jad"] = "text/vnd.sun.j2me.app-descriptor";
	autotype["wsrc"] = "application/x-wais-source";
	autotype["m3u"] = "audio/x-mpegurl";
	autotype["sm"] = "application/vnd.stepmania.stepchart";
	autotype["mpy"] = "application/vnd.ibm.minipay";
	autotype["vox"] = "application/x-authorware-bin";
	autotype["zmm"] = "application/vnd.handheld-entertainment+xml";
	autotype["mxs"] = "application/vnd.triscape.mxs";
	autotype["mseq"] = "application/vnd.mseq";
	autotype["emma"] = "application/emma+xml";
	autotype["rmm"] = "audio/x-pn-realaudio";
	autotype["twd"] = "application/vnd.simtech-mindmapper";
	autotype["uu"] = "text/x-uuencode";
	autotype["lrm"] = "application/vnd.ms-lrm";
	autotype["x3dv"] = "model/x3d+vrml";
	autotype["xwd"] = "image/x-xwindowdump";
	autotype["py"] = "text/x-script.phyton";
	autotype["osfpvg"] = "application/vnd.yamaha.openscoreformat.osfpvg+xml";
	autotype["dxr"] = "application/x-director";
	autotype["fsc"] = "application/vnd.fsc.weblaunch";
	autotype["nsc"] = "application/x-conference";
	autotype["bcpio"] = "application/x-bcpio";
	autotype["link66"] = "application/vnd.route66.link66+xml";
	autotype["t3"] = "application/x-t3vm-image";
	autotype["moov"] = "video/quicktime";
	autotype["gsf"] = "application/x-font-ghostscript";
	autotype["wp5"] = "application/wordperfect6.0";
	autotype["x32"] = "application/x-authorware-bin";
	autotype["box"] = "application/vnd.previewsystems.box";
	autotype["webp"] = "image/webp";
	autotype["skp"] = "application/vnd.koan";
	autotype["osf"] = "application/vnd.yamaha.openscoreformat";
	autotype["bmi"] = "application/vnd.bmi";
	autotype["trm"] = "application/x-msterminal";
	autotype["c4u"] = "application/vnd.clonk.c4group";
	autotype["ufd"] = "application/vnd.ufdl";
	autotype["emf"] = "application/x-msmetafile";
	autotype["ktz"] = "application/vnd.kahootz";
	autotype["sisx"] = "application/vnd.symbian.install";
	autotype["msh"] = "model/mesh";
	autotype["list3820"] = "application/vnd.ibm.modcap";
	autotype["dmg"] = "application/x-apple-diskimage";
	autotype["f77"] = "text/x-fortran";
	autotype["skd"] = "application/vnd.koan";
	autotype["etx"] = "text/x-setext";
	autotype["shar"] = "application/x-shar";
	autotype["atx"] = "application/vnd.antix.game-component";
	autotype["pov"] = "model/x-pov";
	autotype["pvu"] = "paleovu/x-pv";
	autotype["lbd"] = "application/vnd.llamagraphics.life-balance.desktop";
	autotype["xslt"] = "application/xslt+xml";
	autotype["spc"] = "text/x-speech";
	autotype["pbd"] = "application/vnd.powerbuilder6";
	autotype["stf"] = "application/vnd.wt.stf";
	autotype["nif"] = "image/x-niff";
	autotype["uvt"] = "application/vnd.dece.ttml+xml";
	autotype["wmd"] = "application/x-ms-wmd";
	autotype["xbd"] = "application/vnd.fujixerox.docuworks.binder";
	autotype["fif"] = "image/fif";
	autotype["sdr"] = "application/sounder";
	autotype["tar"] = "application/x-tar";
	autotype["azf"] = "application/vnd.airzip.filesecure.azf";
	autotype["msty"] = "application/vnd.muvee.style";
	autotype["gam"] = "application/x-tads";
	autotype["grxml"] = "application/srgs+xml";
	autotype["otf"] = "font/opentype";
	autotype["rif"] = "application/reginfo+xml";
	autotype["rv"] = "video/vnd.rn-realvideo";
	autotype["xvml"] = "application/xv+xml";
	autotype["pkg"] = "application/octet-stream";
	autotype["z"] = "application/x-compressed";
	autotype["g3w"] = "application/vnd.geospace";
	autotype["ftc"] = "application/vnd.fluxtime.clip";
	autotype["p7s"] = "application/pkcs7-signature";
	autotype["omcd"] = "application/x-omcdatamaker";
	autotype["midi"] = "application/x-midi";
	autotype["sig"] = "application/pgp-signature";
	autotype["aas"] = "application/x-authorware-seg";
	autotype["skt"] = "application/vnd.koan";
	autotype["mie"] = "application/x-mie";
	autotype["turbot"] = "image/florian";
	autotype["c"] = "text/x-c";
	autotype["lnk"] = "application/x-ms-shortcut";
	autotype["gca"] = "application/x-gca-compressed";
	autotype["blorb"] = "application/x-blorb";
	autotype["wtb"] = "application/vnd.webturbo";
	autotype["xlw"] = "application/x-msexcel";
	autotype["xsm"] = "application/vnd.syncml+xml";
	autotype["movie"] = "video/x-sgi-movie";
	autotype["tfm"] = "application/x-tex-tfm";
	autotype["clkk"] = "application/vnd.crick.clicker.keyboard";
	autotype["uvp"] = "video/vnd.dece.pd";
	autotype["mkv"] = "video/x-matroska";
	autotype["hta"] = "application/hta";
	autotype["uvvg"] = "image/vnd.dece.graphic";
	autotype["html"] = "text/html";
	autotype["mrcx"] = "application/marcxml+xml";
	autotype["sbk"] = "application/x-tbook";
	autotype["fly"] = "text/vnd.fly";
	autotype["acc"] = "application/vnd.americandynamics.acc";
	autotype["bh2"] = "application/vnd.fujitsu.oasysprs";
	autotype["nfo"] = "text/x-nfo";
	autotype["ppd"] = "application/vnd.cups-ppd";
	autotype["mathml"] = "application/mathml+xml";
	autotype["icc"] = "application/vnd.iccprofile";
	autotype["ivp"] = "application/vnd.immervision-ivp";
	autotype["niff"] = "image/x-niff";
	autotype["ser"] = "application/java-serialized-object";
	autotype["htmls"] = "text/html";
	autotype["wg"] = "application/vnd.pmi.widget";
	autotype["svr"] = "x-world/x-svr";
	autotype["nap"] = "image/naplps";
	autotype["sol"] = "application/solids";
	autotype["vcd"] = "application/x-cdlink";
	autotype["s"] = "text/x-asm";
	autotype["i2g"] = "application/vnd.intergeo";
	autotype["iefs"] = "image/ief";
	autotype["qwt"] = "application/vnd.quark.quarkxpress";
	autotype["snd"] = "audio/x-adpcm";
	autotype["xls"] = "application/x-msexcel";
	autotype["listafp"] = "application/vnd.ibm.modcap";
	autotype["tfi"] = "application/thraud+xml";
	autotype["x3d"] = "model/x3d+xml";
	autotype["sxm"] = "application/vnd.sun.xml.math";
	autotype["dfac"] = "application/vnd.dreamfactory";
	autotype["sv4crc"] = "application/x-sv4crc";
	autotype["inf"] = "application/inf";
	autotype["htm"] = "text/html";
	autotype["luac"] = "application/x-lua-bytecode";
	autotype["h264"] = "video/h264";
	autotype["aiff"] = "audio/x-aiff";
	autotype["nlu"] = "application/vnd.neurolanguage.nlu";
	autotype["xsr"] = "video/x-amt-showrun";
	autotype["res"] = "application/x-dtbresource+xml";
	autotype["pcf"] = "application/x-font-pcf";
	autotype["ecelp4800"] = "audio/vnd.nuera.ecelp4800";
	autotype["ggb"] = "application/vnd.geogebra.file";
	autotype["slt"] = "application/vnd.epson.salt";
	autotype["wb1"] = "application/x-qpro";
	autotype["bat"] = "application/x-msdownload";
	autotype["xltx"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.template";
	autotype["mp2a"] = "audio/mpeg";
	autotype["c11amz"] = "application/vnd.cluetrust.cartomobile-config-pkg";
	autotype["hbci"] = "application/vnd.hbci";
	autotype["zir"] = "application/vnd.zul";
	autotype["mseed"] = "application/vnd.fdsn.mseed";
	autotype["wbs"] = "application/vnd.criticaltools.wbs+xml";
	autotype["aep"] = "application/vnd.audiograph";
	autotype["bdf"] = "application/x-font-bdf";
	autotype["emz"] = "application/x-msmetafile";
	autotype["fst"] = "image/vnd.fst";
	autotype["3dmf"] = "x-world/x-3dmf";
	autotype["maker"] = "application/vnd.framemaker";
	autotype["azs"] = "application/vnd.airzip.filesecure.azs";
	autotype["fdf"] = "application/vnd.fdf";
	autotype["uvx"] = "application/vnd.dece.unspecified";
	autotype["rdf"] = "application/rdf+xml";
	autotype["m3a"] = "audio/mpeg";
	autotype["mft"] = "application/rpki-manifest";
	autotype["tsv"] = "text/tab-separated-values";
	autotype["tpl"] = "application/vnd.groove-tool-template";
	autotype["clkx"] = "application/vnd.crick.clicker";
	autotype["xpl"] = "application/xproc+xml";
	autotype["cdmia"] = "application/cdmi-capability";
	autotype["gmx"] = "application/vnd.gmx";
	autotype["pgm"] = "image/x-portable-graymap";
	autotype["hh"] = "text/x-h";
	autotype["pps"] = "application/vnd.ms-powerpoint";
	autotype["txf"] = "application/vnd.mobius.txf";
	autotype["md"] = "text/x-markdown";
	autotype["xspf"] = "application/xspf+xml";
	autotype["cod"] = "application/vnd.rim.cod";
	autotype["htke"] = "application/vnd.kenameaapp";
	autotype["xps"] = "application/vnd.ms-xpsdocument";
	autotype["ddd"] = "application/vnd.fujixerox.ddd";
	autotype["sis"] = "application/vnd.symbian.install";
	autotype["azw"] = "application/vnd.amazon.ebook";
	autotype["stw"] = "application/vnd.sun.xml.writer.template";
	autotype["dxf"] = "image/vnd.dxf";
	autotype["gl"] = "video/x-gl";
	autotype["odc"] = "application/vnd.oasis.opendocument.chart";
	autotype["sfv"] = "text/x-sfv";
	autotype["apr"] = "application/vnd.lotus-approach";
	autotype["viv"] = "video/vnd.vivo";
	autotype["wmlsc"] = "application/vnd.wap.wmlscriptc";
	autotype["rp"] = "image/vnd.rn-realpix";
	autotype["lua"] = "text/x-lua";
	autotype["sdc"] = "application/vnd.stardivision.calc";
	autotype["nws"] = "message/rfc822";
	autotype["sdkd"] = "application/vnd.solent.sdkm+xml";
	autotype["scm"] = "video/x-scm";
	autotype["sl"] = "application/x-seelogo";
	autotype["afp"] = "application/vnd.ibm.modcap";
	autotype["gtw"] = "model/vnd.gtw";
	autotype["wcm"] = "application/vnd.ms-works";
	autotype["spp"] = "application/scvp-vp-response";
	autotype["qt"] = "video/quicktime";
	autotype["aifc"] = "audio/x-aiff";
	autotype["help"] = "application/x-helpfile";
	autotype["cpp"] = "text/x-c";
	autotype["aab"] = "application/x-authorware-bin";
	autotype["ico"] = "image/x-icon";
	autotype["p7c"] = "application/x-pkcs7-mime";
	autotype["it"] = "audio/it";
	autotype["svf"] = "image/x-dwg";
	autotype["def"] = "text/plain";
	autotype["mmr"] = "image/vnd.fujixerox.edmics-mmr";
	autotype["mp4a"] = "audio/mp4";
	autotype["htt"] = "text/webviewhtml";
	autotype["org"] = "application/vnd.lotus-organizer";
	autotype["scq"] = "application/scvp-cv-request";
	autotype["mpv"] = "application/x-project";
	autotype["ots"] = "application/vnd.oasis.opendocument.spreadsheet-template";
	autotype["fhc"] = "image/x-freehand";
	autotype["bed"] = "application/vnd.realvnc.bed";
	autotype["doc"] = "application/msword";
	autotype["fg5"] = "application/vnd.fujitsu.oasysgp";
	autotype["cmp"] = "application/vnd.yellowriver-custom-menu";
	autotype["cpt"] = "application/x-cpt";
	autotype["lha"] = "application/x-lha";
	autotype["ics"] = "text/calendar";
	autotype["kpt"] = "application/vnd.kde.kpresenter";
	autotype["edm"] = "application/vnd.novadigm.edm";
	autotype["mp4"] = "video/mp4";
	autotype["dcr"] = "application/x-director";
	autotype["deb"] = "application/x-debian-package";
	autotype["xlf"] = "application/x-xliff+xml";
	autotype["see"] = "application/vnd.seemail";
	autotype["naplps"] = "image/naplps";
	autotype["atomsvc"] = "application/atomsvc+xml";
	autotype["h261"] = "video/h261";
	autotype["gramps"] = "application/x-gramps-xml";
	autotype["vcard"] = "text/vcard";
	autotype["ogv"] = "video/ogg";
	autotype["xml"] = "text/xml";
	autotype["xlam"] = "application/vnd.ms-excel.addin.macroenabled.12";
	autotype["pskcxml"] = "application/pskc+xml";
	autotype["pm"] = "text/x-script.perl-module";
	autotype["spx"] = "audio/ogg";
	autotype["wad"] = "application/x-doom";
	autotype["cdmid"] = "application/cdmi-domain";
	autotype["elc"] = "application/x-elc";
	autotype["mdi"] = "image/vnd.ms-modi";
	autotype["ghf"] = "application/vnd.groove-help";
	autotype["sdw"] = "application/vnd.stardivision.writer";
	autotype["pptx"] = "application/vnd.openxmlformats-officedocument.presentationml.presentation";
	autotype["irm"] = "application/vnd.ibm.rights-management";
	autotype["unv"] = "application/i-deas";
	autotype["mgp"] = "application/vnd.osgeo.mapguide.package";
	autotype["funk"] = "audio/make";
	autotype["gpx"] = "application/gpx+xml";
	autotype["pkipath"] = "application/pkix-pkipath";
	autotype["xvm"] = "application/xv+xml";
	autotype["knp"] = "application/vnd.kinar";
	autotype["dvi"] = "application/x-dvi";
	autotype["psb"] = "application/vnd.3gpp.pic-bw-small";
	autotype["asc"] = "application/pgp-signature";
	autotype["my"] = "audio/make";
	autotype["jut"] = "image/jutvision";
	autotype["xlb"] = "application/x-excel";
	autotype["wp6"] = "application/wordperfect";
	autotype["mpeg"] = "video/mpeg";
	autotype["cla"] = "application/vnd.claymore";
	autotype["uil"] = "text/x-uil";
	autotype["atomcat"] = "application/atomcat+xml";
	autotype["djv"] = "image/vnd.djvu";
	autotype["x3dz"] = "model/x3d+xml";
	autotype["et3"] = "application/vnd.eszigno3+xml";
	autotype["u32"] = "application/x-authorware-bin";
	autotype["uvh"] = "video/vnd.dece.hd";
	autotype["rsd"] = "application/rsd+xml";
	autotype["uvvx"] = "application/vnd.dece.unspecified";
	autotype["mpga"] = "audio/mpeg";
	autotype["vsd"] = "application/vnd.visio";
	autotype["ncx"] = "application/x-dtbncx+xml";
	autotype["torrent"] = "application/x-bittorrent";
	autotype["bsh"] = "application/x-bsh";
	autotype["mus"] = "application/vnd.musician";
	autotype["ppsm"] = "application/vnd.ms-powerpoint.slideshow.macroenabled.12";
	autotype["appcache"] = "text/cache-manifest";
	autotype["imap"] = "application/x-httpd-imap";
	autotype["vmf"] = "application/vocaltec-media-file";
	autotype["man"] = "text/troff";
	autotype["htx"] = "text/html";
	autotype["in"] = "text/plain";
	autotype["uvu"] = "video/vnd.uvvu.mp4";
	autotype["tcap"] = "application/vnd.3gpp2.tcap";
	autotype["ssi"] = "text/x-server-parsed-html";
	autotype["obd"] = "application/x-msbinder";
	autotype["rtf"] = "text/richtext";
	autotype["mme"] = "application/base64";
	autotype["tao"] = "application/vnd.tao.intent-module-archive";
	autotype["potm"] = "application/vnd.ms-powerpoint.template.macroenabled.12";
	autotype["gif"] = "image/gif";
	autotype["thmx"] = "application/vnd.ms-officetheme";
	autotype["ext"] = "application/vnd.novadigm.ext";
	autotype["tr"] = "text/troff";
	autotype["xlsx"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
	autotype["ivu"] = "application/vnd.immervision-ivu";
	autotype["cif"] = "chemical/x-cif";
	autotype["jam"] = "application/vnd.jam";
	autotype["hpg"] = "application/vnd.hp-hpgl";
	autotype["fig"] = "application/x-xfig";
	autotype["xdp"] = "application/vnd.adobe.xdp+xml";
	autotype["uvva"] = "audio/vnd.dece.audio";
	autotype["mid"] = "x-music/x-midi";
	autotype["omc"] = "application/x-omc";
	autotype["spot"] = "text/vnd.in3d.spot";
	autotype["mov"] = "video/quicktime";
	autotype["gv"] = "text/vnd.graphviz";
	autotype["otc"] = "application/vnd.oasis.opendocument.chart-template";
	autotype["metalink"] = "application/metalink+xml";
	autotype["cmc"] = "application/vnd.cosmocaller";
	autotype["wiz"] = "application/msword";
	autotype["srt"] = "application/x-subrip";
	autotype["fgd"] = "application/x-director";
	autotype["jpe"] = "image/pjpeg";
	autotype["clkw"] = "application/vnd.crick.clicker.wordbank";
	autotype["mfm"] = "application/vnd.mfmp";
	autotype["ssm"] = "application/streamingmedia";
	autotype["dtd"] = "application/xml-dtd";
	autotype["ifm"] = "application/vnd.shana.informed.formdata";
	autotype["pas"] = "text/x-pascal";
	autotype["bz"] = "application/x-bzip";
	autotype["flx"] = "text/vnd.fmi.flexstor";
	autotype["g"] = "text/plain";
	autotype["dbk"] = "application/docbook+xml";
	autotype["ac"] = "application/pkix-attr-cert";
	autotype["ink"] = "application/inkml+xml";
	autotype["x3dvz"] = "model/x3d+vrml";
	autotype["wpd"] = "application/x-wpwin";
	autotype["kne"] = "application/vnd.kinar";
	autotype["musicxml"] = "application/vnd.recordare.musicxml+xml";
	autotype["tbk"] = "application/x-tbook";
	autotype["drw"] = "application/drafting";
	autotype["cap"] = "application/vnd.tcpdump.pcap";
	autotype["lvp"] = "audio/vnd.lucent.voice";
	autotype["kfo"] = "application/vnd.kde.kformula";
	autotype["sitx"] = "application/x-stuffitx";
	autotype["jnlp"] = "application/x-java-jnlp-file";
	autotype["hvp"] = "application/vnd.yamaha.hv-voice";
	autotype["sv4cpio"] = "application/x-sv4cpio";
	autotype["mpkg"] = "application/vnd.apple.installer+xml";
	autotype["xer"] = "application/patch-ops-error+xml";
	autotype["cdmic"] = "application/cdmi-container";
	autotype["aso"] = "application/vnd.accpac.simply.aso";
	autotype["pki"] = "application/pkixcmp";
	autotype["oa2"] = "application/vnd.fujitsu.oasys2";
	autotype["nnd"] = "application/vnd.noblenet-directory";
	autotype["iso"] = "application/x-iso9660-image";
	autotype["cdmiq"] = "application/cdmi-queue";
	autotype["qxl"] = "application/vnd.quark.quarkxpress";
	autotype["paw"] = "application/vnd.pawaafile";
	autotype["csp"] = "application/vnd.commonspace";
	autotype["jlt"] = "application/vnd.hp-jlyt";
	autotype["mxl"] = "application/vnd.recordare.musicxml";
	autotype["rexx"] = "text/x-script.rexx";
	autotype["crx"] = "application/x-chrome-extension";
	autotype["ksp"] = "application/vnd.kde.kspread";
	autotype["ms"] = "text/troff";
	autotype["fcdt"] = "application/vnd.adobe.formscentral.fcdt";
	autotype["der"] = "application/x-x509-ca-cert";
	autotype["oga"] = "audio/ogg";
	autotype["wbmp"] = "image/vnd.wap.wbmp";
	autotype["cat"] = "application/vnd.ms-pki.seccat";
	autotype["es"] = "application/x-esrehber";
	autotype["gph"] = "application/vnd.flographit";
	autotype["chat"] = "application/x-chat";
	autotype["stk"] = "application/hyperstudio";
	autotype["m4p"] = "application/mp4";
	autotype["mht"] = "message/rfc822";
	autotype["p10"] = "application/x-pkcs10";
	autotype["wax"] = "audio/x-ms-wax";
	autotype["sst"] = "application/vnd.ms-pki.certstore";
	autotype["ufdl"] = "application/vnd.ufdl";
	autotype["src"] = "application/x-wais-source";
	autotype["jpeg"] = "image/pjpeg";
	autotype["ttl"] = "text/turtle";
	autotype["jfif"] = "image/pjpeg";
	autotype["ami"] = "application/vnd.amiga.ami";
	autotype["ai"] = "application/postscript";
	autotype["xltm"] = "application/vnd.ms-excel.template.macroenabled.12";
	autotype["mar"] = "application/octet-stream";
	autotype["mjpg"] = "video/x-motion-jpeg";
	autotype["fzs"] = "application/vnd.fuzzysheet";
	autotype["pm5"] = "application/x-pagemaker";
	autotype["ecelp7470"] = "audio/vnd.nuera.ecelp7470";
	autotype["xlsb"] = "application/vnd.ms-excel.sheet.binary.macroenabled.12";
	autotype["texi"] = "application/x-texinfo";
	autotype["mpn"] = "application/vnd.mophun.application";
	autotype["xld"] = "application/x-excel";
	autotype["cgm"] = "image/cgm";
	autotype["fh5"] = "image/x-freehand";
	autotype["curl"] = "text/vnd.curl";
	autotype["omdoc"] = "application/omdoc+xml";
	autotype["spl"] = "application/x-futuresplash";
	autotype["pml"] = "application/vnd.ctc-posml";
	autotype["mobi"] = "application/x-mobipocket-ebook";
	autotype["ivy"] = "application/x-livescreen";
	autotype["wpl"] = "application/vnd.ms-wpl";
	autotype["dotm"] = "application/vnd.ms-word.template.macroenabled.12";
	autotype["vqe"] = "audio/x-twinvq-plugin";
	autotype["pub"] = "application/x-mspublisher";
	autotype["saf"] = "application/vnd.yamaha.smaf-audio";
	autotype["lzh"] = "application/x-lzh";
	autotype["ltx"] = "application/x-latex";
	autotype["a"] = "application/octet-stream";
	autotype["sgm"] = "text/x-sgml";
	autotype["pct"] = "image/x-pict";
	autotype["ltf"] = "application/vnd.frogans.ltf";
	autotype["3dml"] = "text/vnd.in3d.3dml";
	autotype["mod"] = "audio/x-mod";
	autotype["rpm"] = "audio/x-pn-realaudio-plugin";
	autotype["deepv"] = "application/x-deepv";
	autotype["uris"] = "text/uri-list";
	autotype["ima"] = "application/x-ima";
	autotype["docm"] = "application/vnd.ms-word.document.macroenabled.12";
	autotype["lam"] = "audio/x-liveaudio";
	autotype["wqd"] = "application/vnd.wqd";
	autotype["qtc"] = "video/x-qtc";
	autotype["m4v"] = "video/x-m4v";
	autotype["stc"] = "application/vnd.sun.xml.calc.template";
	autotype["plb"] = "application/vnd.3gpp.pic-bw-large";
	autotype["ris"] = "application/x-research-info-systems";
	autotype["pgn"] = "application/x-chess-pgn";
	autotype["gxf"] = "application/gxf";
	autotype["aps"] = "application/mime";
	autotype["sdd"] = "application/vnd.stardivision.impress";
	autotype["diff"] = "text/plain";
	autotype["otg"] = "application/vnd.oasis.opendocument.graphics-template";
	autotype["eps"] = "application/postscript";
	autotype["zip"] = "application/zip";
	autotype["dl"] = "video/x-dl";
	autotype["dist"] = "application/octet-stream";
	autotype["afm"] = "application/x-font-type1";
	autotype["xpr"] = "application/vnd.is-xpr";
	autotype["rlc"] = "image/vnd.fujixerox.edmics-rlc";
	autotype["123"] = "application/vnd.lotus-1-2-3";
	autotype["shtml"] = "text/x-server-parsed-html";
	autotype["jcm"] = "application/x-java-commerce";
	autotype["spq"] = "application/scvp-vp-request";
	autotype["jisp"] = "application/vnd.jisp";
	autotype["mads"] = "application/mads+xml";
	autotype["ncm"] = "application/vnd.nokia.configuration-message";
	autotype["xl"] = "application/excel";
	autotype["mdb"] = "application/x-msaccess";
	autotype["wsdl"] = "application/wsdl+xml";
	autotype["ods"] = "application/vnd.oasis.opendocument.spreadsheet";
	autotype["sgl"] = "application/vnd.stardivision.writer-global";
	autotype["inkml"] = "application/inkml+xml";
	autotype["vqf"] = "audio/x-twinvq";
	autotype["cst"] = "application/x-director";
	autotype["pl"] = "text/x-script.perl";
	autotype["sfs"] = "application/vnd.spotfire.sfs";
	autotype["markdown"] = "text/x-markdown";
	autotype["xpw"] = "application/vnd.intercon.formnet";
	autotype["mkd"] = "text/x-markdown";
	autotype["c4p"] = "application/vnd.clonk.c4group";
	autotype["aip"] = "text/x-audiosoft-intra";
	autotype["scd"] = "application/x-msschedule";
	autotype["vtu"] = "model/vnd.vtu";
	autotype["ksh"] = "text/x-script.ksh";
	autotype["fti"] = "application/vnd.anser-web-funds-transfer-initiation";
	autotype["qif"] = "image/x-quicktime";
	autotype["rt"] = "text/vnd.rn-realtext";
	autotype["class"] = "application/x-java-class";
	autotype["cdf"] = "application/x-netcdf";
	autotype["cbt"] = "application/x-cbr";
	autotype["meta4"] = "application/metalink4+xml";
	autotype["rnx"] = "application/vnd.rn-realplayer";
	autotype["ipfix"] = "application/ipfix";
	autotype["sgi"] = "image/sgi";
	autotype["application"] = "application/x-ms-application";
	autotype["vda"] = "application/vda";
	autotype["fh4"] = "image/x-freehand";
	autotype["igm"] = "application/vnd.insors.igm";
	autotype["smil"] = "application/smil+xml";
	autotype["flo"] = "application/vnd.micrografx.flo";
	autotype["csv"] = "text/csv";
	autotype["efif"] = "application/vnd.picsel";
	autotype["mscml"] = "application/mediaservercontrol+xml";
	autotype["atom"] = "application/atom+xml";
	autotype["eva"] = "application/x-eva";
	autotype["karbon"] = "application/vnd.kde.karbon";
	autotype["prc"] = "application/x-mobipocket-ebook";
	autotype["woff"] = "application/x-font-woff";
	autotype["ppz"] = "application/mspowerpoint";
	autotype["frame"] = "application/vnd.framemaker";
	autotype["pcurl"] = "application/vnd.curl.pcurl";
	autotype["sxd"] = "application/vnd.sun.xml.draw";
	autotype["asx"] = "video/x-ms-asf-plugin";
	autotype["p"] = "text/x-pascal";
	autotype["webm"] = "video/webm";
	autotype["iges"] = "model/iges";
	autotype["plf"] = "application/vnd.pocketlearn";
	autotype["uvvi"] = "image/vnd.dece.graphic";
	autotype["gac"] = "application/vnd.groove-account";
	autotype["vxml"] = "application/voicexml+xml";
	autotype["aw"] = "application/applixware";
	autotype["ott"] = "application/vnd.oasis.opendocument.text-template";
	autotype["dgc"] = "application/x-dgc-compressed";
	autotype["cfs"] = "application/x-cfs-compressed";
	autotype["vtt"] = "text/vtt";
	autotype["jps"] = "image/x-jps";
	autotype["svg"] = "image/svg+xml";
	autotype["ief"] = "image/ief";
	autotype["dts"] = "audio/vnd.dts";
	autotype["dart"] = "application/vnd.dart";
	autotype["qtif"] = "image/x-quicktime";
	autotype["pya"] = "audio/vnd.ms-playready.media.pya";
	autotype["rmp"] = "audio/x-pn-realaudio-plugin";
	autotype["vss"] = "application/vnd.visio";
	autotype["tiff"] = "image/x-tiff";
	autotype["crd"] = "application/x-mscardfile";
	autotype["c4f"] = "application/vnd.clonk.c4group";
	autotype["svd"] = "application/vnd.svd";
	autotype["c4d"] = "application/vnd.clonk.c4group";
	autotype["la"] = "audio/x-nspaudio";
	autotype["vcx"] = "application/vnd.vcx";
	autotype["xpdl"] = "application/xml";
	autotype["vis"] = "application/vnd.visionary";
	autotype["js"] = "application/javascript";
	autotype["cdx"] = "chemical/x-cdx";
	autotype["pyo"] = "application/x-python-code";
	autotype["vob"] = "video/x-ms-vob";
	autotype["btif"] = "image/prs.btif";
	autotype["zoo"] = "application/octet-stream";
	autotype["jpgv"] = "video/jpeg";
	autotype["qd3"] = "x-world/x-3dmf";
	autotype["vos"] = "video/vosaic";
	autotype["uva"] = "audio/vnd.dece.audio";
	autotype["ez2"] = "application/vnd.ezpix-album";
	autotype["dmp"] = "application/vnd.tcpdump.pcap";
	autotype["bz2"] = "application/x-bzip2";
	autotype["vql"] = "audio/x-twinvq-plugin";
	autotype["xfdf"] = "application/vnd.adobe.xfdf";
	autotype["gdl"] = "model/vnd.gdl";
	autotype["mhtml"] = "message/rfc822";
	autotype["w60"] = "application/wordperfect6.0";
	autotype["zaz"] = "application/vnd.zzazz.deck+xml";
	autotype["pwz"] = "application/vnd.ms-powerpoint";
	autotype["mng"] = "video/x-mng";
	autotype["sql"] = "application/x-sql";
	autotype["event-stream"] = "text/event-stream";
	autotype["stp"] = "application/step";
	autotype["uvvt"] = "application/vnd.dece.ttml+xml";
	autotype["rcprofile"] = "application/vnd.ipunplugged.rcprofile";
	autotype["wks"] = "application/vnd.ms-works";
	autotype["sldx"] = "application/vnd.openxmlformats-officedocument.presentationml.slide";
	autotype["qxt"] = "application/vnd.quark.quarkxpress";
	autotype["au"] = "audio/basic";
	autotype["wml"] = "text/vnd.wap.wml";
	autotype["wmlc"] = "application/vnd.wap.wmlc";
	autotype["csml"] = "chemical/x-csml";
	autotype["onetmp"] = "application/onenote";
	autotype["pcl"] = "application/x-pcl";
	autotype["xfdl"] = "application/vnd.xfdl";
	autotype["f90"] = "text/x-fortran";
	autotype["cdxml"] = "application/vnd.chemdraw+xml";
	autotype["word"] = "application/msword";
	autotype["ntf"] = "application/vnd.nitf";
	autotype["dxp"] = "application/vnd.spotfire.dxp";
	autotype["mp4s"] = "application/mp4";
	autotype["eml"] = "message/rfc822";
	autotype["otp"] = "application/vnd.oasis.opendocument.presentation-template";
	autotype["aif"] = "audio/x-aiff";
	autotype["cii"] = "application/vnd.anser-web-certificate-issue-initiation";
	autotype["les"] = "application/vnd.hhe.lesson-player";
	autotype["svc"] = "application/vnd.dvb.service";
	autotype["lsp"] = "text/x-script.lisp";
	autotype["hvd"] = "application/vnd.yamaha.hv-dic";
	autotype["vivo"] = "video/vnd.vivo";
	autotype["oprc"] = "application/vnd.palm";
	autotype["mcurl"] = "text/vnd.curl.mcurl";
	autotype["c++"] = "text/plain";
	autotype["xyz"] = "chemical/x-xyz";
	autotype["uvvv"] = "video/vnd.dece.video";
	autotype["wtk"] = "application/x-wintalk";
	autotype["gim"] = "application/vnd.groove-identity-message";
	autotype["cdkey"] = "application/vnd.mediastation.cdkey";
	autotype["gqs"] = "application/vnd.grafeq";
	autotype["roa"] = "application/rpki-roa";
	autotype["mp21"] = "application/mp21";
	autotype["mbox"] = "application/mbox";
	autotype["xdr"] = "video/x-amt-demorun";
	autotype["g2w"] = "application/vnd.geoplan";
	autotype["ecelp9600"] = "audio/vnd.nuera.ecelp9600";
	autotype["mm"] = "application/x-meme";
	autotype["xdssc"] = "application/dssc+xml";
	autotype["mmf"] = "application/vnd.smaf";
	autotype["t"] = "text/troff";
	autotype["uvi"] = "image/vnd.dece.graphic";
	autotype["sdkm"] = "application/vnd.solent.sdkm+xml";
	autotype["cct"] = "application/x-director";
	autotype["xif"] = "image/vnd.xiff";
	autotype["uvm"] = "video/vnd.dece.mobile";
	autotype["pfx"] = "application/x-pkcs12";
	autotype["7z"] = "application/x-7z-compressed";
	autotype["qxd"] = "application/vnd.quark.quarkxpress";
	autotype["portpkg"] = "application/vnd.macports.portpkg";
	autotype["rf"] = "image/vnd.rn-realflash";
	autotype["gsd"] = "audio/x-gsm";
	autotype["wbxml"] = "application/vnd.wap.wbxml";
	autotype["sh"] = "text/x-script.sh";
	autotype["ssf"] = "application/vnd.epson.ssf";
	autotype["ktx"] = "image/ktx";
	autotype["fpx"] = "image/vnd.net-fpx";
	autotype["xpm"] = "image/xpm";
	autotype["docx"] = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
	autotype["setreg"] = "application/set-registration-initiation";
	autotype["latex"] = "application/x-latex";
	autotype["cba"] = "application/x-cbr";
	autotype["arj"] = "application/octet-stream";
	autotype["xpx"] = "application/vnd.intercon.formnet";
	autotype["npx"] = "image/vnd.net-fpx";
	autotype["avi"] = "video/x-msvideo";
	autotype["pfa"] = "application/x-font-type1";
	autotype["talk"] = "text/x-speech";
	autotype["xop"] = "application/xop+xml";
	autotype["3ds"] = "image/x-3ds";
	autotype["ei6"] = "application/vnd.pg.osasli";
	autotype["jpm"] = "video/jpm";
	autotype["dsc"] = "text/prs.lines.tag";
	autotype["wq1"] = "application/x-lotus";
	autotype["adp"] = "audio/adpcm";
	autotype["xar"] = "application/vnd.xara";
	autotype["igs"] = "model/iges";
	autotype["z3"] = "application/x-zmachine";
	autotype["eol"] = "audio/vnd.digital-winds";
	autotype["z6"] = "application/x-zmachine";
	autotype["wrl"] = "x-world/x-vrml";
	autotype["esf"] = "application/vnd.epson.esf";
	autotype["zsh"] = "text/x-script.zsh";
	autotype["oa3"] = "application/vnd.fujitsu.oasys3";
	autotype["utz"] = "application/vnd.uiq.theme";
	autotype["xpix"] = "application/x-vnd.ls-xpix";
	autotype["gsp"] = "application/x-gsp";
	autotype["xla"] = "application/x-msexcel";
	autotype["sxi"] = "application/vnd.sun.xml.impress";
	autotype["msf"] = "application/vnd.epson.msf";
	autotype["afl"] = "video/animaflex";
	autotype["abc"] = "text/vnd.abc";
	autotype["crl"] = "application/pkix-crl";
	autotype["asf"] = "video/x-ms-asf";
	autotype["pfunk"] = "audio/make";
	autotype["pfm"] = "application/x-font-type1";
	autotype["dd2"] = "application/vnd.oma.dd2+xml";
	autotype["srx"] = "application/sparql-results+xml";
	autotype["uvvs"] = "video/vnd.dece.sd";
	autotype["p8"] = "application/pkcs8";
	autotype["oxps"] = "application/oxps";
	autotype["aos"] = "application/x-nokia-9000-communicator-add-on-software";
	autotype["swa"] = "application/x-director";
	autotype["mb"] = "application/mathematica";
	autotype["ez"] = "application/andrew-inset";
	autotype["gsm"] = "audio/x-gsm";
	autotype["z7"] = "application/x-zmachine";
	autotype["n3"] = "text/n3";
	autotype["z8"] = "application/x-zmachine";
	autotype["pot"] = "application/vnd.ms-powerpoint";
	autotype["mcf"] = "text/mcf";
	autotype["apk"] = "application/vnd.android.package-archive";
	autotype["wp"] = "application/wordperfect";
	autotype["mpc"] = "application/vnd.mophun.certificate";
	autotype["ram"] = "audio/x-pn-realaudio";
	autotype["ins"] = "application/x-internett-signup";
	autotype["vew"] = "application/groupwise";
	autotype["distz"] = "application/octet-stream";
	autotype["uoml"] = "application/vnd.uoml+xml";
	autotype["csh"] = "text/x-script.csh";
	autotype["pcap"] = "application/vnd.tcpdump.pcap";
	autotype["jsonml"] = "application/jsonml+json";
	autotype["odt"] = "application/vnd.oasis.opendocument.text";
	autotype["boz"] = "application/x-bzip2";
	autotype["deploy"] = "application/octet-stream";
	autotype["ps"] = "application/postscript";
	autotype["epub"] = "application/epub+zip";
	autotype["smf"] = "application/vnd.stardivision.math";
	autotype["ts"] = "video/MP2T";
	autotype["png"] = "image/png";
	autotype["jar"] = "application/java-archive";
	autotype["pls"] = "application/pls+xml";
	autotype["gz"] = "application/x-gzip";
	autotype["voc"] = "audio/x-voc";
	autotype["dataless"] = "application/vnd.fdsn.seed";
	autotype["udeb"] = "application/x-debian-package";
	autotype["kia"] = "application/vnd.kidspiration";
	autotype["unityweb"] = "application/vnd.unity";
	autotype["wspolicy"] = "application/wspolicy+xml";
	autotype["mbk"] = "application/vnd.mobius.mbk";
	autotype["ait"] = "application/vnd.dvb.ait";
	autotype["shf"] = "application/shf+xml";
	autotype["web"] = "application/vnd.xara";
	autotype["uvvp"] = "video/vnd.dece.pd";
	autotype["txt"] = "text/plain";
	autotype["uvvm"] = "video/vnd.dece.mobile";
	autotype["mj2"] = "video/mj2";
	autotype["qwd"] = "application/vnd.quark.quarkxpress";
	autotype["xlm"] = "application/x-excel";
	autotype["mmd"] = "application/vnd.chipnuts.karaoke-mmd";
	autotype["xm"] = "audio/xm";
	autotype["ecma"] = "application/ecmascript";
	autotype["mpm"] = "application/vnd.blueice.multipass";
	autotype["dot"] = "application/msword";
	autotype["vst"] = "application/vnd.visio";
	autotype["hal"] = "application/vnd.hal+xml";
	autotype["odg"] = "application/vnd.oasis.opendocument.graphics";
	autotype["json"] = "text/plain";
	autotype["dms"] = "application/octet-stream";
	autotype["tgz"] = "application/x-compressed";
	autotype["uri"] = "text/uri-list";
	autotype["dif"] = "video/x-dv";
	autotype["mc1"] = "application/vnd.medcalcdata";
	autotype["sdml"] = "text/plain";
	autotype["aam"] = "application/x-authorware-map";
	autotype["rar"] = "application/x-rar-compressed";
	autotype["igl"] = "application/vnd.igloader";
	autotype["exi"] = "application/exi";
	autotype["hlb"] = "text/x-script";
	autotype["m2a"] = "audio/mpeg";
	autotype["clkt"] = "application/vnd.crick.clicker.template";
	autotype["xgz"] = "xgl/drawing";
	autotype["xhvml"] = "application/xv+xml";
	autotype["conf"] = "text/plain";
	autotype["uvd"] = "application/vnd.dece.data";
	autotype["hqx"] = "application/x-mac-binhex40";
	autotype["ssml"] = "application/ssml+xml";
	autotype["tif"] = "image/x-tiff";
	autotype["z5"] = "application/x-zmachine";
	autotype["crt"] = "application/x-x509-user-cert";
	autotype["qam"] = "application/vnd.epson.quickanime";
	autotype["webapp"] = "application/x-web-app-manifest+json";
	autotype["unis"] = "text/uri-list";
	autotype["wdp"] = "image/vnd.ms-photo";
	autotype["mpa"] = "video/mpeg";
	autotype["sub"] = "text/vnd.dvb.subtitle";
	autotype["std"] = "application/vnd.sun.xml.draw.template";
	autotype["cmx"] = "image/x-cmx";
	autotype["cmdf"] = "chemical/x-cmdf";
	autotype["mka"] = "audio/x-matroska";
	autotype["uvv"] = "video/vnd.dece.video";
	autotype["dv"] = "video/x-dv";
	autotype["hps"] = "application/vnd.hp-hps";
	autotype["htc"] = "text/x-component";
	autotype["lzx"] = "application/x-lzx";
	autotype["z2"] = "application/x-zmachine";
	autotype["mqy"] = "application/vnd.mobius.mqy";
	autotype["clp"] = "application/x-msclip";
	autotype["sdp"] = "application/x-sdp";
	autotype["vor"] = "application/vnd.stardivision.writer";
	autotype["dp"] = "application/vnd.osgi.dp";
	autotype["sru"] = "application/sru+xml";
	autotype["p7r"] = "application/x-pkcs7-certreqresp";
	autotype["xap"] = "application/x-silverlight-app";
	autotype["env"] = "application/x-envoy";
	autotype["bin"] = "application/x-macbinary";
	autotype["vrt"] = "x-world/x-vrt";
	autotype["seed"] = "application/vnd.fdsn.seed";
	autotype["davmount"] = "application/davmount+xml";
	autotype["wmx"] = "video/x-ms-wmx";
	autotype["oas"] = "application/vnd.fujitsu.oasys";
	autotype["tmo"] = "application/vnd.tmobile-livetv";
	autotype["ppam"] = "application/vnd.ms-powerpoint.addin.macroenabled.12";
	autotype["pptm"] = "application/vnd.ms-powerpoint.presentation.macroenabled.12";
	autotype["edx"] = "application/vnd.novadigm.edx";
	autotype["pwn"] = "application/vnd.3m.post-it-notes";
	autotype["cer"] = "application/x-x509-ca-cert";
	autotype["set"] = "application/set";
	autotype["tga"] = "image/x-tga";
	autotype["m4u"] = "video/vnd.mpegurl";
	autotype["lma"] = "audio/x-nspaudio";
	autotype["urls"] = "text/uri-list";
	autotype["wmls"] = "text/vnd.wap.wmlscript";
	autotype["sea"] = "application/x-sea";
	autotype["igx"] = "application/vnd.micrografx.igx";
	autotype["pyv"] = "video/vnd.ms-playready.media.pyv";
	autotype["f4v"] = "video/x-f4v";
	autotype["rep"] = "application/vnd.businessobjects";
	autotype["rdz"] = "application/vnd.data-vision.rdz";
	autotype["ttc"] = "application/x-font-ttf";
	autotype["swi"] = "application/vnd.aristanetworks.swi";
	autotype["nc"] = "application/x-netcdf";
	autotype["mpp"] = "application/vnd.ms-project";
	autotype["ma"] = "application/mathematica";
	autotype["ulx"] = "application/x-glulx";
	autotype["prt"] = "application/pro_eng";
	autotype["tei"] = "application/tei+xml";
	autotype["ipk"] = "application/vnd.shana.informed.package";
	autotype["odp"] = "application/vnd.oasis.opendocument.presentation";
	autotype["tcsh"] = "text/x-script.tcsh";
	autotype["ifb"] = "text/calendar";
	autotype["odi"] = "application/vnd.oasis.opendocument.image";
	autotype["3dm"] = "x-world/x-3dmf";
	autotype["msl"] = "application/vnd.mobius.msl";
	autotype["evy"] = "application/x-envoy";
	autotype["frl"] = "application/freeloader";
	autotype["g3"] = "image/g3fax";
	autotype["for"] = "text/x-fortran";
	autotype["sse"] = "application/vnd.kodak-descriptor";
	autotype["joda"] = "application/vnd.joost.joda-archive";
	autotype["sprite"] = "application/x-sprite";
	autotype["arc"] = "application/x-freearc";
	autotype["uvvu"] = "video/vnd.uvvu.mp4";
	autotype["vrml"] = "x-world/x-vrml";
	autotype["tsi"] = "audio/tsp-audio";
	autotype["exe"] = "application/x-msdownload";
	autotype["gre"] = "application/vnd.geometry-explorer";
	autotype["bpk"] = "application/octet-stream";
	autotype["pnm"] = "image/x-portable-anymap";
	autotype["mxu"] = "video/vnd.mpegurl";
	autotype["mc"] = "application/x-magic-cap-package-1.0";
	autotype["tsp"] = "audio/tsplayer";
	autotype["semf"] = "application/vnd.semf";
	autotype["sic"] = "application/vnd.wap.sic";
	autotype["m1v"] = "video/mpeg";
	autotype["iota"] = "application/vnd.astraea-software.iota";
	autotype["rpst"] = "application/vnd.nokia.radio-preset";
	autotype["hvs"] = "application/vnd.yamaha.hv-script";
	autotype["rmi"] = "audio/midi";
	autotype["flw"] = "application/vnd.kde.kivio";
	autotype["ace"] = "application/x-ace-compressed";
	autotype["pqa"] = "application/vnd.palm";
	autotype["h263"] = "video/h263";
	autotype["dpg"] = "application/vnd.dpgraph";
	autotype["fxp"] = "application/vnd.adobe.fxp";
	autotype["pclxl"] = "application/vnd.hp-pclxl";
	autotype["kpxx"] = "application/vnd.ds-keypoint";
	autotype["kon"] = "application/vnd.kde.kontour";
	autotype["ice"] = "x-conference/x-cooltalk";
	autotype["p7a"] = "application/x-pkcs7-signature";
	autotype["hgl"] = "application/vnd.hp-hpgl";
	autotype["aim"] = "application/x-aim";
	autotype["ivr"] = "i-world/i-vrml";
	autotype["nix"] = "application/x-mix-transfer";
	autotype["sxw"] = "application/vnd.sun.xml.writer";
	autotype["jav"] = "text/x-java-source";
	autotype["teacher"] = "application/vnd.smart.teacher";
	autotype["rs"] = "application/rls-services+xml";
	autotype["php"] = "text/x-php";
	autotype["roff"] = "text/troff";
	autotype["umj"] = "application/vnd.umajin";
	autotype["wmz"] = "application/x-msmetafile";
	autotype["plc"] = "application/vnd.mobius.plc";
	autotype["dump"] = "application/octet-stream";
	autotype["text"] = "text/plain";
	autotype["rng"] = "application/vnd.nokia.ringing-tone";
	autotype["qd3d"] = "x-world/x-3dmf";
	autotype["saveme"] = "aapplication/octet-stream";
	autotype["xlc"] = "application/x-excel";
	autotype["kwt"] = "application/vnd.kde.kword";
	autotype["boo"] = "application/book";
	autotype["so"] = "application/octet-stream";
	autotype["wk1"] = "application/x-123";
	autotype["vcf"] = "text/x-vcard";
	autotype["qti"] = "image/x-quicktime";
	autotype["qps"] = "application/vnd.publishare-delta-tree";
	autotype["wm"] = "video/x-ms-wm";
	autotype["djvu"] = "image/vnd.djvu";
	autotype["ngdat"] = "application/vnd.nokia.n-gage.data";
	autotype["dna"] = "application/vnd.dna";
	autotype["snf"] = "application/x-font-snf";
	autotype["sgml"] = "text/x-sgml";
	autotype["semd"] = "application/vnd.semd";
	autotype["bdm"] = "application/vnd.syncml.dm+wbxml";
	autotype["stl"] = "application/x-navistyle";
	autotype["ppt"] = "application/x-mspowerpoint";
	autotype["qfx"] = "application/vnd.intu.qfx";
	autotype["mpg4"] = "video/mp4";
	autotype["onepkg"] = "application/onenote";
	autotype["ez3"] = "application/vnd.ezpix-package";
	autotype["css"] = "text/css";
	autotype["sxc"] = "application/vnd.sun.xml.calc";
	autotype["ssdl"] = "application/ssdl+xml";
	autotype["pfr"] = "application/font-tdpfr";
	autotype["gss"] = "application/x-gss";
	autotype["clkp"] = "application/vnd.crick.clicker.palette";
	autotype["skm"] = "application/vnd.koan";
	autotype["dcurl"] = "text/vnd.curl.dcurl";
	autotype["pdb"] = "application/vnd.palm";
	autotype["sxg"] = "application/vnd.sun.xml.writer.global";
	autotype["wmf"] = "application/x-msmetafile";
	autotype["texinfo"] = "application/x-texinfo";
	autotype["xdw"] = "application/vnd.fujixerox.docuworks";
	autotype["psf"] = "application/x-font-linux-psf";
	autotype["mp4v"] = "video/mp4";
	autotype["mag"] = "application/vnd.ecowin.chart";
	autotype["mime"] = "www/mime";
	autotype["mxml"] = "application/xv+xml";
	autotype["mlp"] = "application/vnd.dolby.mlp";
	autotype["fnc"] = "application/vnd.frogans.fnc";
	autotype["install"] = "application/x-install-instructions";
	autotype["ptid"] = "application/vnd.pvi.ptid1";
	autotype["x3dbz"] = "model/x3d+binary";
	autotype["setpay"] = "application/set-payment-initiation";
	autotype["nitf"] = "application/vnd.nitf";
	autotype["xaml"] = "application/xaml+xml";
	autotype["dwf"] = "model/vnd.dwf";
	autotype["fvt"] = "video/vnd.fvt";
	autotype["wvx"] = "video/x-ms-wvx";
	autotype["lst"] = "text/plain";
	autotype["hdf"] = "application/x-hdf";
	autotype["smv"] = "video/x-smv";
	autotype["xht"] = "application/xhtml+xml";
	autotype["cu"] = "application/cu-seeme";
	autotype["xlv"] = "application/x-excel";
	autotype["swf"] = "application/x-shockwave-flash";
	autotype["o"] = "application/octet-stream";
	autotype["nvd"] = "application/x-navidoc";
	autotype["pdf"] = "application/pdf";
	autotype["rnc"] = "application/relax-ng-compact-syntax";
	autotype["mzz"] = "application/x-vnd.audioexplosion.mzz";
	autotype["z4"] = "application/x-zmachine";
	autotype["isu"] = "video/x-isvideo";
	autotype["msi"] = "application/x-msdownload";
	autotype["opml"] = "text/x-opml";
	autotype["gtar"] = "application/x-gtar";
	autotype["xdf"] = "application/xcap-diff+xml";
	autotype["rip"] = "audio/vnd.rip";
	autotype["iif"] = "application/vnd.shana.informed.interchange";
	autotype["potx"] = "application/vnd.openxmlformats-officedocument.presentationml.template";
	autotype["mks"] = "video/x-matroska";
	autotype["mpe"] = "video/mpeg";
	autotype["onetoc"] = "application/onenote";
	autotype["lhx"] = "application/octet-stream";
	autotype["mods"] = "application/mods+xml";
	autotype["rast"] = "image/cmu-raster";
	autotype["fmf"] = "video/x-atomic3d-feature";
	autotype["rld"] = "application/resource-lists-diff+xml";
	autotype["mpg"] = "video/mpeg";
	autotype["sfd-hdstx"] = "application/vnd.hydrostatix.sof-data";
	autotype["cil"] = "application/vnd.ms-artgalry";
	autotype["scurl"] = "text/vnd.curl.scurl";
	autotype["uvz"] = "application/vnd.dece.zip";
	autotype["fh"] = "image/x-freehand";
	autotype["xenc"] = "application/xenc+xml";
	autotype["dir"] = "application/x-director";
	autotype["log"] = "text/plain";
	autotype["s3m"] = "audio/s3m";
	autotype["spr"] = "application/x-sprite";
	autotype["acutc"] = "application/vnd.acucorp";

	return autotype;
}