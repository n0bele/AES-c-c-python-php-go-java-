//#include "stdafx.h"
#include "aeswrapper.h"

#define EnDeKey "1Q2a3k79"

std::string CNewAes::pad(const std::string &input, int blocksize, Padding padding) {
	std::string out;
	if (padding == PKCS7) {
		int padsize = blocksize - input.size() % blocksize;
		out.reserve(input.size() + padsize);
		out = input;
		out.append(padsize, (char)padsize);
		return out.c_str();
	} else if (padding == ZEROS) {
		int padsize = (blocksize - input.size() % blocksize) % blocksize;
		out.reserve(input.size() + padsize);
		out = input;
		if (padsize) {
			out.append(padsize, '\0');
		}
		return out.c_str();
	} else {
		// bad padding type
		return "";
	}
}

std::string CNewAes:: unpad(const std::string &input, int blocksize, Padding padding) {
	if (input.empty() || (int)input.size() < blocksize || (input.size() % blocksize != 0)) {
		return "";
	}
	if (padding == PKCS7) {
		int padsize = (int)input[input.size() -1];
		if (padsize > 0 && padsize <= blocksize && (int)input.size() >= padsize) {
			std::string strsub = input.substr(0, input.size() - padsize);
			return strsub.c_str();
		} else {
			// bad input length 
			return "";
		}
	} else if (padding == ZEROS) {
		int padsize = 0;
		for (int i = input.size() - 1 ; i >= 0 && input[i] == '\0'; --i) {
			padsize ++;
			if (padsize >= (blocksize - 1)) {
				break;
			}
		}
		std::string strsub = input.substr(0, input.size() - padsize);
		return strsub.c_str();
	} else {
		// invalid padding type
		return "";
	}
}

std::string CNewAes::pad_key(const std::string &key) {
	if (key.size() <= 16) { // 128-bits
		return pad(key, 16, ZEROS);
	} else if (key.size() <= 24) { // 192-bits
		return pad(key, 24, ZEROS);
	} else if (key.size() <= 32) { // 256-bits
		return pad(key, 32, ZEROS);
	} else {
		std::string strSub = key.substr(0, 32); // take the first 256-bits
		return strSub.c_str();
	}
}

std::string CNewAes::cbc_encrypt(const std::string &input, const std::string key, Padding padding) {
	std::string padkey = pad_key(key); // set the proper key length
	AES_KEY aeskey;
	int nxx = padkey.size() * 8;
	int rc = AES_set_encrypt_key((const unsigned char *)padkey.data(), padkey.size() * 8, &aeskey);
	if (rc != 0) {
		// api call failed
		return "";
	}
	unsigned char ivec[AES_BLOCK_SIZE] = { '0','1','0','1' ,'0','1' ,'0','1' ,'2','3','4','5','a','b','c','d' };
	std::string padinput = pad(input, AES_BLOCK_SIZE, padding);
	std::string out(padinput.size(), 0);
	for (size_t i = 0; i < padinput.size(); i += AES_BLOCK_SIZE) {
		AES_cbc_encrypt((const unsigned char *)padinput.data() + i, (unsigned char *)out.data() + i, AES_BLOCK_SIZE, &aeskey, ivec, AES_ENCRYPT);
	}
	return out;
}

std::string CNewAes::cbc_decrypt(const std::string &input, const std::string key, Padding padding) {
	int nxxx = input.size();
	if (input.size() < AES_BLOCK_SIZE || (input.size() % AES_BLOCK_SIZE != 0)) {
		// invalid encrypt text length
		return "";
	}
	unsigned char ivec[AES_BLOCK_SIZE] = { '0','1','0','1' ,'0','1' ,'0','1' ,'2','3','4','5','a','b','c','d' };
	std::string padkey = pad_key(key); // set the proper key length
	AES_KEY aeskey;
	int rc = AES_set_decrypt_key((const unsigned char *)padkey.data(),padkey.size() * 8, &aeskey);
	if (rc != 0) {
		// api call failed
		return "";
	}
	std::string out(input.size(), 0);
	for (size_t i = 0; i < input.size(); i += AES_BLOCK_SIZE) {
		AES_cbc_encrypt((const unsigned char *)input.data() + i, (unsigned char *)out.data() + i, AES_BLOCK_SIZE, &aeskey, ivec, AES_DECRYPT);
	}
	return unpad(out, AES_BLOCK_SIZE, padding);
}

inline int hexchar_to_bin(char ch) {
	ch = tolower(ch);
	if (ch >= '0' && ch <= '9') {
		return ch - '0';
	} else if (ch >= 'a' && ch <= 'f') {
		return ch - 'a' + 10;
	} else {
		return -1;
	}
}

std::string CNewAes::HexToBin(LPCSTR pszHex)
{
	if( pszHex == NULL || strlen(pszHex) % 2 != 0)
		return "";

	std::string strHex = pszHex;

	std::string strOutBuffer;
	strOutBuffer.reserve(strHex.size() / 2);

	for (size_t i = 0; i + 1 < strHex.size(); i += 2) 
	{
		int hi = hexchar_to_bin(strHex[i]);
		int lo = hexchar_to_bin(strHex[i+1]);
		if (hi >= 0 && lo >= 0) 
		{
			strOutBuffer.push_back((char)((hi << 4) + lo));
		} 
		else 
		{
			return "";
		}
	}

	return strOutBuffer.c_str();
}

static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

static inline bool is_base64(unsigned char c) {
	return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string CNewAes::base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
	std::string ret;
	int i = 0;
	int j = 0;
	unsigned char char_array_3[3];
	unsigned char char_array_4[4];

	while (in_len--) {
		char_array_3[i++] = *(bytes_to_encode++);
		if (i == 3) {
			char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
			char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
			char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
			char_array_4[3] = char_array_3[2] & 0x3f;

			for(i = 0; (i <4) ; i++)
				ret += base64_chars[char_array_4[i]];
			i = 0;
		}
	}

	if (i)
	{
		for(j = i; j < 3; j++)
			char_array_3[j] = '0';

		char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
		char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
		char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
		char_array_4[3] = char_array_3[2] & 0x3f;

		for (j = 0; (j < i + 1); j++)
			ret += base64_chars[char_array_4[j]];

		while((i++ < 3))
			ret += '=';

	}

	return ret;
}

std::string CNewAes::base64_decode(std::string const& encoded_string) {
	int in_len = encoded_string.size();
	int i = 0;
	int j = 0;
	int in_ = 0;
	unsigned char char_array_4[4], char_array_3[3];
	std::string ret;

	while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
		char_array_4[i++] = encoded_string[in_]; in_++;
		if (i ==4) {
			for (i = 0; i <4; i++)
				char_array_4[i] = base64_chars.find(char_array_4[i]);

			char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
			char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
			char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

			for (i = 0; (i < 3); i++)
				ret += char_array_3[i];
			i = 0;
		}
	}

	if (i) {
		for (j = i; j <4; j++)
			char_array_4[j] = 0;

		for (j = 0; j <4; j++)
			char_array_4[j] = base64_chars.find(char_array_4[j]);

		char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
		char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
		char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

		for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
	}

	return ret;
}

char * Hex2ASC(const BYTE *Hex, int Len)  
{  
	static char  ASC[4096 * 2];  
	int    i;  
	for (i = 0; i < Len; i++)  
	{  
		//这里是小写的md5
		ASC[i * 2] = "0123456789abcdef"[Hex[i] >> 4];  
		ASC[i * 2 + 1] = "0123456789abcdef"[Hex[i] & 0x0F];  
	}  
	ASC[i * 2] = 0;  
	return ASC;  
}  

char * CNewAes::Md5(const char * str)  
{  
	MD5_CTX ctx;  
	const unsigned char * buf = reinterpret_cast<const unsigned char *>(str);  
	int len = strlen(str);  
	HINSTANCE hDLL;  
	if ( (hDLL = LoadLibraryA("advapi32.dll")) > 0 )  
	{  

		PMD5Init MD5Init = (PMD5Init)GetProcAddress(hDLL,"MD5Init");  
		PMD5Update MD5Update = (PMD5Update)GetProcAddress(hDLL,"MD5Update");  
		PMD5Final MD5Final = (PMD5Final)GetProcAddress(hDLL,"MD5Final");  

		MD5Init(&ctx);  
		MD5Update(&ctx, buf, len);  
		MD5Final(&ctx);  
	}  
	return Hex2ASC(ctx.digest,16);  
} 

ULONGLONG GetTimeStamp(void)
{
	FILETIME ft = { 0 };
	SYSTEMTIME st = { 0 };
	ULARGE_INTEGER ull = { 0 };
	::GetSystemTime(&st);
	::SystemTimeToFileTime(&st, &ft);
	ull.LowPart = ft.dwLowDateTime;
	ull.HighPart = ft.dwHighDateTime;
	return (ull.QuadPart - 116444736000000000ULL) / 10000000ULL;
}

string CNewAes::EnPostStr(string &sStr)
{
	//Base64处理
	string sRet = "";
	do 
	{
		string sEncrypt = cbc_encrypt(sStr, "wodeshijiehenmei");
		if (sEncrypt.empty())
			break;
		sRet = base64_encode((unsigned char *)sEncrypt.c_str(), sEncrypt.length());
		/*
		string sRand;
		char szRand[64] = {0};
		srand((unsigned)time(NULL));
		sprintf(szRand,"%d", 10000000+rand());
		sRand = szRand;
		string sKeyStr = sRand.substr(0,8)+EnDeKey;
		//字符串md5
		string sHexMd5 = Md5(sKeyStr.c_str());
		if (sHexMd5.empty())
			break;
		string sEnKey = HexToBin(sHexMd5.c_str()).data();
		if (sEnKey.empty())
			break;
		//AES加密字符串
		string sEncrypt = cbc_encrypt(sStr, sEnKey);
		if (sEncrypt.empty())
			break;
		//Base64处理
		string sEnBase64 = base64_encode((unsigned char *)sEncrypt.c_str(),sEncrypt.length());
		//前8字节+Base64处理过AES加密过的字符串
		sRet = sKeyStr.substr(0,8)+sEnBase64;
		*/
	} while (0);

	return sRet;
}

string CNewAes::DePostStr(string &sEnStr)
{
	string sRet = "";
	do 
	{
		string sAesSrc = base64_decode(sEnStr);// BASE64解码
		if (sAesSrc.empty())
			break;
		sRet = cbc_decrypt(sAesSrc, "wodeshijiehenmei");
		/*
		int nDeLen = sEnStr.length();
		int nDecryptStrLen = (nDeLen-8)*2;
		string sDeKeyStr = sEnStr.substr(0,8)+EnDeKey;
		string sRealEnStr = sEnStr.substr(8,sEnStr.length());
		string sHexMd5 = Md5(sDeKeyStr.c_str());
		if (sHexMd5.empty())
			break;
		string sDeKey = HexToBin(sHexMd5.c_str()).data();
		if (sDeKey.empty())
			break;
		string sAesSrc = base64_decode(sRealEnStr);// BASE64解码
		sRet = cbc_decrypt(sAesSrc, sDeKey);
		*/

	} while (0);
	return sRet;
}