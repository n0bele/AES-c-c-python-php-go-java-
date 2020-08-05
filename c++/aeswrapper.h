
#include "aes.h"
#include <stdio.h>
#include <string>
#include <time.h>
#include <Windows.h>
using namespace std;

typedef struct {  
	ULONG i[2];                          /* number of _bits_ handled mod 2^64 */  
	ULONG buf[4];                                           /* scratch buffer */  
	unsigned char in[64];                                     /* input buffer */  
	unsigned char digest[16];            /* actual digest after MD5Final call */  
} MD5_CTX;
#define MD5DIGESTLEN 16  
#define PROTO_LIST(list)    list  
typedef void (WINAPI* PMD5Init) PROTO_LIST ((MD5_CTX *));
typedef void (WINAPI* PMD5Update) PROTO_LIST ((MD5_CTX *, const unsigned char *, unsigned int));
typedef void (WINAPI* PMD5Final )PROTO_LIST ((MD5_CTX *));

class  CNewAes {
public:
    enum Padding {
        ZEROS,
        PKCS7,
    };
	static char * Md5(const char * str);
	static string EnPostStr(string &sStr);
	static string DePostStr(string &sEnStr);
	static std::string HexToBin(LPCSTR pszHex);
	static std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len);
	static std::string base64_decode(std::string const& encoded_string);
	static std::string pad(const std::string &input, int blocksize, Padding padding);
    static std::string unpad(const std::string &input, int blocksize, Padding padding);
    static std::string pad_key(const std::string &key);
    static std::string cbc_encrypt(const std::string &input, const std::string key, Padding padding = PKCS7);
    static std::string  cbc_decrypt(const std::string &input, const std::string key, Padding padding = PKCS7);
};

