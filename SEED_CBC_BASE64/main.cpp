#define _CRT_SECURE_NO_WARNINGS

#define BUF_SIZE 10240
#define SOCKET_TEST_SIM 0

#if SOCKET_TEST_SIM
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Winsock2.h>

#define SERVER_IP "172.16.10.141"
#define PORT_NUM 5005
#endif

#include "b64.h"
#include "seedcbc.h"

#include <string>
#include <iostream>


int print_decryptdata(int after_decrypt_len, unsigned char after_decrypt_plaintext[], unsigned char *dst, int size);
void error_handling(char *msg);

void convert_string2wstring(const std::string& src, std::wstring& dest);
void convert_wstring2string(const std::wstring& src, std::string& dest);
std::string ReplaceAll(std::string& str, const std::string& from, const std::string& to);

int main(){
	unsigned char key[16];
	unsigned char iv[16];
	//std::string str_seed_key = "chlguswls!@#giga";
	std::string str_seed_key = "1234567891234567";
	
	std::cout << str_seed_key.length() << std::endl;
	if (16 != str_seed_key.length())
	{
		std::cout << "Seed 키의 길이(16byte)가 충족되지 않았습니다." << std::endl;
		return -1;
	}

	for (int i = 0; i < 16; i++)
	{
		key[i] = *(const_cast<char*>(str_seed_key.c_str() + i));
		iv[i] = *(const_cast<char*>(str_seed_key.c_str() + i));
	}

	/* 대칭키와 IV */
	//unsigned char key[16] = { 0xED, 0x24, 0x01, 0xAD, 0x22, 0xFA, 0x25, 0x59, 0x91, 0xBA, 0xFD, 0xB0, 0x1F, 0xEF, 0xD6, 0x97 };
	//unsigned char iv[16] = { 0x93, 0xEB, 0x14, 0x9F, 0x92, 0xC9, 0x90, 0x5B, 0xAE, 0x5C, 0xD3, 0x4D, 0xA0, 0x6C, 0x3C, 0x8E };
	// chlguswls!@#giga

	//unsigned char key[16] = { 0x63, 0x68, 0x6c, 0x67, 0x75, 0x73, 0x77, 0x6C, 0x73, 0x21, 0x40, 0x23, 0x67, 0x69, 0x67, 0x61 };
	//unsigned char iv[16] = { 0x63, 0x68, 0x6c, 0x67, 0x75, 0x73, 0x77, 0x6C, 0x73, 0x21, 0x40, 0x23, 0x67, 0x69, 0x67, 0x61 };

	//unsigned char key[16] = { 'A','2','3','1','9','3','A','8','0','F','1','5','M','S','0','7' };
	//unsigned char iv[16] = { 'D','C','8','8','E','0','F','5','1','B','6','0','0','0','1','6' };

	//for (int i = 0; i < 16; i++)
	//{
	//	key[i] = *(const_cast<char*>(str_seed_key.c_str() + i));
	//	iv[i] = *(const_cast<char*>(str_seed_key.c_str() + i));
	//}

	
	/* 입출력 버퍼 */
	unsigned char plaintext[BUF_SIZE] = "\0";
	unsigned char ciphertext[BUF_SIZE+16] = "\0";

	unsigned char after_decrypt_plaintext[BUF_SIZE] = "\0"; /* 복호화에 사용될 평문출력버퍼 */
	unsigned char recv_text[BUF_SIZE] = "\0";

	unsigned char *str = NULL; /* str : base64 인코딩 후의 데이터 */
	unsigned char *dst = NULL; /* dst : base64 디코딩 후의 데이터 */
	
	int  size = 0;
	int recv_text_length = 0;
	int plaintext_len = 0; /* 입력받은 plaintext의 길이 */
	int after_decrypt_len = 0; /* 복호화 후 데이터 길이 */
	int after_encrypt_len = 0; /* 암호화 후 데이터 길이 */
	
	std::locale::global(std::locale(""));
	std::wcout.imbue(std::locale());

	/*const unsigned char* test_str = (const unsigned char*)"한글123abc";
	int test_size = 0;
	unsigned char* test_out_str;
	test_out_str = __base64_encode(test_str, strlen((char*)test_str), &test_size);

	std::cout << test_out_str << std::endl;

	unsigned char* test_out_decode_str;
	int test_out_size = strlen((char*)test_out_str);

	test_out_decode_str = __base64_decode(test_out_str, strlen((char*)test_out_str), &test_out_size);
	std::cout << test_out_decode_str << std::endl;*/

	std::cout << "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<" << std::endl;
	std::cout << "암호화 테스트" << std::endl;

	char* plainStr = NULL;
	int plainStr_Size = 0;

	unsigned char seed_encoded_Str[BUF_SIZE + 16] = "\0";
	int encoded_Cyper_Size = 0;

	unsigned char* base64_encoded_Str = NULL;
	int base64_encoded_Size = 0;

	//plainStr = (char*)"{\r\n  \"set-tx-configuration\": {\r\n    \"tx-mac\": \"00:67:a8:2d:84:7e\",\r\n    \"tx-ip\": \"232.123.132.154\",\r\n    \"rx-said\": \"PC000001\",\r\n    \"rx-client-id\": \"00:52:a8:2d:84:4e\",\r\n    \"rx-cust-id\":\"\",\r\n    \"auth-method\":\"auth-pw\",\r\n    \"port-1\": \"10001\",\r\n    \"port-2\": \"10002\",\r\n    \"port-3\": \"10003\",\r\n    \"port-4\": \"10004\",\r\n    \"port-5\": \"10005\",\r\n    \"zone-id\":\"ZONE0001\",\r\n    \"option\":\" \"\r\n  }\r\n}\r\n";
	plainStr = (char*)"sjpsjp";
	plainStr_Size = strlen((char*)plainStr);

	// SEED Encode
	encoded_Cyper_Size = KISA_SEED_CBC_ENCRYPT(key, iv, (unsigned char*)plainStr, plainStr_Size, seed_encoded_Str);

	// Base64 Encode
	//! You must "free()" output str after process done
	base64_encoded_Str = __base64_encode((unsigned char*)seed_encoded_Str, encoded_Cyper_Size, &base64_encoded_Size);


	std::cout << "[Encode] PlainStr : " << plainStr << std::endl;
	std::cout << "[Encode] base64_encoded_Str : " << base64_encoded_Str << std::endl;
	std::cout << "[Encode] PlainStr size : " << base64_encoded_Size << std::endl;
	std::cout << "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<" << std::endl;

	std::cout << ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>" << std::endl;
	std::cout << "복호화 테스트" << std::endl;

	unsigned char* base64_CyperStr = NULL;
	int base64_CyperStr_Size = 0;
	
	unsigned char* seed_CyperStr = NULL;

	unsigned char decoded_PlainStr[BUF_SIZE] = "\0";
	int decoded_PlainStr_Size = 0;


	// Init base64 cyper String
	base64_CyperStr = (unsigned char*)"BoX1QjSlsmD1UcCP/8vzBg==";
	base64_CyperStr_Size = strlen((char*)base64_CyperStr); // Not include \0
	//base64_CyperStr = base64_encoded_Str;
	//base64_CyperStr_Size = strlen((char*)base64_CyperStr); // Not include \0

	// Base64 Decode
	//! You must "free()" output str after process done
	seed_CyperStr = __base64_decode(base64_CyperStr, strlen((char*)base64_CyperStr), &base64_CyperStr_Size);

	std::cout << "base64 decode after size : " << base64_CyperStr_Size << std::endl;

	// SEED Decode
	decoded_PlainStr_Size = KISA_SEED_CBC_DECRYPT(key, iv, seed_CyperStr, base64_CyperStr_Size, decoded_PlainStr);

	std::cout << "[Decode] base64_CyperStr : " << base64_CyperStr << std::endl;
	std::cout << "[Decode] PlainStr : " << decoded_PlainStr << std::endl;
	std::cout << "[Decode] PlainStr size : " << decoded_PlainStr_Size << std::endl;
	std::cout << ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>" << std::endl;

	free(base64_encoded_Str);
	free(seed_CyperStr);



	

	return 0;
}

int print_decryptdata(int after_decrypt_len, unsigned char after_decrypt_plaintext[], unsigned char *dst, int size){
	int i = 0;

	//printf("\n디코딩 후 데이터: %s\n\n디코딩 후 데이터 길이: %d\n", dst, size);

	printf("\n데이터 복호화 결과: ");
	for (i = 0; i < after_decrypt_len; i++)
		printf("%c", after_decrypt_plaintext[i]);
	//printf("\n복호화 후 데이터 길이: %d\n", plainlen);
	printf("\n");

	return 0;
}

void error_handling(char *msg){
	fputs(msg, stderr);
	fputc('\n', stderr);
	exit(1);
}


std::string ReplaceAll(std::string& str, const std::string& from, const std::string& to) {
	size_t start_pos = 0; //string처음부터 검사
	while ((start_pos = str.find(from, start_pos)) != std::string::npos)  //from을 찾을 수 없을 때까지
	{
		str.replace(start_pos, from.length(), to);
		start_pos += to.length(); // 중복검사를 피하고 from.length() > to.length()인 경우를 위해서
	}
	return str;
}