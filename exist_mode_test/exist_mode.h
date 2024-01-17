#ifndef EXIST_MODE_H
#define EXIST_MODE_H

#include <vector>
#include <string>
#include <cryptopp/aes.h>

using namespace std;
using namespace CryptoPP;

class CTR
{
	private:
		byte key[AES::BLOCKSIZE];
		byte nonce[AES::BLOCKSIZE/2];
		vector<byte> data;
	
	public:
		CTR(byte* key, byte* nonce);

		~CTR();

		vector<byte> print_data();

		void Insertion(string text, int index);

		void Deletion(int del_len, int index);

		void Replacement(string text, int index);
};

class CBC
{
	private:
		byte key[AES::BLOCKSIZE];
		byte iv[AES::BLOCKSIZE];
		vector<byte> data;
	
	public:
		CBC(byte* key, byte* iv);

		~CBC();

		vector<byte> print_data();

		void Insertion(string text, int index);

		void Deletion(int del_len, int index);

		void Replacement(string text, int index);

};

#endif
