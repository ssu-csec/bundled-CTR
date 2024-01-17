#include <iostream>
#include <iterator>                                                                    
#include <string>                                                   
#include <cstring>                                                              
#include <vector>                                                         
#include <cryptopp/aes.h>                                               
#include <cryptopp/modes.h>                                          
#include <cryptopp/filters.h>
#include "exist_mode.h"

using namespace std;
using namespace CryptoPP;

CTR::CTR(byte* key, byte* nonce)
{
	memcpy(this->key, key, AES::BLOCKSIZE);
	memcpy(this->nonce, nonce, AES::BLOCKSIZE/2);
}

CTR::~CTR()
{}

vector<byte> CTR::print_data()
{
	return this->data;
}

void CTR::Insertion(string text, int index)
{
	CTR_Mode<AES>::Encryption e;
	CTR_Mode<AES>::Decryption d;

	e.SetKeyWithIV(key, sizeof(key), nonce);
	d.SetKeyWithIV(key, sizeof(key), nonce);

	if(data.size() != 0)
	{
		byte decrypt[this->data.size()] = {0x00, };
		d.ProcessData(decrypt, (const byte*)this->data.data(), this->data.size());
		string plain(reinterpret_cast<const char*>(decrypt), sizeof(decrypt));

		plain.insert(index, text);
		// test
		/*
		int left_len
		byte encrypt[AES::BLOCKSIZE];
		this->data.clear();
		while()*/
		// test end
		byte encrypt[plain.length()];
		e.ProcessData(encrypt, (const byte*)plain.c_str(), plain.length());
		this->data.clear();
		this->data.insert(this->data.begin(), encrypt, encrypt + sizeof(encrypt));
	}
	else
	{
		byte encrypt[text.length()];
		e.ProcessData(encrypt, (const byte*)text.c_str(), text.length());
		this->data.insert(this->data.begin(), encrypt, encrypt + sizeof(encrypt));
	}


	return;
}

void CTR::Deletion(int del_len, int index)
{
	CTR_Mode<AES>::Encryption e;
	CTR_Mode<AES>::Decryption d;

	e.SetKeyWithIV(key, sizeof(key), nonce);
	d.SetKeyWithIV(key, sizeof(key), nonce);

	byte decrypt[this->data.size()] = {0x00, };
	d.ProcessData(decrypt, (const byte*)this->data.data(), this->data.size());
	string plain(reinterpret_cast<const char*>(decrypt), sizeof(decrypt));

	plain.erase(index, del_len);
	byte encrypt[plain.length()];
	e.ProcessData(encrypt, (const byte*)plain.c_str(), plain.length());
	this->data.clear();
	this->data.insert(this->data.begin(), encrypt, encrypt + sizeof(encrypt));

	return;
}

void CTR::Replacement(string text, int index)
{
	CTR_Mode<AES>::Encryption e;
	CTR_Mode<AES>::Decryption d;

	e.SetKeyWithIV(key, sizeof(key), nonce);
	d.SetKeyWithIV(key, sizeof(key), nonce);

	byte decrypt[this->data.size()] = {0x00, };
	d.ProcessData(decrypt, (const byte*)this->data.data(), this->data.size());
	string plain(reinterpret_cast<const char*>(decrypt), sizeof(decrypt));

	plain.replace(index, text.length(), text);
	byte encrypt[plain.length()];
	e.ProcessData(encrypt, (const byte*)plain.c_str(), plain.length());
	this->data.clear();
	this->data.insert(this->data.begin(), encrypt, encrypt + sizeof(encrypt));

	return;
}

CBC::CBC(byte* key, byte* iv)
{
	memcpy(this->key, key, AES::BLOCKSIZE);
	memcpy(this->iv, iv, AES::BLOCKSIZE);
}

CBC::~CBC()
{}

vector<byte> CBC::print_data()
{
	return this->data;
}

void CBC::Insertion(string text, int index)
{
	CBC_Mode<AES>::Encryption e;
	CBC_Mode<AES>::Decryption d;

	e.SetKeyWithIV(key, sizeof(key), iv);
	d.SetKeyWithIV(key, sizeof(key), iv);
	if(data.size() != 0)
	{
		byte decrypt[this->data.size()] = {0x00, };
		d.ProcessData(decrypt, (const byte*)this->data.data(), this->data.size());
		string plain(reinterpret_cast<const char*>(decrypt), sizeof(decrypt));

		plain.insert(index, text);
		byte encrypt[plain.length()];
		e.ProcessData(encrypt, (const byte*)plain.c_str(), plain.length());
		this->data.clear();
		this->data.insert(this->data.begin(), encrypt, encrypt + sizeof(encrypt));
	}
	else
	{
		byte encrypt[text.length()];
		e.ProcessData(encrypt, (const byte*)text.c_str(), text.length());
		this->data.insert(this->data.begin(), encrypt, encrypt + sizeof(encrypt));
	}

	return;
}

void CBC::Deletion(int del_len, int index)
{
	CBC_Mode<AES>::Encryption e;
	CBC_Mode<AES>::Decryption d;

	e.SetKeyWithIV(key, sizeof(key), iv);
	d.SetKeyWithIV(key, sizeof(key), iv);

	byte decrypt[this->data.size()] = {0x00, };
	d.ProcessData(decrypt, (const byte*)this->data.data(), this->data.size());
	string plain(reinterpret_cast<const char*>(decrypt), sizeof(decrypt));

	plain.erase(index, del_len);
	byte encrypt[plain.length()];
	e.ProcessData(encrypt, (const byte*)plain.c_str(), plain.length());
	this->data.clear();
	this->data.insert(this->data.begin(), encrypt, encrypt + sizeof(encrypt));

	return;
}

void CBC::Replacement(string text, int index)
{
	CBC_Mode<AES>::Encryption e;
	CBC_Mode<AES>::Decryption d;

	e.SetKeyWithIV(key, sizeof(key), iv);
	d.SetKeyWithIV(key, sizeof(key), iv);

	byte decrypt[this->data.size()] = {0x00, };
	d.ProcessData(decrypt, (const byte*)this->data.data(), this->data.size());
	string plain(reinterpret_cast<const char*>(decrypt), sizeof(decrypt));

	plain.replace(index, text.length(), text);
	byte encrypt[plain.length()];
	e.ProcessData(encrypt, (const byte*)plain.c_str(), plain.length());
	this->data.clear();
	this->data.insert(this->data.begin(), encrypt, encrypt + sizeof(encrypt));

	return;
}
