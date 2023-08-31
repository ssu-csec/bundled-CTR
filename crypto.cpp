#include <iostream>
#include <iterator>
#include <string>
#include <cstring>
#include <vector>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include "crypto.h"

using namespace std;
using namespace CryptoPP;

vector<byte> metadata_gen(int len)
{
	vector<byte> metadata;
	int remain = len;
	if(len%16 != 0)
		len++;
	metadata.push_back((byte)0x00);         // the first data of metadata is 0 for counter block

	while(remain > AES::BLOCKSIZE)
	{   
		metadata.push_back((byte)0x10);
		remain -= AES::BLOCKSIZE;
	}
	metadata.push_back((byte)remain);   
	
	return metadata;
}

vector<byte> metadata_enc(vector<byte> metadata, byte* counter, byte* key, byte* nonce)
{
	vector<byte> meta_cipher;
	byte meta[metadata.size() + AES::BLOCKSIZE/2];
			    
	byte iv[AES::BLOCKSIZE];
	memcpy(iv, nonce, AES::BLOCKSIZE/2);
	fill_n(iv + AES::BLOCKSIZE/2, AES::BLOCKSIZE/2, (byte)0x00);
						    
	memcpy(meta, counter, AES::BLOCKSIZE/2);
	memcpy(meta + AES::BLOCKSIZE/2, metadata.data(), metadata.size());
	for (int i = 0; i < sizeof(meta); i++)
	{   
		meta_cipher.push_back(0x00);
	}   
	CTR_Mode<AES>::Encryption e;
	e.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
	e.ProcessData(meta_cipher.data(), (const byte*)meta, sizeof(meta));
	return meta_cipher;
}

vector<byte> metadata_dec(vector<byte> meta_cipher, byte* key, byte* nonce)
{
	vector<byte> metadata;
	byte tmp_meta[meta_cipher.size()] = {(byte)0x00, };
	
	byte iv[AES::BLOCKSIZE];
	memcpy(iv, nonce, AES::BLOCKSIZE/2);
	fill_n(iv + AES::BLOCKSIZE/2, AES::BLOCKSIZE/2, (byte)0x00);

	CTR_Mode<AES>::Decryption d;
	d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
	d.ProcessData(tmp_meta, (const byte*)meta_cipher.data(), meta_cipher.size());

	metadata.insert(metadata.end(), tmp_meta + AES::BLOCKSIZE/2, &tmp_meta[-1]);

	return metadata;
}

vector<byte> encryption(byte* nonce, byte* counter, string plaintext, byte* key, byte* back_counter)    // encrypt data and generate bundle with it
{
	vector<byte> bundle;
	byte firstblock[AES::BLOCKSIZE];
	byte iv[AES::BLOCKSIZE];
				    
	ECB_Mode<AES>::Encryption ecb;
	CTR_Mode<AES>::Encryption ctr;
							    
	memcpy(firstblock + AES::BLOCKSIZE/2, back_counter, AES::BLOCKSIZE/2);
	memcpy(firstblock, counter, AES::BLOCKSIZE/2);
	memcpy(iv, nonce, AES::BLOCKSIZE/2);
	memcpy(iv + AES::BLOCKSIZE/2, counter, AES::BLOCKSIZE/2);
	byte first_cipher[AES::BLOCKSIZE];
	ecb.SetKey(key, AES::DEFAULT_KEYLENGTH);
	ecb.ProcessData(first_cipher, (const byte*)firstblock, AES::BLOCKSIZE);
	
	for (int i = 0; i < AES::BLOCKSIZE; i++)
		bundle.push_back(first_cipher[i]);
	for (int i = 0; i < plaintext.length(); i++)
		bundle.push_back(0x00);
	
	ctr.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
	ctr.ProcessData(bundle.data() + AES::BLOCKSIZE, (const byte*)plaintext.c_str(), plaintext.length());
																										    
	return bundle;
}

vector<byte> decryption(byte* nonce, vector<byte> bundle, byte* key, vector<byte> metadata)						// decrypt bundles
{
	vector<byte> plaintext;
	vector<byte> tmp_bundle;
	byte tmp_decrypt[bundle.size()] = {(byte)0x00, };
	int tmp_num = 0;										// the number of data in first data block of a bundle
	byte plain_meta[metadata.size()];						// decrypted metadata
	byte counter[AES::BLOCKSIZE] = {0x00, };							// first counter of each bundle (dynamic data)
	byte* index = bundle.data();							// address
	byte tmp_block[AES::BLOCKSIZE] = {(byte)0x00, };
	byte back_ctr[AES::BLOCKSIZE/2];
	
	ECB_Mode<AES>::Decryption ecb;
	CTR_Mode<AES>::Decryption ctr;
	memcpy(counter, nonce, AES::BLOCKSIZE/2);
	
	ctr.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, counter);
	ctr.ProcessData(plain_meta, (const byte*)metadata.data(), sizeof(metadata));
	
	ecb.SetKey(key, AES::DEFAULT_KEYLENGTH);
	
	for(int i = AES::BLOCKSIZE/2; i < sizeof(plain_meta); i++)
	{
		if(plain_meta[i] == (byte)0x00)
		{
			if(tmp_bundle.size() != 0)
			{
				// decrypt previous bundle
				memcpy(counter + AES::BLOCKSIZE/2, tmp_block + AES::BLOCKSIZE/2, AES::BLOCKSIZE/2);
				ctr.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, counter);
				ctr.ProcessData(tmp_decrypt, (const byte*)tmp_bundle.data(), tmp_bundle.size());
				for (int j = 0; j < tmp_bundle.size() - AES::BLOCKSIZE + tmp_num; j++)
					plaintext.push_back(tmp_decrypt[(AES::BLOCKSIZE - tmp_num) + j]);
				tmp_bundle.clear();
				memset(tmp_decrypt, (byte)0x00, sizeof(tmp_decrypt));

				// decrypt first block and generate counter of new bundle
				ecb.ProcessData(tmp_block, index, AES::BLOCKSIZE);
				if(1 != 0 && memcmp(back_ctr, tmp_block, AES::BLOCKSIZE/2) != 0)
					cout << "Error in block number" << i << endl;
				memcpy(back_ctr, tmp_block + AES::BLOCKSIZE/2, AES::BLOCKSIZE/2);
			}
				index += AES::BLOCKSIZE;
		}
		else
		{
			// insert block data to tmp_bundle
			if(plain_meta[i - 1] == (byte)0x00)			// first data block of a bundle
			{
				tmp_num = (int)plain_meta[i];
				for(int j = 0; j < AES::BLOCKSIZE - (int)plain_meta[i]; j++)
				{
					tmp_bundle.push_back(0x00);
				}
			}
			for(int j = 0; j < (int)plain_meta[i]; j++)
			{
				tmp_bundle.push_back(index[j]);
			}

			index += (int)plain_meta[i];
		}
	}
	if(tmp_bundle.size() != 0)
	{
		memcpy(counter + AES::BLOCKSIZE/2, tmp_block + AES::BLOCKSIZE/2, AES::BLOCKSIZE/2);
		ctr.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, counter);
		ctr.ProcessData(tmp_decrypt, (const byte*)tmp_bundle.data(), tmp_bundle.size());
		for (int j = 0; j < tmp_bundle.size() - AES::BLOCKSIZE + tmp_num; j++)
			plaintext.push_back(tmp_decrypt[(AES::BLOCKSIZE - tmp_num) + j]);
	}

	return plaintext;
}

vector<int> bundle_list_gen(vector<byte> metadata)
{
	int check = 0;
	vector<int> head_list;
	for (int i = 0; i < metadata.size(); i++)
	{
		if (metadata[i] == 0x00)
		{
			head_list.push_back(check);
			check += AES::BLOCKSIZE;
		}
		else
		{
			check += (int)metadata[i];
		}

	}
	return head_list;
}
int search_block_index(vector<byte> metadata, int index)
{
	int check = index;
	int block_index = 0;
	while(block_index < metadata.size())
	{
		check -= metadata[block_index];
		if(check < 0)
			return block_index;
		else if (check > 0)
			block_index++;
		else
			return block_index + 1;
	}
	return block_index;
}

int search_real_index(vector<byte> metadata, int index)
{
	int real = 0;
	for (int i = 0; i < index; i++)
	{
		if(metadata[i] == 0x00)
			real += AES::BLOCKSIZE;
		else
			real += (int)metadata[i];	
	}
	return real;
}

int search_counter_block(vector<byte> metadata, int index)
{
	for (int i = index; i > 0; i--)
	{
		if (metadata[i] == 0x00)
		{
			return i;
		}
	}

	return 0;
}

bundled_CTR::bundled_CTR(byte* key, byte* nonce)
{
	memcpy(this->key,key, AES::BLOCKSIZE);
	memcpy(this->nonce,nonce, AES::BLOCKSIZE/2);
}

Modi_info bundled_CTR::Insertion(string text, int index)
{}

Modi_info bundled_CTR::Deletion(int del_len, int index)
{
}

Modi_info bundled_CTR::Replacement(string text, int index)
{}


