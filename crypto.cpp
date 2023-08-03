#include <iostream>
#include <iterator>
#include <string>
#include <cstring>
#include <vector>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>

using namespace std;
using namespace CryptoPP;


byte* metadata_gen(int len)
{
	byte* metadata;
	int meta_len = len/AES::BLOCKSIZE;
	int remain = len;
	if(len%16 != 0)
		meta_len++;
	metadata = new byte[meta_len + 1];
	metadata[0] = (byte)0x00;			// the first data of metadata is 0 for counter block

	int i = 1;
	while(remain > AES::BLOCKSIZE)
	{
		metadata[i] = (byte)0x10;
		remain -= AES::BLOCKSIZE;
		i++;
	}
	metadata[i] = (byte)remain;	

	return metadata;
}
byte* metadata_enc(byte* metadata, byte* counter, byte* key, byte* nonce)
{
	byte* meta_cipher;
	byte meta[sizeof(metadata) + AES::BLOCKSIZE/2];
	CTR_Mode<AES>::Encryption e;
	memcpy(meta, counter, AES::BLOCKSIZE/2);
	memcpy(meta + AES::BLOCKSIZE/2, metadata, sizeof(metadata));
	meta_cipher = new byte[sizeof(meta)];
	e.SetKeyWithIV(key, sizeof(key), nonce);
	e.ProcessData(meta_cipher, (const byte*)meta, sizeof(meta));
	return meta_cipher;
}

vector<byte> encryption(byte* nonce, byte* counter, string plaintext, byte* key)	// encrypt data and generate bundle with it
{
	vector<byte> bundle;
	byte firstblock[AES::BLOCKSIZE];
	byte iv[AES::BLOCKSIZE];
	
	ECB_Mode<AES>::Encryption ecb;
	CTR_Mode<AES>::Encryption ctr;
	
	fill_n(firstblock + AES::BLOCKSIZE/2, AES::BLOCKSIZE/2, (byte)0x00);
	memcpy(firstblock, counter, AES::BLOCKSIZE/2);
	memcpy(iv, nonce, AES::BLOCKSIZE/2);
	memcpy(iv + AES::BLOCKSIZE/2, counter, AES::BLOCKSIZE/2);
	
	byte first_cipher[AES::BLOCKSIZE];
	ecb.SetKey(key, AES::DEFAULT_KEYLENGTH);
	ecb.ProcessData(first_cipher, (const byte*)firstblock, AES::BLOCKSIZE);
	for(int i = 0; i < AES::BLOCKSIZE; i++)
		bundle.push_back(firstblock[i]);
	ctr.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
	ctr.ProcessData(bundle.data() + AES::BLOCKSIZE, (const byte*)plaintext.c_str(), plaintext.length());
	
	return bundle;
}

vector<byte> decryption(byte* nonce, byte* bundle, byte* key, byte* metadata)						// decrypt bundles
{
	vector<byte> plaintext;
	vector<byte> tmp_bundle;
	byte tmp_decrypt[sizeof(bundle)] = {(byte)0x00, };
	int tmp_num = 0;										// the number of data in first data block of a bundle
	byte plain_meta[sizeof(metadata)];						// decrypted metadata
	byte counter[AES::BLOCKSIZE];							// first counter of each bundle (dynamic data)
	byte* index = bundle;									// address
	byte tmp_block[AES::BLOCKSIZE] = {(byte)0x00, };
	byte back_ctr[AES::BLOCKSIZE/2];
	
	ECB_Mode<AES>::Decryption ecb;
	CTR_Mode<AES>::Decryption ctr;
	memcpy(counter, nonce, AES::BLOCKSIZE/2);
	
	fill_n(counter + AES::BLOCKSIZE/2, AES::BLOCKSIZE/2, (byte)0x00);
	ctr.SetKeyWithIV(key, sizeof(key), counter);
	ctr.ProcessData(plain_meta, (const byte*)metadata, sizeof(metadata));
	
	ecb.SetKey(key, sizeof(key));

	for(int i = 0; i < sizeof(metadata); i++)
	{
		if(plain_meta[i] == (byte)0x00)
		{
			// decrypt previous bundle
			memcpy(counter + AES::BLOCKSIZE/2, tmp_block + AES::BLOCKSIZE/2, AES::BLOCKSIZE/2);
			ctr.SetKeyWithIV(key, sizeof(key), counter);
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
		ctr.SetKeyWithIV(key, sizeof(key), counter);
		ctr.ProcessData(tmp_decrypt, (const byte*)tmp_bundle.data(), tmp_bundle.size());
		for (int j = 0; j < tmp_bundle.size() - AES::BLOCKSIZE + tmp_num; j++)
			plaintext.push_back(tmp_decrypt[(AES::BLOCKSIZE - tmp_num) + j]);
	}

	return plaintext;
}

int search_block_index(byte* metadata, int index)
{
	int check = index;
	int block_index = 0;
	while(block_index < sizeof(metadata))
	{
		check -= (int)metadata[block_index];
		if (check < 0)
			return block_index;
		else if (check > 0)
			block_index++;
		else
			return block_index + 1;
	}
}

/*class bundledCTR
{

private:
	
	byte* main_data;
	byte* meta_data;
	byte key[AES::BLOCKSIZE];
	byte nonce[AES::BLOCKSIZE/2];

public:

	bundledCTR(byte* key, byte* nonce)
	{
		this->key = key;
		this->nonce = nonce;
	}

	~bundledCTR() {}

	void Insertion(string text, int index)
	{}

	void Deletion(int del_len, int index)
	{}

	void Replacement(string text, int index)
	{}

	void Defrag()
	{}


}*/

