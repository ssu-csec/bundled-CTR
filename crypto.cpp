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

vector<byte> metadata_gen(int len)
{
	vector<byte> metadata;
	int remain = len;
	if(len%16 != 0)
		meta_len++;
	metadata.push_back((byte)0x00);			// the first data of metadata is 0 for counter block

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
	byte meta[sizeof(metadata) + AES::BLOCKSIZE/2];
	
	byte iv[AES::BLOCKSIZE];
	memcpy(iv, nonce, AES::BLOCKSIZE/2);
	fill_n(iv + AES::BLOCKSIZE/2, AES::BLOCKSIZE/2, (byte)0x00);
	
	memcpy(meta, counter, AES::BLOCKSIZE/2);
	memcpy(meta + AES::BLOCKSIZE/2, metadata.data(), metadata.size());
	meta_cipher = new byte[sizeof(meta)];
	
	CTR_Mode<AES>::Encryption e;
	e.SetKeyWithIV(key, sizeof(key), iv);
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
	d.SetKeyWithIV(key, sizeof(key), iv);
	d.ProcessData(tmp_meta, (const byte*)meta_cipher.data(), meta_cipher.size());

	metadata.insert(metadata.begin(), begin(tmp_meta) + AES::BLOCKSIZE/2, end(tmp_meta));

	return metadata;
}

vector<byte> encryption(byte* nonce, byte* counter, string plaintext, byte* key, byte* back_counter)	// encrypt data and generate bundle with it
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
	for(int i = 0; i < AES::BLOCKSIZE; i++)
		bundle.push_back(firstblock[i]);
	ctr.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
	ctr.ProcessData(bundle.data() + AES::BLOCKSIZE, (const byte*)plaintext.c_str(), plaintext.length());
	
	return bundle;
}

vector<byte> decryption(byte* nonce, vector<byte> bundle, byte* key, vector<byte> metadata)						// decrypt bundles
{
	vector<byte> plaintext;
	vector<byte> tmp_bundle;
	byte tmp_decrypt[sizeof(bundle)] = {(byte)0x00, };
	int tmp_num = 0;										// the number of data in first data block of a bundle
	byte plain_meta[sizeof(metadata)];						// decrypted metadata
	byte counter[AES::BLOCKSIZE];							// first counter of each bundle (dynamic data)
	byte* index = bundle.data();							// address
	byte tmp_block[AES::BLOCKSIZE] = {(byte)0x00, };
	byte back_ctr[AES::BLOCKSIZE/2];
	
	ECB_Mode<AES>::Decryption ecb;
	CTR_Mode<AES>::Decryption ctr;
	memcpy(counter, nonce, AES::BLOCKSIZE/2);
	
	fill_n(counter + AES::BLOCKSIZE/2, AES::BLOCKSIZE/2, (byte)0x00);
	ctr.SetKeyWithIV(key, sizeof(key), counter);
	ctr.ProcessData(plain_meta, (const byte*)metadata.data(), sizeof(metadata));
	
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

class Modi_info
{
private:
	int del_index;
	int del_len;
	int ins_index;
	vector<byte> new_meta;
	vector<byte> ins_list;

public:
	
	Modi_info()
	{}

	~Modi_info()
	{}

}

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


class bundled_CTR
{

private:
	
	vector<byte> main_data;
	vector<byte> meta_data;
	byte key[AES::BLOCKSIZE];
	byte nonce[AES::BLOCKSIZE/2];

public:

	bundled_CTR(byte* key, byte* nonce)
	{
		memcpy(this->key,key, AES::BLOCKSIZE);
		memcpy(this->nonce,nonce, AES::BLOCKSIZE/2);
	}

	~bundled_CTR() {}

	void Insertion(string text, int index)
	{}

	Modi_info Deletion(int del_len, int index)
	{
		Modi_info modi_info();
		vector<byte> meta_plain = metadata_dec(this->meta_data, this->key, this->nonce);

		ECB_Mode<AES>::Encryption e;
		ECB_Mode<AES>::Decryption d;
		e.SetKey(this->key, sizeof(this->key));
		d.SetKey(this->key, sizeof(this->key));
		
		int f_block_index = search_block_index(meta_plain, index);
		int b_block_index = search_block_index(meta_plain, index + del_len);
		int f_in_index = index;
		for(int i = 0; i < f_block_index; i++)
		{
			f_in_index -= (int)meta_plain[i];
		}
		int b_in_index = index + del_len;
		for(int i = 0; i < b_in_index; i++)
		{
			b_in_index -= (int)meta_plain[i];
		}
		if (meta_plain[f_block_index] == 0x00 && meta_plain[b_block_index] == 0x00)	// case1: remove bundle(s)
		{
			if(f_block_index != 0)
			{
				int f_ctr_index = search_counter_block(meta_plain, f_block_index - 1);
				int f_real_index = search_real_index(meta_plain, f_ctr_block);
				int b_real_index = search_real_index(meta_plain, b_block_index);
				byte f_ctr_block[AES::BLOCKSIZE] = {0x00, };
				byte b_ctr_block[AES::BLOCKSIZE] = {0x00, };
				d.processData(f_ctr_block, (const byte*)(this->main_data.data() + f_real_index), AES::BLOCKSIZE);
				d.ProcessData(b_ctr_block, (const byte*)(this->main_data.data() + b_real_index), AES::BLOCKSIZE);
				memcpy(f_ctr_block + AES::BLOCKSIZE/2, b_ctr_block, AES::BLOCKSIZE/2);
				e.ProcessData(this->main_data.data() + f_real_index, (const byte*)f_ctr_block, AES::BLOCKSIZE);		// replace first counter block of previous bundle
			}
			meta_plain.erase(meta_plain.begin() + f_block_index, meta_plain.begin() + b_block_index);			// update metadata
			
		}
		else
		{
			int f_ctr_index = search_counter_block(meta_plain, f_block_index);
			int b_ctr_index = search_counter_block(meta_plain, b_block_index);
			
			int f_real_index = search_real_index(meta_plain, f_ctr_index);
			int b_real_index = search_real_index(meta_plain, b_ctr_index);
			
			byte f_ctr_block[AES::BLOCKSIZE];
			byte b_ctr_block[AES::BLOCKSIZE];
			d.ProcessData(f_ctr_block, (const byte*)(this->main_data.data() + f_real_index), AES::BLOCKSIZE);
			d.ProcessData(b_ctr_block, (const byte*)(this->main_data.data() + b_real_index), AES::BLOCKSIZE);

			long long b_ctr;
			memcpy(&b_ctr, b_ctr_block, AES::BLOCKSIZE/2);
			b_ctr = b_ctr + (long long)(b_block_index - b_ctr_index - 1);
			memcpy(f_ctr_block + AES::BLOCKSIZE/2, &b_ctr, AES::BLOCKSIZE/2);
			
			byte new_ctr_block[AES::BLOCKSIZE] = {0, };
			memcpy(new_ctr_block, &b_ctr, AESLLBLOCKSIZE/2);
			memcpy(new_ctr_block + AES::BLOCKSIZE/2, b_ctr_block + AES::BLOCKSIZE/2, AES::BLOCKSIZE/2);
			
			e.ProcessData(this->main_data.data() + f_real_index, (const byte*)f_ctr_block, AES::BLOCKSIZE);      // replace first counter block of previous bundle
			meta_plain[f_block_index] = f_in_index;
			meta_plain[b_block_index] = meta_plain[b_block_index] - b_in_index;
			meta_plain.erase(meta_plain.begin() + f_block_index + 1, meta_plain.begin() + b_block_index);
			meta_plain.insert(meta_plain.begin() + f_block_index + 1, 0x00);
		}

		int f_remove_index = search_real_index(meta_plain, f_block_index) + f_in_index;
		int b_remove_index = search_real_index(meta_plain, b_block_index) + b_in_index;
		this->main_data.erase(this->main_data.begin() + f_remove_index, this->main_data.begin() + b_remove_index);
		
		<byte> counter[AES::BLOCKSIZE/2] = {0x00, };
		this->meta_data = metadata_enc(meta_plain, counter, this->key, this->nonce)
		
		return modi_info;
	}

	void Replacement(string text, int index)
	{}

	void Defrag()
	{}


}

