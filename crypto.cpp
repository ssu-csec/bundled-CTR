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

Modi_info::Modi_info()
{
	del_index = 0;
	del_len = 0;
	ins_index = 0;
	rep_index = 0;
}

void Modi_info::update_del_data(int len)
{
	this->del_len += len;
	return;
}

void Modi_info::update_ins_data(int index, vector<byte> list)
{
	this->ins_list.insert(this->ins_list.begin() + index, list.begin(), list.end());
	return;
}

void Modi_info::update_ins_data(int index, byte* block)
{
	this->ins_list.insert(this->ins_list.begin() + index, block, block + AES::BLOCKSIZE);
	return;
}
void Modi_info::update_ins_data(int index, byte one)
{
	this->ins_list.insert(this->ins_list.begin(), one);
	return;
}

void Modi_info::update_rep_data(int index, byte* block)
{
	this->rep_list.insert(this->rep_list.begin() + index, block, block + AES::BLOCKSIZE);
	return;
}

void Modi_info::update_metadata(vector<byte> metadata)
{
	this->new_meta = metadata;
	return;
}

vector<byte> metadata_gen(int len)
{
	vector<byte> metadata;
	int remain = len;
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
	byte meta[metadata.size() + AES::BLOCKSIZE/2] = {0x00, };

	byte iv[AES::BLOCKSIZE] = {0x00, };
	memcpy(iv, nonce, AES::BLOCKSIZE/2);

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

vector<byte> metadata_dec(vector<byte> meta_cipher, byte* key, byte* nonce, byte* rec_ctr)
{
	vector<byte> metadata;
	byte tmp_meta[meta_cipher.size()] = {(byte)0x00, };

	byte iv[AES::BLOCKSIZE];
	memcpy(iv, nonce, AES::BLOCKSIZE/2);
	fill_n(iv + AES::BLOCKSIZE/2, AES::BLOCKSIZE/2, (byte)0x00);

	CTR_Mode<AES>::Decryption d;
	d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
	d.ProcessData(tmp_meta, (const byte*)meta_cipher.data(), meta_cipher.size());

	memcpy(rec_ctr, tmp_meta, AES::BLOCKSIZE/2);
	metadata.insert(metadata.end(), tmp_meta + AES::BLOCKSIZE/2, tmp_meta + sizeof(tmp_meta));

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
	byte tmp_decrypt[bundle.size()] = {0x00, };
	int tmp_num = 0;										// the number of data in first data block of a bundle
	byte* index = bundle.data();							// address
	byte tmp_block[AES::BLOCKSIZE] = {0x00, };
	byte back_ctr[AES::BLOCKSIZE/2] = {0x00, };
	byte recent_ctr[AES::BLOCKSIZE/2] = {0x00, };

	byte counter[AES::BLOCKSIZE] = {0x00, };				// counter block of each bundle
	memcpy(counter, nonce, AES::BLOCKSIZE/2);

	ECB_Mode<AES>::Decryption ecb;
	CTR_Mode<AES>::Decryption ctr;	
	ecb.SetKey(key, AES::DEFAULT_KEYLENGTH);

	vector<byte> plain_meta = metadata_dec(metadata, key, nonce, recent_ctr);

	for(int i = 0; i < plain_meta.size(); i++)
	{
		if(plain_meta[i] == (byte)0x00)
		{
			memcpy(counter + AES::BLOCKSIZE/2, tmp_block, AES::BLOCKSIZE/2);
			if(tmp_bundle.size() != 0)
			{
				// decrypt previous bundle
				ctr.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, counter);
				ctr.ProcessData(tmp_decrypt, (const byte*)tmp_bundle.data(), tmp_bundle.size());
				for (int j = 0; j < tmp_bundle.size() -  tmp_num; j++)
					plaintext.push_back(tmp_decrypt[j + tmp_num]);
				tmp_bundle.clear();
				memset(tmp_decrypt, (byte)0x00, sizeof(tmp_decrypt));
			}
			// decrypt first block and generate counter of new bundle
			ecb.ProcessData(tmp_block, index, AES::BLOCKSIZE);
			if(i != 0 && memcmp(back_ctr, tmp_block, AES::BLOCKSIZE/2) != 0)
				cout << "Error in block number" << i << endl;
			memcpy(back_ctr, tmp_block + AES::BLOCKSIZE/2, AES::BLOCKSIZE/2);
			
			index += AES::BLOCKSIZE;
		}
		else
		{
			// insert block data to tmp_bundle
			if(plain_meta[i - 1] == (byte)0x00 && plain_meta.size() - 1 != i && plain_meta[i + 1] != 0x00)			// first data block of a bundle
			{
				tmp_num = AES::BLOCKSIZE - (int)plain_meta[i];
				for(int j = 0; j < tmp_num; j++)
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
		memcpy(counter + AES::BLOCKSIZE/2, tmp_block, AES::BLOCKSIZE/2);
		ctr.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, counter);
		ctr.ProcessData(tmp_decrypt, (const byte*)tmp_bundle.data(), tmp_bundle.size());
		for (int j = tmp_num; j < tmp_bundle.size(); j++)
			plaintext.push_back(tmp_decrypt[j]);
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
		if(index == 0)
			break;
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

byte* find_ctr(byte* counter, int num)
{
	byte* res = new byte[AES::BLOCKSIZE/2];
	memcpy(res, counter, AES::BLOCKSIZE/2);
	long long tmp_ctr = 0;
	unsigned int check = 1;
	if (*(char *)&check == 1) 			// little endian
	{
		int start = 0;
		int end = 7;
		while (start < end) {
			int temp = res[start];
			res[start] = res[end];
			res[end] = temp;

			start++;
			end--;
		}
	}
	memcpy(&tmp_ctr, res, AES::BLOCKSIZE/2);
	tmp_ctr += (long long)num;
	memcpy(res, &tmp_ctr, AES::BLOCKSIZE/2);
	if (*(char *)&check == 1)           // little endian
	{
		int start = 0;
		int end = 7;
		while (start < end) {
			// swap
			int temp = res[start];
			res[start] = res[end];
			res[end] = temp;

			start++;
			end--;
		}
	}

	return res;
}

bundled_CTR::bundled_CTR(byte* key, byte* nonce)
{
	memcpy(this->key,key, AES::BLOCKSIZE);
	memcpy(this->nonce,nonce, AES::BLOCKSIZE/2);
}
bundled_CTR::bundled_CTR(vector<byte> data, vector<byte> meta, byte* key, byte* nonce)
{
	this->main_data = data;
	this->meta_data = meta;
	memcpy(this->key,key, AES::BLOCKSIZE);  
	memcpy(this->nonce,nonce, AES::BLOCKSIZE/2);
}

bundled_CTR::~bundled_CTR()
{}

vector<byte> bundled_CTR::print_data()
{
	return this->main_data;
}

vector<byte> bundled_CTR::print_meta()
{
	return this->meta_data;
}

Modi_info bundled_CTR::Insertion(string text, int index)
{
	Modi_info modi_info;
	byte recent_ctr[AES::BLOCKSIZE/2] = {0x00, };						// will be inserted on front of the metadata
	byte next_ctr[AES::BLOCKSIZE/2] = {0x00, };							// whoch save the next counter of inserted data bundle
	vector<byte> meta_plain = metadata_dec(this->meta_data, this->key, this->nonce, recent_ctr);
	vector<int> bundle_list = bundle_list_gen(meta_plain);

	ECB_Mode<AES>::Encryption e;
	ECB_Mode<AES>::Decryption d;
	e.SetKey(this->key, sizeof(this->key));
	d.SetKey(this->key, sizeof(this->key));

	int block_index = search_block_index(meta_plain, index);
	int in_index = index;
	for(int i = 0; i < block_index; i++)
	{
		in_index -= (int)meta_plain[i];
	}
	if(meta_plain[block_index] != AES::BLOCKSIZE)			// cut the first or last block of bundle
	{
		string tmp_str = "";
		if(meta_plain[block_index - 1] == 0x00) // cut the first block in bundle
		{
			int dec_index = search_real_index(meta_plain, block_index - 1);
			byte ctr_block[AES::BLOCKSIZE];
			d.ProcessData(ctr_block, (const byte*)(this->main_data.data() + dec_index), AES::BLOCKSIZE);
			memcpy(ctr_block + AES::BLOCKSIZE/2, ctr_block, AES::BLOCKSIZE/2);
			memcpy(ctr_block, this->nonce, AES::BLOCKSIZE/2);
			e.ProcessData(ctr_block, (const byte*)ctr_block, AES::BLOCKSIZE);
			for (int i = 0; i < in_index; i++)
			{
				tmp_str += to_string(ctr_block[(AES::BLOCKSIZE - (int)meta_plain[block_index]) + i]^this->main_data[dec_index + AES::BLOCKSIZE + i]);
			}
			text = tmp_str + text;
			this->main_data.erase(this->main_data.begin() + dec_index + AES::BLOCKSIZE, this->main_data.begin() + dec_index + AES::BLOCKSIZE + in_index);
			modi_info.del_index = dec_index + AES::BLOCKSIZE;
			modi_info.update_del_data(in_index);
			meta_plain[block_index] -= (byte)in_index;
			block_index--;
		}
		else                                    // cut the last block in bundle
		{
			int ctr_index = search_block_index(meta_plain, block_index);
			int dec_index = search_real_index(meta_plain, ctr_index);
			int b_real_index = search_real_index(meta_plain, block_index);
			byte ctr_block[AES::BLOCKSIZE];
			d.ProcessData(ctr_block, (const byte*)(this->main_data.data() + dec_index), AES::BLOCKSIZE);
			byte* index_block_ctr = find_ctr(ctr_block, block_index - ctr_index - 1);
			memcpy(ctr_block, this->nonce, AES::BLOCKSIZE/2);
			memcpy(ctr_block + AES::BLOCKSIZE/2, index_block_ctr, AES::BLOCKSIZE/2);
			e.ProcessData(ctr_block, (const byte*)ctr_block, AES::BLOCKSIZE);
			for(int i = in_index; i < meta_plain[block_index]; i++)
			{
				tmp_str += to_string(ctr_block[i]^this->main_data[b_real_index + i]);
			}
			text = text + tmp_str;
			this->main_data.erase(this->main_data.begin() + b_real_index + in_index, this->main_data.begin() + b_real_index + (int)meta_plain[block_index]);
			modi_info.del_index = b_real_index + in_index;
			modi_info.update_del_data((int)meta_plain[block_index] - in_index);
			meta_plain[block_index] = (byte)in_index;
			block_index++;
			delete[] index_block_ctr;
		}
		in_index = 0;
	}

	int real_index = search_real_index(meta_plain, block_index) + in_index;

	if(block_index == meta_plain.size() || meta_plain[block_index] == 0x00)	// case1: insert between two bundles 
	{
		if(block_index != 0)
		{
			int f_ctr_index = search_counter_block(meta_plain, block_index - 1); 
			int f_real_index = search_real_index(meta_plain, f_ctr_index);
			byte f_ctr_block[AES::BLOCKSIZE];
			d.ProcessData(f_ctr_block, (const byte*)(this->main_data.data() + f_real_index), AES::BLOCKSIZE);
			memcpy(next_ctr, f_ctr_block + AES::BLOCKSIZE, AES::BLOCKSIZE/2);
			memcpy(f_ctr_block + AES::BLOCKSIZE, recent_ctr, AES::BLOCKSIZE/2);
			e.ProcessData(this->main_data.data() + f_real_index, (const byte*)f_ctr_block, AES::BLOCKSIZE);
			modi_info.rep_index = f_real_index;
			modi_info.update_rep_data(0, this->main_data.data() + f_real_index);
		}
		else
		{
			int b_real_index = search_real_index(meta_plain, block_index);
			byte b_ctr_block[AES::BLOCKSIZE];
			d.ProcessData(b_ctr_block, (const byte*)(this->main_data.data() + b_real_index), AES::BLOCKSIZE);
			memcpy(next_ctr, b_ctr_block, AES::BLOCKSIZE/2);
		}
		vector<byte> new_data = encryption(this->nonce, recent_ctr, text, this->key, next_ctr);
		vector <byte> new_meta = metadata_gen(text.length());
		meta_plain.insert(meta_plain.begin() + block_index, new_meta.begin(), new_meta.end());
		byte *tmp_ctr = find_ctr(recent_ctr, new_meta.size());
		memcpy(recent_ctr, tmp_ctr, AES::BLOCKSIZE/2);
		delete[] tmp_ctr;
	}
	else				// case2: insert at a middle of a bundle
	{
		int f_ctr_index = search_counter_block(meta_plain, block_index);
		int f_real_index = search_real_index(meta_plain, f_ctr_index);
		byte f_ctr_block[AES::BLOCKSIZE];
		byte b_ctr_block[AES::BLOCKSIZE];
		d.ProcessData(f_ctr_block, (const byte*)(this->main_data.data() + f_real_index), AES::BLOCKSIZE);
		byte* index_block_ctr = find_ctr(f_ctr_block, block_index - f_ctr_index - 1);
		
		memcpy(b_ctr_block, index_block_ctr, AES::BLOCKSIZE/2);
		memcpy(b_ctr_block + AES::BLOCKSIZE/2, f_ctr_block + AES::BLOCKSIZE/2, AES::BLOCKSIZE/2);		// make new counter block of back part of index bundle
		e.ProcessData(b_ctr_block, (const byte*)b_ctr_block, AES::BLOCKSIZE);
		memcpy(next_ctr, index_block_ctr, AES::BLOCKSIZE/2);
		memcpy(f_ctr_block + AES::BLOCKSIZE/2, recent_ctr, AES::BLOCKSIZE/2);							// connect new bundle to front part of index block
		e.ProcessData(this->main_data.data() + f_real_index, (const byte*)f_ctr_block, AES::BLOCKSIZE); // update counter block of front bundle
		
		modi_info.rep_index = f_real_index;
		modi_info.update_rep_data(0, this->main_data.data() + f_real_index);
		
		if(in_index != 0)
		{
			meta_plain[block_index] = (byte)in_index;
			meta_plain.insert(meta_plain.begin() + block_index + 1, byte(AES::BLOCKSIZE - in_index));
		}
		vector<byte> new_data = encryption(this->nonce, recent_ctr, text, this->key, next_ctr);
		vector<byte> new_meta = metadata_gen(text.length());
		byte *tmp_ctr = find_ctr(recent_ctr, new_meta.size());
		memcpy(recent_ctr, tmp_ctr, AES::BLOCKSIZE/2);
		delete[] tmp_ctr;
		this->main_data.insert(this->main_data.begin() + real_index, b_ctr_block, b_ctr_block + AES::BLOCKSIZE); // insert new counter block
		modi_info.update_ins_data(0, b_ctr_block);
		meta_plain.insert(meta_plain.begin() + block_index + 1, 0x00);
		this->main_data.insert(this->main_data.begin() + real_index, new_data.begin(), new_data.end());			 // insert new bundle
		modi_info.update_ins_data(0, new_data);
		meta_plain.insert(meta_plain.begin() + block_index + 1, new_meta.begin(), new_meta.end());

		delete[] index_block_ctr;
	}
	modi_info.ins_index = real_index;
	this->meta_data = metadata_enc(meta_plain, recent_ctr, this->key, this->nonce);
	
	modi_info.update_metadata(this->meta_data); 
	return modi_info;
}

Modi_info bundled_CTR::Deletion(int del_len, int index)
{
	Modi_info modi_info;
	byte recent_ctr[AES::BLOCKSIZE/2] = {0x00, };
	vector<byte> meta_plain = metadata_dec(this->meta_data, this->key, this->nonce, recent_ctr);

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
	for(int i = 0; i < b_block_index; i++)
	{
		b_in_index -= (int)meta_plain[i];
	}
	int f_remove_index = search_real_index(meta_plain, f_block_index) + f_in_index;
	int b_remove_index = search_real_index(meta_plain, b_block_index) + b_in_index;
	modi_info.del_index = f_remove_index;
	if (meta_plain[f_block_index] == 0x00)
	{
		if (meta_plain[b_block_index] == 0x00)		// case1: remove bundle(s)
		{
			if(f_block_index != 0)
			{
				int f_ctr_index = search_counter_block(meta_plain, f_block_index - 1);
				int f_real_index = search_real_index(meta_plain, f_ctr_index);
				int b_real_index = search_real_index(meta_plain, b_block_index);
				byte f_ctr_block[AES::BLOCKSIZE] = {0x00, };
				byte b_ctr_block[AES::BLOCKSIZE] = {0x00, };
				d.ProcessData(f_ctr_block, (const byte*)(this->main_data.data() + f_real_index), AES::BLOCKSIZE);
				d.ProcessData(b_ctr_block, (const byte*)(this->main_data.data() + b_real_index), AES::BLOCKSIZE);
				memcpy(f_ctr_block + AES::BLOCKSIZE/2, b_ctr_block, AES::BLOCKSIZE/2);
				e.ProcessData(this->main_data.data() + f_real_index, (const byte*)f_ctr_block, AES::BLOCKSIZE);		// replace first counter block of previous bundle
				modi_info.rep_index = f_real_index;
				modi_info.update_rep_data(0, this->main_data.data() + f_real_index);
			}
			meta_plain.erase(meta_plain.begin() + f_block_index, meta_plain.begin() + b_block_index);			// update metadata
		}
		else							// case2: remove from front part of a bundle
		{
			int b_ctr_index = search_counter_block(meta_plain, b_block_index);
			int b_real_index = search_real_index(meta_plain, b_ctr_index);

			byte b_ctr_block[AES::BLOCKSIZE]; 
			d.ProcessData(b_ctr_block, (const byte*)(this->main_data.data() + b_real_index), AES::BLOCKSIZE);
		
			byte* new_ctr = find_ctr(b_ctr_block, (b_block_index - b_ctr_index - 1));

			if(f_block_index != 0)
			{
				int f_ctr_index = search_counter_block(meta_plain, f_block_index - 1);
				int f_real_index = search_real_index(meta_plain, f_ctr_index);

				byte f_ctr_block[AES::BLOCKSIZE];
				d.ProcessData(f_ctr_block, (const byte*)(this->main_data.data() + f_real_index), AES::BLOCKSIZE);
				modi_info.ins_index = f_remove_index;
				if(meta_plain[b_block_index] != AES::BLOCKSIZE && meta_plain[b_block_index - 1] != 0x00)        // remove the front part of the last block of bundle
				{
					byte dec_block[AES::BLOCKSIZE];
					memcpy(dec_block, this->nonce, AES::BLOCKSIZE/2);
					memcpy(dec_block + AES::BLOCKSIZE/2, new_ctr, AES::BLOCKSIZE/2);
					e.ProcessData(dec_block, (const byte*)dec_block, AES::BLOCKSIZE);

					byte enc_block[AES::BLOCKSIZE];
					memcpy(enc_block, this->nonce, AES::BLOCKSIZE/2);
					memcpy(enc_block + AES::BLOCKSIZE/2, recent_ctr, AES::BLOCKSIZE/2);
					e.ProcessData(enc_block, (const byte*)enc_block, AES::BLOCKSIZE);

					byte tmp_byte;
					for(int i = b_in_index; i < meta_plain[b_block_index]; i++)
					{
						tmp_byte = dec_block[i]^this->main_data[b_real_index + i - b_in_index];
						this->main_data[b_remove_index + i - b_in_index] = tmp_byte^enc_block[i];
						modi_info.update_ins_data(i - b_in_index, this->main_data[b_remove_index + i - b_in_index]);
						modi_info.del_len++;
					}
					memcpy(b_ctr_block, recent_ctr, AES::BLOCKSIZE/2);
					memcpy(new_ctr, recent_ctr, AES::BLOCKSIZE/2);
					byte* tmp_recent_ctr = find_ctr(recent_ctr, 1);
					memcpy(recent_ctr, tmp_recent_ctr, AES::BLOCKSIZE/2);
					delete[] tmp_recent_ctr;
				}
				memcpy(f_ctr_block + AES::BLOCKSIZE/2, new_ctr, AES::BLOCKSIZE/2);

				e.ProcessData(this->main_data.data() + f_real_index, (const byte*)f_ctr_block, AES::BLOCKSIZE);     // replace first counter block of previous bundle
				modi_info.rep_index = f_real_index;
				modi_info.update_rep_data(0, this->main_data.data() + f_real_index);
			}
			memcpy(b_ctr_block, new_ctr, AES::BLOCKSIZE/2);
			delete[] new_ctr;
			e.ProcessData(b_ctr_block, (const byte*)b_ctr_block, AES::BLOCKSIZE);
			this->main_data.insert(this->main_data.begin() + b_remove_index, b_ctr_block, b_ctr_block + AES::BLOCKSIZE);
			modi_info.update_ins_data(0, b_ctr_block);
			meta_plain[b_block_index] -= (int)b_in_index;
			meta_plain.erase(meta_plain.begin() + f_block_index + 1, meta_plain.begin() + b_block_index);
		}
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
		if(b_ctr_index == b_block_index)						// case3: remove back part of a bundle
		{
			memcpy(f_ctr_block + AES::BLOCKSIZE/2, b_ctr_block, AES::BLOCKSIZE/2);
			meta_plain.erase(meta_plain.begin() + f_block_index, meta_plain.begin() + b_block_index);
		}
		else
		{
			modi_info.ins_index = f_remove_index;
			byte* b_ctr = find_ctr(b_ctr_block, (b_block_index - b_ctr_index - 1));
			memcpy(f_ctr_block + AES::BLOCKSIZE/2, b_ctr, AES::BLOCKSIZE/2);

			byte new_ctr_block[AES::BLOCKSIZE] = {0, };				// new counter block of back block
			if(meta_plain[b_block_index] != AES::BLOCKSIZE && meta_plain[b_block_index - 1] != 0x00)		// remove the front part of the last block of bundle
			{
				byte dec_block[AES::BLOCKSIZE];
				memcpy(dec_block, this->nonce, AES::BLOCKSIZE/2);
				memcpy(dec_block + AES::BLOCKSIZE/2, b_ctr, AES::BLOCKSIZE/2);
				e.ProcessData(dec_block, (const byte*)dec_block, AES::BLOCKSIZE);

				byte enc_block[AES::BLOCKSIZE];
				memcpy(enc_block, this->nonce, AES::BLOCKSIZE/2);
				memcpy(enc_block + AES::BLOCKSIZE/2, recent_ctr, AES::BLOCKSIZE/2);
				e.ProcessData(enc_block, (const byte*)enc_block, AES::BLOCKSIZE);

				byte tmp_byte;
				for(int i = b_in_index; i < meta_plain[b_block_index]; i++)
				{
					tmp_byte = dec_block[i]^this->main_data[b_remove_index + i - b_in_index];
					this->main_data[b_remove_index + i - b_in_index] = tmp_byte^enc_block[i];
					modi_info.update_ins_data(i - b_in_index, this->main_data[b_remove_index + 1 - b_in_index]);
					modi_info.del_len++;
				}
				memcpy(b_ctr, recent_ctr, AES::BLOCKSIZE/2);
				memcpy(f_ctr_block + AES::BLOCKSIZE/2, recent_ctr, AES::BLOCKSIZE/2);						// connect back bundle to previous bundle
				byte* tmp_recent_ctr = find_ctr(recent_ctr, 1);
				memcpy(recent_ctr, tmp_recent_ctr, AES::BLOCKSIZE/2);
				delete[] tmp_recent_ctr;

			}
			memcpy(new_ctr_block, b_ctr, AES::BLOCKSIZE/2);
			memcpy(new_ctr_block + AES::BLOCKSIZE/2, b_ctr_block + AES::BLOCKSIZE/2, AES::BLOCKSIZE/2);
			e.ProcessData(new_ctr_block, (const byte*)new_ctr_block, AES::BLOCKSIZE);
			
			main_data.insert(this->main_data.begin() + b_remove_index, new_ctr_block, new_ctr_block + AES::BLOCKSIZE);
			modi_info.update_ins_data(0, this->main_data.data() + b_remove_index);
			
			b_in_index = (int)meta_plain[b_block_index] - b_in_index;
			meta_plain.erase(meta_plain.begin() + f_block_index, meta_plain.begin() + b_block_index + 1);
			meta_plain.insert(meta_plain.begin() + f_block_index, (byte)b_in_index);
			meta_plain.insert(meta_plain.begin() + f_block_index, 0x00);
		}

		if(meta_plain[f_block_index] != AES::BLOCKSIZE && meta_plain[f_block_index - 1] == 0x00)			// remove back part of the first block in bundle
		{
			if(f_block_index - 1 != 0)
			{
				int prev_ctr_index = search_counter_block(meta_plain, f_block_index - 2);
				int prev_real = search_real_index(meta_plain, prev_ctr_index);
				byte prev_ctr_block[AES::BLOCKSIZE];
				d.ProcessData(prev_ctr_block, (const byte*)(this->main_data.data() + prev_real), AES::BLOCKSIZE);
				memcpy(prev_ctr_block + AES::BLOCKSIZE/2, recent_ctr, AES::BLOCKSIZE/2);
				e.ProcessData(this->main_data.data() + prev_real, (const byte*)prev_ctr_block, AES::BLOCKSIZE);
			}

			byte dec_block[AES::BLOCKSIZE];
			memcpy(dec_block, this->nonce, AES::BLOCKSIZE/2);
			memcpy(dec_block + AES::BLOCKSIZE/2, f_ctr_block, AES::BLOCKSIZE/2);
			e.ProcessData(dec_block, (const byte*)dec_block, AES::BLOCKSIZE);

			byte enc_block[AES::BLOCKSIZE];
			memcpy(enc_block, this->nonce, AES::BLOCKSIZE/2);
			memcpy(enc_block + AES::BLOCKSIZE/2, recent_ctr, AES::BLOCKSIZE/2);
			e.ProcessData(enc_block, (const byte*)enc_block, AES::BLOCKSIZE);

			byte tmp_byte;
			for(int i = 0; i < f_in_index; i++)
			{
				tmp_byte = dec_block[(AES::BLOCKSIZE - meta_plain[f_block_index]) + i]^this->main_data[f_real_index + i - f_in_index];
				this->main_data[f_real_index + i - f_in_index] = tmp_byte^enc_block[(AES::BLOCKSIZE - meta_plain[f_block_index]) + i];
				modi_info.update_ins_data(i, this->main_data[f_real_index + i - f_in_index]);
				modi_info.del_len++;
				modi_info.del_index--;
			}

			memcpy(f_ctr_block, recent_ctr, AES::BLOCKSIZE/2);												// update counter to recent counter
			byte* tmp_recent_ctr = find_ctr(recent_ctr, 1);
			memcpy(recent_ctr, tmp_recent_ctr, AES::BLOCKSIZE/2);
			delete[] tmp_recent_ctr;
		}

		meta_plain.insert(meta_plain.begin() + f_block_index, (byte)f_in_index);
		e.ProcessData(this->main_data.data() + f_real_index, (const byte*)f_ctr_block, AES::BLOCKSIZE);      // replace first countunter block of previous bundle
		modi_info.rep_index = f_real_index;
		modi_info.update_rep_data(0, this->main_data.data() + f_real_index);
	}
	this->main_data.erase(this->main_data.begin() + f_remove_index, this->main_data.begin() + b_remove_index);
	modi_info.del_len += (b_remove_index - f_remove_index);
	this->meta_data = metadata_enc(meta_plain, recent_ctr, this->key, this->nonce);
	
	modi_info.update_metadata(this->meta_data); 
	return modi_info;
}

Modi_info bundled_CTR::Replacement(string text, int index)
{
	Modi_info modi_info;
	byte recent_ctr[AES::BLOCKSIZE/2] = {0x00, };		// which save the next counter of recently used counter
	byte next_ctr[AES::BLOCKSIZE/2] = {0x00, };			// which save the next counter of inserted data bundle
	vector<byte> meta_plain = metadata_dec(this->meta_data, this->key, this->nonce, recent_ctr);
	vector<int> bundle_list = bundle_list_gen(meta_plain);

	ECB_Mode<AES>::Encryption e;
	ECB_Mode<AES>::Decryption d;
	e.SetKey(this->key, sizeof(this->key));
	d.SetKey(this->key, sizeof(this->key));

	int f_block_index = search_block_index(meta_plain, index);
	int b_block_index = search_block_index(meta_plain, index + text.length());
	int f_in_index = index;
	for(int i = 0; i < f_block_index; i++)
	{   
		f_in_index -= (int)meta_plain[i];
	}   
	int b_in_index = index + text.length();
	for(int i = 0; i < b_in_index; i++)
	{   
		b_in_index -= (int)meta_plain[i];
	}

	if(meta_plain[f_block_index] != AES::BLOCKSIZE && meta_plain[f_block_index - 1] == 0x00)            // cut the first block in bundle
	{   
		string tmp_str = ""; 
		int dec_index = search_real_index(meta_plain, f_block_index - 1); 
		byte ctr_block[AES::BLOCKSIZE];
		d.ProcessData(ctr_block, (const byte*)(this->main_data.data() + dec_index), AES::BLOCKSIZE);
		memcpy(ctr_block + AES::BLOCKSIZE/2, ctr_block, AES::BLOCKSIZE/2);
		memcpy(ctr_block, this->nonce, AES::BLOCKSIZE/2);
		e.ProcessData(ctr_block, (const byte*)ctr_block, AES::BLOCKSIZE);
		for (int i = 0; i < f_in_index; i++)
		{   
			tmp_str += to_string(ctr_block[(AES::BLOCKSIZE - (int)meta_plain[f_block_index]) + i]^this->main_data[dec_index + AES::BLOCKSIZE + i]);
		}   
		text = tmp_str + text;
		this->main_data.erase(this->main_data.begin() + dec_index + AES::BLOCKSIZE, this->main_data.begin() + dec_index + AES::BLOCKSIZE + f_in_index);
		meta_plain[f_block_index] -= (byte)f_in_index;
		f_block_index--;
		f_in_index = 0;
	}

	if(meta_plain[b_block_index] != AES::BLOCKSIZE && meta_plain[b_block_index - 1] != 0x00)			// cut the last block in bundle
	{   
		string tmp_str = "";
		int ctr_index = search_block_index(meta_plain, b_block_index);
		int dec_index = search_real_index(meta_plain, ctr_index);
		int real_index = search_real_index(meta_plain, b_block_index);
		byte ctr_block[AES::BLOCKSIZE];
		d.ProcessData(ctr_block, (const byte*)(this->main_data.data() + dec_index), AES::BLOCKSIZE);
		byte* index_block_ctr = find_ctr(ctr_block, b_block_index - ctr_index - 1);
		memcpy(ctr_block, this->nonce, AES::BLOCKSIZE/2);
		memcpy(ctr_block + AES::BLOCKSIZE/2, index_block_ctr, AES::BLOCKSIZE/2);
		e.ProcessData(ctr_block, (const byte*)ctr_block, AES::BLOCKSIZE);
		for(int i = b_in_index; i < meta_plain[b_block_index]; i++)
		{
			tmp_str += to_string(ctr_block[i]^this->main_data[real_index + i]);
		}
		text = text + tmp_str;
		this->main_data.erase(this->main_data.begin() + real_index + b_in_index, this->main_data.begin() + real_index + (int)meta_plain[b_block_index]);
		meta_plain[b_block_index] = (byte)b_in_index;
		b_block_index++;
		delete[] index_block_ctr;
		b_in_index = 0;
	}
	int f_rep_index = search_real_index(meta_plain, f_block_index) + f_in_index;
	int b_rep_index = search_real_index(meta_plain, b_block_index) + b_in_index;
	
	if (meta_plain[f_block_index] == 0x00)		// case1-1: replace from the front part of a bundle
	{
		if(f_block_index != 0)
		{
			int f_ctr_index = search_counter_block(meta_plain, f_block_index - 1);
			int f_real_index = search_real_index(meta_plain, f_ctr_index);
			byte f_ctr_block[AES::BLOCKSIZE];
			d.ProcessData(f_ctr_block, (const byte*)(this->main_data.data() + f_real_index), AES::BLOCKSIZE);
			memcpy(f_ctr_block + AES::BLOCKSIZE/2, recent_ctr, AES::BLOCKSIZE/2);
			e.ProcessData(this->main_data.data() + f_real_index, (const byte*)f_ctr_block, AES::BLOCKSIZE);			// replace the counter block of previous bundle
			modi_info.rep_index = f_real_index;
			modi_info.update_rep_data(0, this->main_data.data() + f_real_index);
		}
	}
	else										// case1-2: replace from the middle of a bundle
	{
		int f_ctr_index = search_counter_block(meta_plain, f_block_index);
		int f_real_index = search_real_index(meta_plain, f_ctr_index);
		byte f_ctr_block[AES::BLOCKSIZE];
		d.ProcessData(f_ctr_block, (const byte*)(this->main_data.data() + f_real_index), AES::BLOCKSIZE);
		memcpy(f_ctr_block + AES::BLOCKSIZE/2, recent_ctr, AES::BLOCKSIZE/2);
		e.ProcessData(this->main_data.data() + f_real_index, (const byte*)f_ctr_block, AES::BLOCKSIZE);				// replace the counter block of previous bundle
		modi_info.rep_index = f_real_index;
		modi_info.update_rep_data(0, this->main_data.data() + f_real_index);
	}
	if (meta_plain[b_block_index] == 0x00)      // case2-1: replace to the end part of a bundle
	{
		int b_real_index = search_real_index(meta_plain, b_block_index);
		byte b_ctr_block[AES::BLOCKSIZE] = {0x00, };
		d.ProcessData(b_ctr_block, (const byte*)(this->main_data.data() + b_real_index), AES::BLOCKSIZE);
		memcpy(next_ctr, b_ctr_block, AES::BLOCKSIZE/2);
	}
	else                            			// case2-2: remove to the middle of a bundle
	{
		int b_ctr_index = search_counter_block(meta_plain, b_block_index);
		int b_real_index = search_real_index(meta_plain, b_ctr_index);
		byte b_ctr_block[AES::BLOCKSIZE];
		d.ProcessData(b_ctr_block, (const byte*)(this->main_data.data() + b_real_index), AES::BLOCKSIZE);
		byte* b_ctr = find_ctr(b_ctr_block, b_block_index - b_ctr_index - 1);
		memcpy(next_ctr, b_ctr, AES::BLOCKSIZE/2);
		memcpy(b_ctr_block, b_ctr, AES::BLOCKSIZE/2);
		e.ProcessData(b_ctr_block, (const byte*)b_ctr_block, AES::BLOCKSIZE);
		this->main_data.insert(this->main_data.begin() + b_rep_index, b_ctr_block, b_ctr_block + AES::BLOCKSIZE);
		modi_info.update_ins_data(0, this->main_data.data() + b_rep_index);
	}
	vector<byte> new_data = encryption(this->nonce, recent_ctr, text, this->key, next_ctr);
	this->main_data.erase(this->main_data.begin() + f_rep_index, this->main_data.begin() + b_rep_index);
	modi_info.del_len += b_rep_index - f_rep_index;
	this->main_data.insert(this->main_data.begin() + f_rep_index, new_data.begin(), new_data.end());
	modi_info.update_ins_data(0, new_data);
	modi_info.ins_index = f_rep_index;
	this->meta_data = metadata_enc(meta_plain, recent_ctr, this->key, this->nonce);
	
	modi_info.update_metadata(this->meta_data);
	return modi_info;
}

void bundled_CTR::Defrag()
{
}

