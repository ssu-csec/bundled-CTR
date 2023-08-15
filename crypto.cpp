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

int search_real_index(vector<byte> metadata, int index)
{
	int real = 0;
	int check = index;
	for (int i = 0; i < metadata.size(); i++)
	{	
		check -= metadata[i];
		if (check > 0)
		{
			if (metadata[i] == 0x00)
			{	
				real += AES::BLOCKSIZE;
			}
			else
			{
				real += metadata[i];
			}
		}
		else if (check < 0)
		{
			check += metadata[i];
			real += check;
			break;
		}
		else
		{
			break;
		}
	}


	return real;

}

int search_counter_block(vector<int> bundle_list, int index)
{
	int counter_index = -1;
	for (int i = 0; i < bundle_list.size(); i++)
	{
		if (bundle_list[i] > index)
		{
			index = bundle_list[i - 1];
			break;
		}
	}

	return counter_index;
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
	{// 1) Modi_info 할당
	Modi_info modi_info_instance;

	// 2) bundle_list 생성
	vector<byte> meta_plain = metadata_dec(this->meta_data, this->key, this->nonce);
	vector<int> bundle_list = bundle_list_gen(meta_plain);

	// 3) data가 삽입될 실제 인덱스와 번들 탐색
	int real_index = search_real_index(meta_plain, index);
	int head_ctr_add = search_counter_block(bundle_list, real_index);

	// 4) 메타 데이터의 첫 8바이트에 담긴 마지막 사용 카운터(C1) 습득
	// Assuming meta_data stores the last used counter in the first 8 bytes
	byte C1[AES::BLOCKSIZE/2];
	memcpy(C1, meta_data.data(), AES::BLOCKSIZE/2);

	if (head_ctr_add != -1) // 삽입 index가 번들 중간에 위치하는가?
	{
		// yes) - 1) 삽입될 위치의 뒷 번들의 첫블록을 복호화하고 연속성 위한 카운터(C2) 습득
		byte C2[AES::BLOCKSIZE/2];
		// decrypt the following bundle's first block to get the C2
		// ... (this part is not clear, you might need more implementation details)

		// yes) - 2) 마지막 카운터(C1)와 습득된 카운터(C2)를 이용하여 삽입 데이터 번들화
		// ... (you will use C1 and C2 to create the bundled data for insertion)

	}
	else
	{
		// no) - 1) 삽입 인덱스 기준으로 뒷부분을 암호화하는데 사용된 카운터 추정(C3)
		byte C3[AES::BLOCKSIZE/2];
		// ... (estimate the counter C3 based on the insertion index)

		// no) - 2) 추정된 카운터(C3)를 이용하여 번들 분화(앞 번들과 뒷번들로 분화)
		// ... (you will use C3 to split the bundle into front and back parts)

		// no) - 3) 마지막 카운터(C1)와 추정된 카운터(C3)를 사용하여 삽입 데이터 번들화
		// ... (you will use C1 and C3 to create the bundled data for insertion)
	}

	// 5) 삽입 번들 기존 번들사이에 삽입
	// ... (you will insert the new bundled data in the middle of the existing data)

	// 6) 메타데이터에 메인데이터의 삽입사항 반영하여 업데이트
	// ... (you will update the meta_data to reflect the changes in the main_data)}

	Modi_info Deletion(int del_len, int index)
	{
		Modi_info modi_info();
		vector<byte> meta_plain = metadata_dec(this->metadata, this->key, this->nonce);
		vector<int> bundle_list = bundle_list_gen(meta_plain);
		
		int head = search_real_index(meta_plain, index);
		int tail = search_real_index(meta_plain, index + del_len);
		int head_ctr_add = search_counter_block(bundle_list, head);
		int tail_ctr_add = search_counter_block(bundle_list, tail);

		ECB_Mode<AES>::Encryption e;
		ECB_Mode<AES>::Decryption d;
		e.SetKey(this->key, sizeof(this->key));
		d.SetKey(this->key, sizeof(this->key));
		byte head_counter[AES::BLOCKSIZE] = {0x00, };
		byte tail_counter[AES::BLOCKSIZE] = {0x00, };

		this->main_data.erase(head, tail);

		// modify metadata and update

		return modi_info;
	}

	void Replacement(string text, int index)
	{}

	void Defrag()
	{}


}

