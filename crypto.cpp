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
int search_next_counter_block(vector<byte> metadata, int index)//입력인덱스가 존재하는 번들 뒷 번들의 카운터가 위치한 index를 알아냄
{
   int i = index;
   while(true)
   {
      if (metadata[i] == 0x00)
      {   
         return i;//뒤에 위치한 카운터의 인덱스 리턴
         
      }
      i++;//인덱스 값을 상승시킨 ==>오른쪽으로 이동
   }

   return 0;
}

int search_index_counter(vector<byte> metadata, int index,int counter)//번들의 
{
   int index_sum = 0;
   int index_counter = counter;
   int start_index = search_counter_block(metadata,index);
   int end_index = search_real_index(metadata,index);
   int t = 0;
   while (1) {
      index_sum = +metadata[t];
      if ((index_sum > start_index) && (index_sum < end_index)) {
         index_counter++;
      }
      if (index_sum > end_index) {
         break;
      }
      t++;
   }
   return index_counter;
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

	Modi_info bundled_CTR::Insertion(string text, int index)
{
    Modi_info modi_info_instance;

    ECB_Mode<AES>::Encryption e;
    ECB_Mode<AES>::Decryption d;
    e.SetKey(this->key, sizeof(this->key)); 
    d.SetKey(this->key, sizeof(this->key));

    // 2) bundle_list 생성
    vector<byte> meta_plain = metadata_dec(this->meta_data, this->key, this->nonce);
    vector<int> bundle_list = bundle_list_gen(meta_plain);

    // 3) data가 삽입될 실제 인덱스와 번들 탐색
    int real_index = search_real_index(meta_plain, index);
    int head_ctr_index = search_counter_block(meta_plain, real_index);
    int next_counter_index = search_next_counter_block(meta_plain, real_index);
    vector<byte> temp_bundle;
    vector<byte> temp_metadata;

    // 4) 메타 데이터의 첫 8바이트에 담긴 마지막 사용 카운터(C1) 습득
    byte C1[AES::BLOCKSIZE / 2];
    memcpy(C1, this->meta_data.data(), AES::BLOCKSIZE / 2);

    if (real_index == head_ctr_index) //번들과 번들 사이에 삽입되는 경우
    {
        byte C2[AES::BLOCKSIZE / 2];
        d.ProcessData(C2, (const byte*)(this->main_data.data() + next_counter_index), AES::BLOCKSIZE/2);
        temp_bundle = encryption(this->nonce, C1, text, this->key, C2);

        // 5) 삽입 번들 기존 번들사이에 삽입
        main_data.insert(main_data.begin() + real_index, temp_bundle.begin(), temp_bundle.end());

        int save = 0;
        int sum = 0;
        for(int i = 0; i < meta_plain.size(); i++)//삽입할 메타데이터의 인덱스를 알아내는 과정
        {
            sum += meta_plain[i];
            if (meta_plain[i] == 0)
            {
                save = i;
            }
            if (sum > real_index)
            {
                break;
            }
        }
        temp_metadata=metadata_gen(strnlen(text));
        e.ProcessData()//메타데이터 암호화
        // 6) 메타데이터에 메인데이터의 삽입사항 반영하여 업데이트
        meta_plain.insert(meta_plain.begin() + save, temp_metadata.begin(), temp_metadata.end());
    }
    else
    {
        // no) - 1) 삽입 인덱스 기준으로 뒷부분을 암호화하는데 사용된 카운터 추정(C3)
        int insert_block_index = search_block_index(meta_plain, index);
        int insert_block_ctr = search_counter_block(meta_plain, insert_block_index);

        byte C3[AES::BLOCKSIZE / 2];//추정카운터(latter_bundle이 암호화 되는데에 사용됬을것으로 보이는 카운터)
        byte C4[AES::BLOCKSIZE / 2];//삽입할 인덱스가 포함된 번들의 카운터
        byte C5[AES::BLOCKSIZE / 2];//삽입할 인덱스가 포함된 번들의 뒷번들의 카운터
        d.ProcessData(C4, (const byte*)(this->main_data.data() + head_ctr_index), AES::BLOCKSIZE/2);//해당번들의 첫블록에서 C4를 가져옴

        vector<byte> previous_bundle;//분화된 앞쪽번들
        vector<byte> latter_bundle;//분화된 뒷쪽번들

        int save = 0;
        int sum = 0;
        for(int i = 0; i < meta_plain.size(); i++)//뒷 블록의 카운터가 포함된 인덱스를 가져오는 과정
        {
            sum += meta_plain[i];//암호문에서의 위치
            if (meta_plain[i] == 0)
            {
                save = i;//삽입될 인덱스가 포함될 다음 bundle의  metadata의위치
            }
            if ((sum > real_index) && (meta_plain[i] == 0))
            {
                break;
            }
        }
        d.ProcessData(C5, (const byte*)(this->main_data.data() + sum), AES::BLOCKSIZE/2);//뒷블록 가져오는 중

        // no) - 2) 추정된 카운터(C3)를 이용하여 번들 분화(앞 번들과 뒷번들로 분화)
        previous_bundle.assign(this->main_data.begin() + insert_block_ctr, this->main_data.begin() + insert_block_index);
        latter_bundle.assign(this->main_data.begin() + insert_block_index, this->main_data.begin() + next_counter_index);
        int C3_int = search_index_counter(meta_plain, real_index, (int)C4);
        memcpy(C3, &C3_int, sizeof(C3_int));

        byte Counter[AES::BLOCKSIZE];
        memcpy(Counter, C3, 8);
        memcpy(Counter + 8, C5, 8);
        latter_bundle.insert(latter_bundle.begin(), Counter, Counter + 16);//뒷번들에 첫블록 삽입
        
        memcpy(&previous_bundle[8], C1, 8);

        // no) - 3) 마지막 카운터(C1)와 추정된 카운터(C3)를 사용하여 삽입 데이터 번들화
        temp_bundle = encryption(this->nonce, C1, text, this->key, C3);
        main_data.insert(main_data.begin() + real_index, temp_bundle.begin(), temp_bundle.end());
        int sum1=0;
        int sum2=0;
        int sum3=0;
        int save1=0;
        int save2=0;
        int t=0;
        int latter=0;
        //메타데이터를 써야함
        for(int i = 0; i < meta_plain.size(); i++)//뒷 블록의 카운터가 포함된 인덱스를 가져오는 과정
        {   
            sum1 += meta_plain[i];//암호문에서의 위치
            sum2 += meta_plain[i];
            if(t=!i){
                sum3 += meta_plain[i];
            }
            if (meta_plain[i] == 0)
            {
                save1 = i;//삽입될 인덱스가 포함될 다음 bundle의  metadata의위치
            }

            if ((sum > real_index))
            {   
                save2=i;
                break;
            }
            t++;
        }
        //번들 분화할때 인덱스가포함된 번들값-바로 전 metadata 합값
        byte need=sum3-sum1;
        byte need2=meta_plain[save2]-need;
        meta_plain[save2]=need;
        //그걸 해당 인덱스 값으로 바꾸고 그 뒷값부터 번들 끝까지 날려
        for(int i=save2+1;i<save;i++){
            latter += meta_plain[i];        }
        meta_plain.erase(meta_plain.begin() + save1, meta_plain.begin() + save);//save1부터 save까지 날려
        //삽입 번들은 그냥 메타젠으로 만들고
        vector<byte> new_matadata;
        vector<byte> latter_matadata;
        new_matadata=metadata_gen(strnlen(text));
        //번들의 첫번째 블록
        latter_matadata=metadata_gen(latter);
        //1번인덱스에다가 need2 삽입
        latter_matadata.insert(latter_matadata.begin()+1,need2);
        //이거를 인설트

        //이값을 meta 젠 len한담에 

    }

   

    
}

	void Replacement(string text, int index)
	{}

	void Defrag()
	{}


}

