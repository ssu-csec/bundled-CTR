#ifndef CRYPTO_H
#define CRYPTO_H

#include <vector>
#include <string>
#include <cryptopp/aes.h>

using namespace std;
using namespace CryptoPP;

class Modi_info
{
	private:
		vector<byte> new_meta;
		vector<byte> ins_list;
		vector<byte> rep_list;

	public:
		int del_index;
		int del_len;
		int ins_index;
		int rep_index;

		Modi_info();

		void update_del_data(int len);

		void update_ins_data(int index, vector<byte> list);

		void update_ins_data(int index, byte* block);

		void update_ins_data(int index, byte one);

		void update_rep_data(int index, byte* block);

		void update_metadata(vector<byte> metadata);

};

vector<byte> metadata_gen(int len);

vector<byte> metadata_enc(vector<byte> metadata, byte* counter, byte* key, byte* nonce);

vector<byte> metadata_dec(vector<byte> meta_cipher, byte* key, byte* nonce, byte* rec_ctr);

vector<byte> encryption(byte* nonce, byte* counter, string plaintext, byte* key, byte* back_counter);

vector<byte> decryption(byte* nonce, vector<byte> bundle, byte* key, vector<byte> metadata);

int search_block_index(vector<byte> metadata, int index);

int search_real_index(vector<byte> metadata, int index);

int search_counter_block(vector<byte> metadata, int index);

byte* find_ctr(byte* counter, int num);

class bundled_CTR
{
	private:
		vector<byte> main_data;
		vector<byte> meta_data;
		byte key[AES::BLOCKSIZE];
		byte nonce[AES::BLOCKSIZE/2];

	public:

		bundled_CTR(byte* key, byte* nonce);

		bundled_CTR(vector<byte> data, vector<byte> meta, byte* key, byte* nonce);

		~bundled_CTR();
		
		vector<byte> print_data();

		vector<byte> print_meta();

		Modi_info Insertion(string text, int index);

		Modi_info Deletion(int del_len, int index);

		Modi_info Replacement(string text, int index);
		
		void Defrag();
};



#endif
