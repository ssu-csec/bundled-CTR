# bundled-CTR

## Getting Started

### Implement Environment

```
Ubuntu 20.04
```

### Prerequisites

We use ```crypto++``` library.
You can install the library by following below:

```
wget https://github.com/weidai11/cryptopp/archive/refs/tags/CRYPTOPP_8_8_0.zip
unzip CRYPTOPP_8_8_0.zip
cd ./cryptopp-CRYPTOPP_8_8_0
make
make test
sudo make install
```
And you can use the library when you compile your code:

```
g++ <Your Source Code *.cpp> -Lcryptopp -lcryptopp
```
## Function

### Metadata

```C++
	vector<byte> metadata_gen(int len)
	vector<byte> metadata_enc(vector<byte> metadata, byte* counter, byte* key, byte* nonce)
```
For generating metadata, you only need the length of plaintext.

For encrypting metadata, you need metadata generated with ```metadata_gen``` function, 8-byte-sized counter value, 16-byte-sized encryption key and 8-byte-sized nonce value. To elaborate, the counter has the most recently used counter value, the key and the nonce are also used when you encrypt main data. When encrypting, you can make initial value with nonce and 8-byte-size array initialized to 0x00.

### Encryption/Decryption

```C++
	vector<byte> encryption(byte* nonce, byte* counter, string plaintext, byte* key)
	vector<byte> decryption(byte* nonce, vector<byte> bundle, byte* key, vector<byte> metadata)
```

For encryption data, you need 8-byte-size nonce, 8-byte-size counter, plaintext and 16-byte-sized key. Similarly, nonce, key are used when decrypting ciphertext bundles. ONe different thing is metadata in encrypted form.  
### Index Search

```C++
	int search_block_index(vector<byte> metadata, int index);
	int search_real_index(vector<byte> metadata, int index);
	int search_counter_block(vector<byte> metadata, int index);
```

These functions are used when you have the index of plaintext and want to find the index at the ciphertext.
The first input of these functions is metadata wirh decrypted form.

## Class

### bundled-CTR
```C++
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

			int Fragcheck(vector<int> bundle_list, int range, int num);

			void Defrag();
	};
```
#### How to use the class

Download and save ```crypto.cpp``` and ```crypto.h``` to the folder where you intend to proceed with your project.
And add
```C++
#include "crypto.h"
```
in the code file.
When you compile your code,
```
g++ <Your Source Code *.cpp> -lcryptopp
```
will work.

In your code, you can declare your class like below.
```C++
bundled_CTR b(key, nonce);
```
Also, you can first create your ciphertext with ```Insertion``` function.
```
b.Insert(plaintext, 0);
```
```plaintext``` is your input data and ```0``` is the first index.

After that, you can use all modification functions in the class.
```C++
b.Insert(text, index);
b.Delete(length, index);
b.Replacement(text, index);
```
If you want to print your ciphertext, you can use ```print_data``` function in the class.

```C++
b.print_data();
```
