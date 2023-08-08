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
## Functions

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
