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

