#include <iostream>
#include <vector>
#include <fstream>
#include <sstream>
#include <string>
#include <chrono>
#include "exist_mode.h"

int main()
{
	srand(time(NULL));
	byte nonce[AES::BLOCKSIZE/2];
	for (int i = 0; i < AES::BLOCKSIZE/2; i++)
	{   
		nonce[i] = (byte)rand()%256;
	}   

	byte counter[AES::BLOCKSIZE/2] = {0x00, };
	byte key[AES::DEFAULT_KEYLENGTH] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
	//bundled_CTR Mode(key, nonce);

	string fileContent;

	string new_data;

	int num = 0;
	cout << "What size (*10): ";
	cin >> num;

	int size = (num)*10;
	CTR Mode(key, nonce);

	ifstream inputFile("204800.txt");

	if (inputFile.is_open()) {

		inputFile.seekg(0, ios::end);
		streampos fileSize = inputFile.tellg();
		inputFile.seekg(0, ios::beg);

		fileContent.resize(fileSize);
		inputFile.read(&fileContent[0], fileSize);

		inputFile.close(); 
	}
	else {
		cerr << "Cannot open file" << endl;
		return 1;  
	}
	new_data = fileContent.substr(0, size);
	ofstream timeStamp("Del_" + to_string(size) + "_CTR.txt", ios::app);
	if(timeStamp.is_open())
	{
		Mode.Insertion(fileContent, 0);

		auto start_time = chrono::high_resolution_clock::now();
		auto end_time = chrono::high_resolution_clock::now();
		int i = rand()%256;
		if(i%3 == 0)
		{   
			start_time = chrono::high_resolution_clock::now();
			Mode.Insertion(new_data, 102400);
			end_time = chrono::high_resolution_clock::now();
		}
		else if(i%3 == 1)
		{
			start_time = chrono::high_resolution_clock::now();
			Mode.Deletion(size, 102400);
			end_time = chrono::high_resolution_clock::now();
			/
			else if(i%3 == 2)
			{
				start_time = chrono::high_resolution_clock::now();
				Mode.Replacement(new_data, 102400);
				end_time = chrono::high_resolution_clock::now();
			}
			auto duration = chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
			timeStamp << duration.count() <<endl;
			timeStamp.close();
			//vector<byte> re_plain = decryption(nonce, Mode.print_data(), key, Mode.print_meta());

			/*cout << "Data size: " << size << " Decrypted data: ";
			  for(auto loop: re_plain)
			  {
			  cout << loop;
			  }
			  cout << endl;*/

		}
		else {
			cerr << "Cannot open file" << endl;
			return 1;
		}


		return 0;
	}
