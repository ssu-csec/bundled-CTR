#include <string>
#include <fstream>
#include <iostream>

using namespace std;

int main()
{
	string f_name = "";

	string twoMBContent;

	ifstream inputFile("gen.txt");

	if (inputFile.is_open()) {

		inputFile.seekg(0, ios::end);
		streampos fileSize = inputFile.tellg();
		inputFile.seekg(0, ios::beg);

		twoMBContent.resize(fileSize);
		inputFile.read(&twoMBContent[0], fileSize);

		inputFile.close();
	}
	else {
		std::cerr << "Cannot generate file " << f_name <<endl;
		return 1;  
	}

	for(int i = 1; i < 40; i++)
	{
		int size = i*10240;
		f_name = to_string(size);
		f_name += ".txt";

		std::ofstream outputFile(f_name);

		if (outputFile.is_open()) {
			outputFile << twoMBContent.substr(0, size - 1) << endl;

			outputFile.close(); 
		} 
		else {
			std::cerr << "Cannot generate file " << f_name << endl;
			return 1; 
		}
	}

	return 0;
}
