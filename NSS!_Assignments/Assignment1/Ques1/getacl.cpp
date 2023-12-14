#include <iostream>
#include <unistd.h>
#include <string.h>
#include "header.h"

extern struct files file_array;
int main(int argc, char *argv[]){
	if (argc != 2){
		std::cout<<"Invalid Number of Arguments"<<std::endl;
		return 1;
	}
	file_array = deserialize();
	char *path = argv[1];
	char *repath = realpath(path, nullptr);
	if (repath == nullptr){
		perror("File Error Encountered");
		return 1;
	}
	for (int i = 0; i < file_array.array.size(); i++){
		if (strcmp(file_array.array[i] -> path, repath) == 0){
			for (int j = 0; j < file_array.array[i] -> acl_strings.size(); j++){
				std::cout<< file_array.array[i] -> acl_strings[j] << "\n";
			}
		}
	}
	return 0;
}
