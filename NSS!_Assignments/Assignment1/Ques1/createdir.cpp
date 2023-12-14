#include <iostream>
#include <sys/stat.h>
#include "header.h"

int main(int argc, char *argv[]){
	if (argc != 2){
		std::cout<<"Invalid Number of Arguments"<<std::endl;
		return 1;
	}
	const char *Name = argv[1];
	int status = mkdir(Name, S_IRWXU);
	if (status == 0){
        	std::cout << "Directory created successfully: " << Name  << std::endl;
    	}
	else{
	       	std::cerr << "Failed to create directory: " << Name << std::endl;
    	}
	return 0;
}
