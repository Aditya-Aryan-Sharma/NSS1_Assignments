#include <iostream>
#include <unistd.h>
#include "header.h"

int main(int argc, char *argv[]){
	if (argc != 2){
		std::cout<<"Invalid Number of Arguments"<<std::endl;
	}
	char *newDirectory = argv[1];
	if (chdir(newDirectory) == 0){
 		std::cout << "Changed directory to: " << newDirectory << std::endl;
    	}
	else{
        	std::cerr << "Failed to change directory." << std::endl;
    	}
	return 0;
}
