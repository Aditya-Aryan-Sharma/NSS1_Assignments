#include <iostream>
#include <fstream>
#include <sys/stat.h>
#include <cstdlib>
#include <unistd.h>
#include <string.h>
#include <vector>

int main(int argc, char *argv[]){
	if (argc < 2){
		std::cout<<"Incorrect Number of Arguments"<<std::endl;
		return 1;
	}
	char *function = argv[1];
	std::vector<const char *> allowed {"setacl", "getacl", "cd", "createdir", "fput", "fget"};
	int i = 0;
	while (i < allowed.size()){
		if (strcmp(function, allowed[i]) == 0){
			break;
		}
		i++;
	}
	if (i == allowed.size()){
		std::cout<<"Cannot execute random executables"<<std::endl;
		return 1;
	}
	uid_t curr = getuid();
	if (setuid(0) != 0){
		perror("Setuid error: ");
		return 1;
	}
	std::ifstream file("pass.txt");
    if (!file.is_open()){
        std::cerr << "Error opening pass.txt" << std::endl;
        return 1;
    }
    std::string storedPass;
    std::getline(file, storedPass);
    file.close(); 
    if (setuid(curr) != 0){
	perror("Setuid Error: ");
	return 1;
    }
    std::string userInput;
    std::cout << "Enter passphrase: ";
    std::cin >> userInput;
    	if (strcmp(userInput.c_str(), storedPass.c_str()) != 0){
		std::cout<<"Authentication Denied"<<std::endl;
		return 1;
	}
	struct stat fileStat;
	uid_t curr_owner = 0;
	uid_t fileowner;
	if (stat(function, &fileStat) == 0){
		fileowner = fileStat.st_uid;
	}
	if (curr_owner != fileowner){
		if (setuid(fileowner) != 0){
			perror("Setuid error: ");
			return 1;
		}
		std::cout<<"Switched to UID = "<<getuid()<<std::endl;
	}
	std::string command = std::string("./") + std::string(function);
	for (int j = 2; j < argc; j++){
		command += std::string(" ") + std::string(argv[j]);
	}
	const char *run = command.c_str();
	if (std::system(run) == 0){
		std::cout<<"Ran the "<<function<<"program with UID = "<<getuid()<<std::endl;
	}
	return 0;
}
