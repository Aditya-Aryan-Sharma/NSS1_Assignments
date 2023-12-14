#include <unistd.h>
#include "header.h"
#include <sys/types.h>
#include <pwd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <iostream>
#include <fstream>
#include <string.h>
#include <vector>

struct files file_array;

uid_t getUserId(const char *username){
	struct passwd* pw;
	pw = getpwnam(username);
	if (pw != nullptr){
		return pw -> pw_uid;
	}
	return 108;
}

char *getUser(uid_t uid){
	struct passwd *pwd = getpwuid(uid);
	if (pwd != nullptr){
		return pwd -> pw_name;
	}
	return nullptr;
}

const char* extractUse(std::string acl){
	int i = acl.size() - 5;
	std::string username = "";
	while (acl[i] != ':'){
		username = acl[i] + username;
		i--;
	}
	return username.c_str();
}

void serialize(){
	const std::string &filename = "ser.txt";
	std::ofstream file(filename);
	if (!file) {
		std::cerr << "Error opening file for writing: " << filename << std::endl;
		return;
	}
	for (const auto& fileData : file_array.array){
       		file << fileData -> acl_len << "\n";
        	for (const std::string& acl : fileData -> acl_strings) {
            		file << acl << "\n";
        	}
        	file << fileData -> data_len << "\n";
        	file << fileData -> data << "\n";
        	file << fileData -> path << "\n";
        	file << fileData -> owner << "\n";
    	}
    	file.close();
}

files deserialize(){
	struct files file_array;
	const std::string &filename = "ser.txt";
	std::ifstream file(filename);
	if (!file) {
        	std::cerr << "Error opening file for reading: " << filename << std::endl;
        	return file_array;
    	}
	std::string line;
	while (std::getline(file, line)){
		struct file_data *data = new file_data;
		data -> acl_len = std::stoi(line);
		for (int i = 0; i < data -> acl_len; i++){
			std::getline(file, line);
			data -> acl_strings.push_back(line);
		}
		std::getline(file, line);
		data -> data_len = std::stoi(line);
		std::getline(file, line);
		data -> data = strdup(line.c_str());
		std::getline(file, line);
		data -> path = strdup(line.c_str());
		std::getline(file, line);
		char *endptr;
		long uidLong = std::strtol(line.c_str(), &endptr, 10);
		data -> owner = static_cast<uid_t>(uidLong);
		file_array.array.push_back(data);
	}
	file.close();
	return file_array;
}
