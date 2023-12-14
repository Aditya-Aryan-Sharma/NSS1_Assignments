#include <unistd.h>
#include "header.h"
#include <sys/types.h>
#include <pwd.h>
#include <iostream>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

extern struct files file_array;

int main(int argc, char* argv[]){
	if (argc != 3){
		std::cout<<"Invalid Number of Arguments"<<std::endl;
		return 1;
	}
	file_array = deserialize();
	char *path = argv[1];
	char *entry = argv[2];
	uid_t uid = getuid();
	char *repath = realpath(path, nullptr);
	if (repath == nullptr){
		perror("File Error Encountered");
		return 1;
	}
	uid_t own;
	uid_t root = getUserId("fakeroot");
	for (int i = 0; i < file_array.array.size(); i++){
		if (strcmp(file_array.array[i] -> path, repath) == 0){
			own = file_array.array[i] -> owner;
			if (uid != root && uid != own){
				std::cout<< "Permission Denied for UID = " << uid<< "\n";
				return 1;
			}
		}
	}
	if (seteuid(root) == -1){
		perror("Seteuid Error");
		return 1;
	}
	bool ans = false;
	std::string user (entry);
	std::string curr_user = extractUse(user);
	for (int i = 0; i < file_array.array.size(); i++){
		if (strcmp(file_array.array[i] -> path, repath) == 0){
			for (int j = 1; j < file_array.array[i] -> acl_strings.size(); j++){
				std::string acl_user = extractUse(file_array.array[i] -> acl_strings[j]);
				if (curr_user.compare(acl_user) == 0){
					ans = true;
					file_array.array[i] -> acl_strings[j] = user;
				}
			}
			if (!ans){
				file_array.array[i] -> acl_strings.push_back(user);
				file_array.array[i] -> acl_len += 1;
			}
			break;
		}
	}
	serialize();
	std::cout<<"Modified permissions successfully\n";
	return 0;
}
