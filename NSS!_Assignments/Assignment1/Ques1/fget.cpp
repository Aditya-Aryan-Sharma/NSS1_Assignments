#include <unistd.h>
#include "header.h"
#include <sys/types.h>
#include <pwd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <iostream>
#include <string.h>

extern struct files file_array;

int main(int argc, char* argv[]){
	if (argc != 2){
		std::cout<<"Invalid Number of Arguments"<<std::endl;
		return 1;
	}
	file_array = deserialize();
	char *path = argv[1];
	uid_t uid = getuid();
	char *repath = realpath(path, nullptr);
	if (repath == nullptr){
		perror("File Error Encountered");
		return 1;
	}
	uid_t root = getUserId("fakeroot");
	bool found = true;
	char * curr_user = getUser(getuid());
	for (int i = 0; i < file_array.array.size(); i++){
		bool permitted = false;
		if (strcmp(file_array.array[i] -> path, repath) == 0){
			for (int j = 0; j < file_array.array[i] -> acl_strings.size(); j++){
				const char* acl_user = extractUse(file_array.array[i] -> acl_strings[j]);
				if (strcmp(curr_user,  acl_user) == 0){
					int size = file_array.array[i]->acl_strings[j].size();
					const std::string& permissionPart = file_array.array[i]->acl_strings[j].substr(size - 3);
					for (char c : permissionPart){
						if (c == 'r'){
							permitted = true;
							break;
						}
					}
				}
			}
		}
		if (permitted){
			break;
		}
		if (i == file_array.array.size() - 1){
			found = false;
		}
	}
	if (!found && getUserId(curr_user) != root){
		std::cout<< "You do not have necessary permissions\n";
		return 1;
	}
	if (seteuid(root) == -1){
		perror("Seteuid Error");
		return 1;
	}
	for (int i = 0; i < file_array.array.size(); i++){
		if (strcmp(file_array.array[i] -> path, repath) == 0){
			std::cout<<file_array.array[i] -> data;
		}
	}
	return 0;
}

