#include <unistd.h>
#include "header.h"
#include <sys/types.h>
#include <pwd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <iostream>
#include <string.h>
#include <fstream>

extern struct files file_array;

int main(int argc, char *argv[]){
	if (argc != 3){
		std::cout<<"Invalid Number of Arguments"<<std::endl;
		return 1;
	}
	file_array = deserialize();
	char *path = argv[1];
	char *buffer = argv[2];
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
					int size = file_array.array[i]-> acl_strings[j].size();
					const std::string& permissionPart = file_array.array[i] -> acl_strings[j].substr(size - 3);
					for (char c : permissionPart){
						if (c == 'w'){
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
	char buff[2048];
	for (int i = 0; i < file_array.array.size(); i++){
		if (strcmp(file_array.array[i] -> path, repath) == 0){
			strcpy(buff, file_array.array[i] -> data);
			strcat(buff, buffer);
			file_array.array[i] -> data = buff;
			file_array.array[i] -> data_len = (int)strlen(buff);
		}
	}
	int fd = open(repath, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | O_APPEND);
    	if (fd == -1) {
        	std::cerr << "Failed to open the file for writing.\n";
        	return 1;
    	}
   	ssize_t bytesWritten = write(fd, buffer, strlen(buffer));
    	if (bytesWritten == -1) {
      	  	std::cerr << "Failed to write data to the file.\n";
        	close(fd);
        	return 1;
    	}
	serialize();
	close(fd);
	return 0;
}
