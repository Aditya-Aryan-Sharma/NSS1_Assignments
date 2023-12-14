#include <iostream>
#include <unistd.h>
#include <stdlib.h>
#include "header.h"
#include <fcntl.h>
#include <string.h>
#include <dirent.h>

extern struct files file_array;
std::string extractUser(std::string path){
	int i = path.size() - 2;
	while (path[i] != '/'){
		i--;
	}
	i--;
	std::string user = "";
	while (path[i] != '/'){
		user = path[i] + user;
		i--;
	}
	return user;
}

int main(){
	std::vector<const char *> dir {"bill/", "david/", "joe/", "kane/", "steve/", "travis/"};
	std::vector<char *> paths;
	for (int i = 0; i < dir.size(); i++){
		DIR *directory;
    		struct dirent *entry;
		directory = opendir(dir[i]);
		if (directory == nullptr){
			perror("opendir():");
			return 1;
		}
		while ((entry = readdir(directory)) != nullptr){
			if (strcmp(entry -> d_name, ".") == 0 || strcmp(entry -> d_name, "..") == 0) {
            		continue;
        	}
			char *file = new char[strlen(dir[i]) + strlen(entry -> d_name)];
        		strcpy(file, dir[i]);
			strcat(file, strdup(entry -> d_name));
			paths.push_back(file);
    		}
   		closedir(directory);
	}
	for (int i = 0; i < paths.size(); i++){
		char *path = realpath(paths[i], nullptr);
		if (path == nullptr){
			perror("File Error Encountered");
			continue;
		}
		paths[i] = path;
	}
	for (int i = 0; i < paths.size(); i++){
		struct file_data *file = new file_data;
		file -> acl_len = 1;
		(file -> acl_strings).push_back("user:" + extractUser(paths[i]) + ":rwx");
		file -> path = paths[i];
		file -> owner = getUserId(extractUser(paths[i]).c_str());
		char str[1024] = "";
		file -> data = str;
		file -> data_len = 0;
		(file_array.array).push_back(file);
	}
	serialize();
	return 0;
}
