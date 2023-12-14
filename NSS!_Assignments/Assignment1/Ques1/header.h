#ifndef HEADER_H
#define HEADER_H
#include <vector>
#include <string>

struct file_data{
	int acl_len;
	std::vector<std::string> acl_strings;
	int data_len;
	char *data;
	char *path;
	uid_t owner;
};

struct files{
	std::vector<file_data *> array;
};

extern struct files file_array;

uid_t getUserId(const char *);
const char* extractUse(std::string);
char* getUser(uid_t);
void serialize();
files deserialize();


#endif
