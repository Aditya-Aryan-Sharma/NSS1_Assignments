#include <iostream>
#include <unistd.h>
#include <string>
#include <cstring>
#include <sys/wait.h>
#include <fstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <vector>
#include <iomanip>
#include <arpa/inet.h>
#include <netdb.h>
#include <chrono>
#include <thread>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>

struct EncryptedData {
    std::vector<unsigned char> iv;
    std::vector<unsigned char> ciphertext;
    std::vector<unsigned char> hmac;
};

std::vector<unsigned char> readRandomBytes(size_t numBytes){
    std::vector<unsigned char> data(numBytes);
    std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
    if (urandom){
        urandom.read(reinterpret_cast<char*>(data.data()), numBytes);
    }
    return data;
}

std::vector<unsigned char> encryptData(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data());
    int cLen = data.size() + AES_BLOCK_SIZE;
    std::vector<unsigned char> ciphertext(cLen, 0);
    int len;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, data.data(), data.size());
    cLen = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    cLen += len;
    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(cLen);
    return ciphertext;
}

std::vector<unsigned char> generateHMAC(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key) {
    unsigned int len;
    std::vector<unsigned char> hmac(EVP_MAX_MD_SIZE, 0);
    HMAC_CTX* ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key.data(), key.size(), EVP_sha256(), NULL);
    HMAC_Update(ctx, data.data(), data.size());
    HMAC_Final(ctx, hmac.data(), &len);
    HMAC_CTX_free(ctx);
    hmac.resize(len);
    return hmac;
}

std::vector<unsigned char> serializeEncryptedData(const EncryptedData& data) {
    std::vector<unsigned char> serializedData;
    serializedData.insert(serializedData.end(), data.iv.begin(), data.iv.end());
    serializedData.insert(serializedData.end(), data.ciphertext.begin(), data.ciphertext.end());
    serializedData.insert(serializedData.end(), data.hmac.begin(), data.hmac.end());
    return serializedData;
}

std::vector<unsigned char> readKey(){
    const std::string &filename = "random_data.bin";
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()){
        std::cerr << "Error opening the file." << std::endl;
        return std::vector<unsigned char>();
    }
    file.seekg(0, std::ios::end);
    std::streampos fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<unsigned char> buffer(fileSize);
    file.read(reinterpret_cast<char*>(buffer.data()), fileSize);
    file.close();
    return buffer;
}

EncryptedData encryptAndSign(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key) {
    std::vector<unsigned char> iv = readRandomBytes(AES_BLOCK_SIZE);
    std::vector<unsigned char> ciphertext = encryptData(plaintext, key, iv);
    std::vector<unsigned char> hmac = generateHMAC(plaintext, key);
    return { iv, ciphertext, hmac };
}

void func1(const char *file){
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0){
        std::cerr << "Error creating socket"<<std::endl;
        return;
    }
    struct sockaddr_in Addr;
    struct hostent *server = gethostbyname("127.0.0.1");
    Addr.sin_family = AF_INET;
    Addr.sin_port = htons(8080);
    bcopy((char *)server->h_addr_list[0], (char *)&Addr.sin_addr.s_addr, server->h_length);
    std::string filename(file);
    std::ifstream infile(filename);
    if (infile.is_open()){
        std::string content((std::istreambuf_iterator<char>(infile)), std::istreambuf_iterator<char>());
        std::vector<unsigned char> fileContent (content.begin(), content.end());
        std::vector<unsigned char> key = readKey();
        EncryptedData edata = encryptAndSign(fileContent, key);
        std::vector<unsigned char> endata = serializeEncryptedData(edata);
        if (connect(sock, (struct sockaddr *)&Addr, sizeof(Addr)) < 0) {
            std::cerr << "Connection failed\n";
            return;
        }
        std::cout<< "Sending Encrypted data along with HMAC and IV/Nonce to other Sibling\n";
        if (send(sock, endata.data(), endata.size(), 0) == -1){
            std::cerr << "Failed to send data over the socket"<< std::endl;
            close(sock);
            exit(EXIT_FAILURE);
        }
        infile.close();
    }
    else{
        std::cerr<< "Error Opening the file"<<std::endl;
        return;
    }
    close(sock);
}

void func2(){
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Error creating socket\n";
        return;
    }
    struct sockaddr_in servAddr;
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servAddr.sin_port = htons(8080);
    if (bind(sock, (struct sockaddr *)&servAddr, sizeof(servAddr)) < 0) {
        std::cerr << "Binding failed\n";
        return;
    }
    listen(sock, 1);
    int socket = accept(sock, NULL, NULL);
    if (socket < 0) {
        std::cerr << "Error accepting connection\n";
        return;
    }
    std::vector<unsigned char> receivedData(8192);
    int bytesReceived = recv(socket, receivedData.data(), receivedData.size(), 0);
    if (bytesReceived == -1) {
        std::cerr << "Failed to receive data over the socket\n";
        close(socket);
        exit(EXIT_FAILURE);
    }
    receivedData.resize(bytesReceived);
    std::string netcatCommand = "nc 127.0.0.9 8888";
    FILE *pipe = popen(netcatCommand.c_str(), "w");
    if (pipe){
        std::cout<< "Connection established with 127.0.0.9:8888\n";
        fwrite(receivedData.data(), sizeof(unsigned char), receivedData.size(), pipe);
        std::cout<< "Sending encrypted data to server.cpp\n"<<"Terminate this process using ctrl-C to break the connection with server and complete the execution of the program\n";
        fflush(pipe);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        pclose(pipe);
    }
    else{
        std::cerr << "Error opening the pipe to netcat." << std::endl;
    }
    close(socket);
}

int main(int argc, char *argv[]){
    if (argc != 2){
        std::cerr << "Invalid Number of arguments"<<std::endl;
        return 1;
    }
    pid_t pid1, pid2;
    pid1 = fork();
    if (pid1 < 0){
        std::cerr << "Failed to fork first child process"<<std::endl;
        return 1;
    }
    else if (pid1 == 0){
        func2();
        return 0;
    }
    pid2 = fork();
    if (pid2 < 0){
        std::cerr << "Failed to fork second child process\n"<<std::endl;
        return 1;
    }
    else if (pid2 == 0){
        func1(argv[1]);
        return 0;
    }
    wait(NULL);
    wait(NULL);
    return 0;
}