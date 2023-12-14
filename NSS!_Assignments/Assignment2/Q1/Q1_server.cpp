#include <iostream>
#include <unistd.h>
#include <string>
#include <cstring>
#include <vector>
#include <sys/wait.h>
#include <fstream>
#include <cstdlib>
#include <sstream>
#include <netdb.h>
#include <chrono>
#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>

struct EncryptedData {
    std::vector<unsigned char> iv;
    std::vector<unsigned char> ciphertext;
    std::vector<unsigned char> hmac;
};

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

EncryptedData deserializeEncryptedData(const std::vector<unsigned char>& serializedData){
    EncryptedData data;
    size_t ivLength = AES_BLOCK_SIZE;
    size_t ciphertextLength = data.ciphertext.size();
    size_t hmacLength = ivLength * 2;
    data.iv.assign(serializedData.begin(), serializedData.begin() + ivLength);
    data.ciphertext.assign(serializedData.begin() + ivLength, serializedData.end() - hmacLength);
    data.hmac.assign(serializedData.end() - hmacLength, serializedData.end());
    return data;
}

std::vector<unsigned char> decryptData(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data());
    int pLen = data.size();
    std::vector<unsigned char> plaintext(pLen, 0);
    int len;
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, data.data(), data.size());
    pLen = len;
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    pLen += len;
    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(pLen);
    return plaintext;
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

bool validateHMAC(const std::vector<unsigned char>& key, const std::vector<unsigned char>& hmac, const std::vector<unsigned char>& plaintext){
    std::vector<unsigned char> newHmac = generateHMAC(plaintext, key);
    if (hmac.size() != newHmac.size())
        return false;
    for (int i = 0; i < hmac.size(); i++){
        if (hmac[i] != newHmac[i]){
            return false;
        }
    }
    return true;
}

void func1(){  //Reads and Sends it to the other process
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0){
        std::cerr << "Error creating socket"<< std::endl;
        return;
    }
    struct sockaddr_in Addr;
    struct hostent *server = gethostbyname("127.0.0.5");
    Addr.sin_family = AF_INET;
    Addr.sin_port = htons(8080);
    bcopy((char *)server->h_addr_list[0], (char *)&Addr.sin_addr.s_addr, server->h_length);
    const std::string& port = "8888";
    const std::string& IP = "127.0.0.9";
    std::string netcatCommand = "netcat -l -p " + port + " -s " + IP;
    std::vector<unsigned char> receivedData(8192);
    FILE* pipe = popen(netcatCommand.c_str(), "r");
    if (pipe){
        size_t bytesRead = fread(receivedData.data(), sizeof(unsigned char), receivedData.size(), pipe);
        receivedData.resize(bytesRead);
        fflush(pipe);
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        pclose(pipe);
    }
    else{
        std::cerr << "Error opening pipe to netcat." << std::endl;
    }
    if (connect(sock, (struct sockaddr *)&Addr, sizeof(Addr)) < 0) {
        std::cerr << "Connection failed"<< std::endl;
        return;
    }
    if (send(sock, receivedData.data(), receivedData.size(), 0) == -1){
        std::cerr << "Failed to send data over the socket"<< std::endl;
        close(sock);
        exit(EXIT_FAILURE);
    }
}

void func2(){   //Reads and Validates the HMAC and store in the file
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Error creating socket\n";
        return;
    }
    struct sockaddr_in servAddr;
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = inet_addr("127.0.0.5");
    servAddr.sin_port = htons(8080);
    if (bind(sock, (struct sockaddr *)&servAddr, sizeof(servAddr)) < 0) {
        std::cerr << "Binding failed"<< std::endl;
        return;
    }
    listen(sock, 1);
    int socket = accept(sock, NULL, NULL);
    if (socket < 0) {
        std::cerr << "Error accepting connection"<< std::endl;
        return;
    }
    std::vector<unsigned char> receivedData(8192);
    int bytesReceived = recv(socket, receivedData.data(), receivedData.size(), 0);
    if (bytesReceived == -1) {
        std::cerr << "Failed to receive data over the socket"<< std::endl;
        close(socket);
        exit(EXIT_FAILURE);
    }
    receivedData.resize(bytesReceived);
    std::vector<unsigned char> key = readKey();
    EncryptedData data = deserializeEncryptedData(receivedData);
    std::vector<unsigned char> decryptedData = decryptData(data.ciphertext, key, data.iv);
    if (!validateHMAC(key, data.hmac, decryptedData)){
        std::cout<< "HMAC not valid. Aborting without writing to the file"<<std::endl;
        return;
    }
    else{
        std::cout<< "Encryption Verified\n";
    }
    const std::string &filename = "out.txt";
    std::ofstream outputFile(filename, std::ios::out);
    if (outputFile.is_open()){
        for (const auto &byte : decryptedData){
            outputFile<< byte;
        }
        outputFile.close();
        std::cout<< "Data written to file out.txt successfully." << std::endl;
    }
    else{
        std::cerr<< "Error opening the file for writing." << std::endl;
    }
}

int main(){
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
        func1();
        return 0;
    }
    wait(NULL);
    wait(NULL);
    return 0;
}