#include <iostream>
#include <fstream>
#include <thread>
#include <vector>
#include <unistd.h>
#include <cstring>
#include <chrono>
#include <string>
#include <mutex>
#include <random>
#include <sstream>
#include <algorithm>
#include <unistd.h>
#include <sys/socket.h>
#include <pwd.h>
#include <utility>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define P 65535
#define G 67

struct encryptedData{
    std::vector<unsigned char> iv;
    std::vector<unsigned char> data;
};

struct group{
    int groupId;
    std::vector<unsigned char> key;
};

struct receivedKeys{
    uid_t userId;
    RSA *rsa;
};

std::vector<receivedKeys> userKeys;
BIGNUM *pub_key;
BIGNUM *pri_key;
std::vector<int> pendingInvitation(1024);
std::vector<group> groups(1024);
std::mutex groupMutex;
std::mutex keyMutex;
std::mutex activeGroupsMutex;

int generateRandomInteger(int min, int max) {
    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<int> distribution(min, max);

    return distribution(mt);
}

std::vector<unsigned char> encrypt(RSA* publicKey, const std::vector<unsigned char>& plaintext) {
    int rsaSize = RSA_size(publicKey);
    std::vector<unsigned char> ciphertext(rsaSize);
    int encryptedSize = RSA_public_encrypt(static_cast<int>(plaintext.size()), plaintext.data(), ciphertext.data(), publicKey, RSA_PKCS1_PADDING);
    if (encryptedSize == -1) {
        std::cerr << "Error encrypting data" << std::endl;
        exit(EXIT_FAILURE);
    }
    ciphertext.resize(encryptedSize);
    return ciphertext;
}

std::vector<unsigned char> decrypt(RSA* privateKey, const std::vector<unsigned char>& ciphertext) {
    int rsaSize = RSA_size(privateKey);
    std::vector<unsigned char> plaintext(rsaSize);
    int decryptedSize = RSA_private_decrypt(static_cast<int>(ciphertext.size()), ciphertext.data(), plaintext.data(), privateKey, RSA_PKCS1_PADDING);
    if (decryptedSize == -1) {
        std::cerr << "Error decrypting data" << std::endl;
        exit(1);
    }
    plaintext.resize(decryptedSize);
    return plaintext;
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

int bytesToInt(const std::vector<unsigned char> &byteVector) {
    if (byteVector.size() < sizeof(int)) {
        return 0;
    }
    int result = 0;
    for (size_t i = 0; i < sizeof(int); ++i) {
        result |= static_cast<int>(byteVector[i]) << (i * 8);
    }
    return result;
}

std::vector<unsigned char> intToBytes(int value) {
    std::vector<unsigned char> result(sizeof(int));
    for (size_t i = 0; i < sizeof(int); ++i) {
        result[i] = (value >> (i * 8)) & 0xFF;
    }
    return result;
}

std::vector<unsigned char> bignumToBytes(const BIGNUM *bn) {
    int size = BN_num_bytes(bn);
    std::vector<unsigned char> result(size);
    BN_bn2bin(bn, result.data());
    return result;
}

std::vector<unsigned char> serializeEncryptedData(const encryptedData &data){
    std::vector<unsigned char> serializedData;
    serializedData.insert(serializedData.end(), data.iv.begin(), data.iv.end());
    serializedData.insert(serializedData.end(), data.data.begin(), data.data.end());
    return serializedData;
}

encryptedData deserializeEncryptedData(std::vector<unsigned char>& data){
    encryptedData enData;
    size_t ivLength = AES_BLOCK_SIZE;
    enData.iv.assign(data.begin(), data.begin() + ivLength);
    enData.data.assign(data.begin() + ivLength, data.end());
    return enData;
}

std::vector<unsigned char> readKey(std::string user){
    const std::string &filename =  user + ".bin";
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

std::vector<unsigned char> readRandomBytes(size_t numBytes){
    std::vector<unsigned char> data(numBytes);
    std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
    if (urandom){
        urandom.read(reinterpret_cast<char*>(data.data()), numBytes);
    }
    return data;
}

std::string readPublicKey(const char* filename) {
    std::ifstream publicKeyFile(filename);
    if (!publicKeyFile.is_open()) {
        std::cerr << "Error opening public key file" << std::endl;
        exit(1);
    }
    std::stringstream buffer;
    buffer << publicKeyFile.rdbuf();
    std::string publicKeyString = buffer.str();
    return publicKeyString;
}

RSA* loadPublicKey(const std::string& publicKeyString) {
    std::cout << publicKeyString << std::endl;
    const BIO_METHOD* method = BIO_s_mem();
    BIO* bio = BIO_new(method);
    if (!bio) {
        std::cerr << "Error creating BIO" << std::endl;
        exit(1);
    }
    if (BIO_puts(bio, publicKeyString.c_str()) <= 0) {
        std::cerr << "Error writing to BIO" << std::endl;
        BIO_free(bio);
        exit(1);
    }
    RSA* publicKey = PEM_read_bio_RSAPublicKey(bio, nullptr, nullptr, nullptr);
    if (!publicKey) {
        std::cerr << "Error reading public key" << std::endl;
        BIO_free(bio);
        exit(1);
    }
    BIO_free(bio);
    return publicKey;
}

RSA* loadPrivateKey(const std::string& privateKeyString) {
    BIO* bio = BIO_new_mem_buf(privateKeyString.c_str(), -1);
    if (!bio) {
        std::cerr << "Error creating BIO" << std::endl;
        exit(1);
    }
    RSA* privateKey = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
    if (!privateKey) {
        std::cerr << "Error reading private key" << std::endl;
        exit(1);
    }
    BIO_free(bio);
    return privateKey;
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

std::pair<BIGNUM *, BIGNUM *> generateDHKeys(){
    pub_key = BN_new();
    BIGNUM *p = BN_new();
    BIGNUM *g = BN_new();
    BIGNUM *a = BN_new();
    int random = generateRandomInteger(1, P - 1);
    BN_dec2bn(&p, std::to_string(P).c_str());
    BN_dec2bn(&g, std::to_string(G).c_str());
    BN_dec2bn(&a, std::to_string(random).c_str());
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating BN_CTX" << std::endl;
        exit(1);
    }
    BN_mod_exp(pub_key, g, a, p, ctx);
    pri_key = a;
    BN_CTX_free(ctx);
    std::make_pair(pub_key, a);
}

void intiateKeyExchange(uid_t userId, int socket){
    std::vector<unsigned char> array = bignumToBytes(pub_key);
    RSA *rsa;
    keyMutex.lock();
    for (int i = 0; i < userKeys.size(); i++){
        if (userKeys[i].userId == userId){
            rsa = userKeys[i].rsa;
            break;
        }
    }
    keyMutex.unlock();
    std::vector<unsigned char> data = encrypt(rsa, array);
    send(socket, data.data(), data.size(), 0);
}

void dhExchange(int socket, std::vector<unsigned char> enData, int groupId){
    char *username;
    struct passwd *pwd = getpwuid(getuid());
    if (pwd != NULL){
        username = pwd ->pw_name;
    }
    std::string privateKey = readPublicKey((std::string(username) + "_private_key.pem").c_str());
    RSA *rsa = loadPrivateKey(privateKey);
    std::vector<unsigned char> plaintext = decrypt(rsa, enData);
    BIGNUM *gU1 = BN_bin2bn(plaintext.data(), plaintext.size(), nullptr);
    BIGNUM *p = BN_new();
    BN_dec2bn(&p, std::to_string(P).c_str());
    BIGNUM *shared_secret = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating BN_CTX" << std::endl;
        exit(1);
    }
    BN_mod_exp(shared_secret, gU1, pri_key, p, ctx);
    BN_CTX_free(ctx);
    std::vector<unsigned char> publicKey = bignumToBytes(pub_key);
    std::vector<unsigned char> hmac = generateHMAC(bignumToBytes(shared_secret), plaintext);
    hmac.insert(hmac.end(), publicKey.begin(), publicKey.end());
    send(socket, hmac.data(), hmac.size(), 0);
    activeGroupsMutex.lock();
    for (int i = 0; i < groups.size(); i++){
        if (groups[i].groupId == groupId){
            groups[i].key = bignumToBytes(shared_secret);
            break;
        }
    }
    activeGroupsMutex.unlock();
}

void sendKey(int socket, uid_t userId, int groupId){
    std::vector<unsigned char> key;
    activeGroupsMutex.lock();
    for (int i = 0; i < groups.size(); i++){
        if (groups[i].groupId == groupId){
            key = groups[i].key;
            break;
        }
    }
    activeGroupsMutex.unlock();
    RSA *rsa;
    keyMutex.lock();
    for (int i = 0; i < userKeys.size(); i++){
        if (userKeys[i].userId == userId){
            rsa = userKeys[i].rsa;
            break;
        }
    }
    keyMutex.unlock();
    std::vector<unsigned char> data = encrypt(rsa, key);
    send(socket, data.data(), data.size(), 0);
}

void receiveKey(int socket, int groupId){
    std::vector<unsigned char> enData(8192);
    int bytes = recv(socket, enData.data(), enData.size(), 0);
    if (bytes == -1){
        std::cerr<< "Error receiving data"<<std::endl;
        return;
    }
    enData.resize(bytes);
    char *username;
    struct passwd *pwd = getpwuid(getuid());
    if (pwd != NULL){
        username = pwd ->pw_name;
    }
    std::string privateKey = readPublicKey((std::string(username) + "_private_key.pem").c_str());
    RSA *rsa = loadPrivateKey(privateKey);
    std::vector<unsigned char> plaintext = decrypt(rsa, enData);
    BIGNUM *gU1 = BN_bin2bn(plaintext.data(), plaintext.size(), nullptr);
    BIGNUM *p = BN_new();
    BN_dec2bn(&p, std::to_string(P).c_str());
    BIGNUM *shared_secret = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating BN_CTX" << std::endl;
        exit(1);
    }
    BN_mod_exp(shared_secret, gU1, pri_key, p, ctx);
    BN_CTX_free(ctx);
    activeGroupsMutex.lock();
    for (int i = 0; i < groups.size(); i++){
        if (groups[i].groupId == groupId){
            groups[i].key = bignumToBytes(shared_secret);
            break;
        }
    }
    activeGroupsMutex.unlock();
}

void compute_shared_secret(int socket, int groupId){
    std::vector<unsigned char> ticket(8192);
    int bytes = recv(socket, ticket.data(), ticket.size(), 0);
    if (bytes == -1){
        std::cerr<< "Error receiving data"<<std::endl;
        return;
    }
    ticket.resize(bytes);
    std::vector<unsigned char> hmac(ticket.begin(), ticket.begin() + 32);
    std::vector<unsigned char> publicKey(ticket.begin() + 32, ticket.end());
    BIGNUM *p = BN_new();
    BN_dec2bn(&p, std::to_string(P).c_str());
    BIGNUM *shared_secret = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating BN_CTX" << std::endl;
        exit(1);
    }
    BN_mod_exp(shared_secret, BN_bin2bn(publicKey.data(), publicKey.size(), nullptr), pri_key, p, ctx);
    BN_CTX_free(ctx);
    if (!validateHMAC(bignumToBytes(pub_key), hmac, bignumToBytes(shared_secret))){
        std::cout<< "Hmac Not validated. Process Aborted"<<std::endl;
        return;
    }
    activeGroupsMutex.lock();
    for (int i = 0; i < groups.size(); i++){
        if (groups[i].groupId == groupId){
            groups[i].key = bignumToBytes(shared_secret);
            break;
        }
    }
    activeGroupsMutex.unlock();
}

std::pair<std::vector<unsigned char>, std::pair<std::vector<unsigned char>, std::vector<unsigned char>>> authenticate(){
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0){
        std::cerr << "Error creating socket"<<std::endl;
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in Addr;
    struct hostent *server = gethostbyname("127.0.0.1");
    Addr.sin_family = AF_INET;
    Addr.sin_port = htons(8080);
    bcopy((char *)server->h_addr_list[0], (char *)&Addr.sin_addr.s_addr, server->h_length);
    if (connect(sock, (struct sockaddr *)&Addr, sizeof(Addr)) < 0) {
        std::cerr << "Connection failed\n";
        exit(EXIT_FAILURE);
    }
    struct passwd *pw = getpwuid(getuid());
    std::string currUser;
    std::string receiver = "server";
    int n1 = generateRandomInteger(1000, 9999);
    send(sock, &n1, sizeof(n1), 0);
    if (pw != nullptr){
        currUser = std::string(pw -> pw_name);
    }
    send(sock, currUser.c_str(), currUser.length(), 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    send(sock, receiver.c_str(), receiver.length(), 0);
    std::vector<unsigned char> nonce(1024), serve(1024);
    int bytes = recv(sock, nonce.data(), nonce.size(), 0);
    nonce.resize(bytes);
    encryptedData enData = deserializeEncryptedData(nonce);
    std::vector<unsigned char> key = readKey(currUser);
    int nonce1 = bytesToInt(decryptData(enData.data, key, enData.iv));
    if (nonce1 != n1){
        std::cout<< "Authentication Denied"<<std::endl;
        exit(EXIT_FAILURE);
    }
    recv(sock, serve.data(), serve.size(), 0);
    std::vector<unsigned char> symmetricKey(1024), ticket(1024);
    bytes = recv(sock, symmetricKey.data(), symmetricKey.size(), 0);
    symmetricKey.resize(bytes);
    encryptedData eData = deserializeEncryptedData(symmetricKey);
    symmetricKey = decryptData(eData.data, key, eData.iv);
    bytes = recv(sock, ticket.data(), ticket.size(), 0);
    ticket.resize(bytes);
    close(sock);
    return std::make_pair(symmetricKey, std::make_pair(ticket, enData.iv));
}

std::pair<std::vector<unsigned char>, int> communicate(){
    auto receivedData = authenticate();
    std::vector<unsigned char> symmetricKey = receivedData.first;
    std::pair<std::vector<unsigned char>, std::vector<unsigned char>> second = receivedData.second;
    std::vector<unsigned char> ticket = second.first;
    std::vector<unsigned char> iv = second.second;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0){
        std::cerr << "Error creating socket"<<std::endl;
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in Addr;
    struct hostent *server = gethostbyname("127.0.0.1");
    Addr.sin_family = AF_INET;
    Addr.sin_port = htons(8888);
    bcopy((char *)server->h_addr_list[0], (char *)&Addr.sin_addr.s_addr, server->h_length);
    if (connect(sock, (struct sockaddr *)&Addr, sizeof(Addr)) < 0) {
        std::cerr << "Connection failed\n";
        exit(EXIT_FAILURE);
    }
    int n2 = generateRandomInteger(1000, 9999);
    std::vector<unsigned char> nonce = serializeEncryptedData({iv, encryptData(intToBytes(n2), symmetricKey, iv)});
    send(sock, ticket.data(), ticket.size(), 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    send(sock, nonce.data(), nonce.size(), 0);
    std::vector<unsigned char> nonce2(1024);
    int bytes = recv(sock, nonce2.data(), nonce2.size(), 0);
    if (bytes == -1){
        std::cerr << "Failed to receive data over the socket"<< std::endl;
        close(sock);
        exit(EXIT_FAILURE);
    }
    nonce2.resize(bytes);
    encryptedData enData = deserializeEncryptedData(nonce2);
    int N2 = bytesToInt(decryptData(enData.data, symmetricKey, enData.iv));
    if (n2 != N2 + 1){
        std::cout<<"Authentication failed !"<<std::endl;
        close(sock);
        exit(EXIT_FAILURE);
    }
    std::vector<unsigned char> nonce3(1024);
    bytes = recv(sock, nonce3.data(), nonce3.size(), 0);
    if (bytes == -1){
        std::cerr << "Failed to receive data over the socket"<< std::endl;
        close(sock);
        exit(EXIT_FAILURE);
    }
    nonce3.resize(bytes);
    encryptedData eData = deserializeEncryptedData(nonce3);
    int n3 = bytesToInt(decryptData(eData.data, symmetricKey, eData.iv));
    std::vector<unsigned char> N3 = serializeEncryptedData({iv, encryptData(intToBytes(n3 - 1), symmetricKey, iv)});
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    send(sock, N3.data(), N3.size(), 0);
    return std::make_pair(symmetricKey, sock);
}

void listening(int socket){
    while(true){
        char buffer[1024];
        std::string receivedString;
        int bytesReceived = recv(socket, buffer, sizeof(buffer), 0);
        if (bytesReceived <= 0){
            continue;
        }
        receivedString.append(buffer, bytesReceived);
        std::cout<<receivedString<<std::endl;
        std::string prefix = "You have been invited to join group number";
        if (receivedString.compare(0, prefix.length(), prefix) == 0){
            size_t pos = receivedString.find("number");
            std::string number = receivedString.substr(pos + 6);
            int groupId = std::stoi(number);
            groupMutex.lock();
            pendingInvitation.push_back(groupId);
            groupMutex.unlock();
        }
        prefix = "Sending the public key of user for user";
        if (receivedString.compare(0, prefix.length(), prefix) == 0){
            struct passwd *pwd = getpwuid(getuid());
            std::string senderString;
            if(pwd != nullptr){
                senderString = readPublicKey((std::string(pwd->pw_name) + "_public_key.pem").c_str());
                std::cout<< (std::string(pwd->pw_name) + "_public_key.pem").c_str()<<std::endl;;
            }
            else{
                std::cout<<"username not found"<<std::endl;
            }
            send(socket, senderString.c_str(), senderString.length(), 0);
        }
        prefix = "Receiving public key from user with user";
        if (receivedString.compare(0, prefix.length(), prefix) == 0){
            char key[8192];
            recv(socket, key, sizeof(key), 0);
            size_t pos = receivedString.find("ID");
            receivedKeys userKey;
            userKey.userId = std::stoi(receivedString.substr(pos + 3));
            userKey.rsa = loadPublicKey(std::string(key));
            keyMutex.lock();
            userKeys.push_back(userKey);
            keyMutex.unlock();
        }
        prefix = "Intiating DH exchange with user ID";
        if (receivedString.compare(0, prefix.length(), prefix) == 0){
            intiateKeyExchange(std::stoi(receivedString.substr(receivedString.find("ID") + 3)), socket);
        }
        prefix = "Receiving DH exchange with user ID";
        if (receivedString.compare(0, prefix.length(), prefix) == 0){
            std::vector<unsigned char> enData(8192);
            int bytes = recv(socket, enData.data(), enData.size(), 0);
            if (bytes == -1){
                std::cerr<< "Error receiving data"<<std::endl;
                continue;
            }
            enData.resize(bytes);
            dhExchange(socket, enData, std::stoi(receivedString.substr(receivedString.find("Group") + 6)));
        }
        prefix = "Shared key established for group_";
        if (receivedString.compare(0, prefix.length(), prefix) == 0){
           compute_shared_secret(socket, std::stoi(receivedString.substr(receivedString.find("group_") + 6)));
        }
        prefix = "Sending group key to uid";
        if (receivedString.compare(0, prefix.length(), prefix) == 0){
           sendKey(socket, std::stoi(receivedString.substr(receivedString.find("uid") + 4)), std::stoi(receivedString.substr(receivedString.find("ID") + 3)));
        }
        prefix = "Receiving group key for Group";
        if (receivedString.compare(0, prefix.length(), prefix) == 0){
           receiveKey(socket, std::stoi(receivedString.substr(receivedString.find("Group") + 6)));
        }
        prefix = "Received a message from group";
        if (receivedString.compare(0, prefix.length(), prefix) == 0){
           std::vector<unsigned char> array(8192);
           int bytes = recv(socket, array.data(), array.size(), 0);
           array.resize(bytes);
           activeGroupsMutex.lock();
           int Group = std::stoi(receivedString.substr(receivedString.find("group") + 6));
           std::vector<unsigned char> key;
            for (int i = 0; i < groups.size(); i++){
                if (groups[i].groupId == Group){
                    key = groups[i].key;
                    break;
                }
            }
            encryptedData enData = deserializeEncryptedData(array);
            std::vector<unsigned char> message = decryptData(enData.data, key, enData.iv);
            for (unsigned char ch : message){
                std::cout << static_cast<char>(ch) << " ";
            }
        }
    }
}

void sending(int socket){
    while(true){
        std::string command;
        std::getline(std::cin, command);
        if (command.find("group_invite_accept") == 0){
            int Group = std::stoi(command.substr(command.find(" ") + 1));
            groupMutex.lock();
            if (std::find(pendingInvitation.begin(), pendingInvitation.end(), Group) >= pendingInvitation.end()){
                std::cout<< "You are not authorized to join group "<< Group<< std::endl;
                groupMutex.unlock();
                continue;
            }
            auto end = std::remove(pendingInvitation.begin(), pendingInvitation.end(), Group);
            pendingInvitation.erase(end, pendingInvitation.end());
            groupMutex.unlock();
            group newGroup;
            newGroup.groupId = Group;
            activeGroupsMutex.lock();
            groups.push_back(newGroup);
            activeGroupsMutex.unlock();
            std::cout<< "Successfully joined group "<<Group<<std::endl;
        }
        if (command.find("write_group") == 0){
            int Group = std::stoi(command.substr(command.find(" ") + 1));
            std::cout<<"Enter message to be sent to Group: "<<Group<<std::endl;
            std::string message;
            std::getline(std::cin, message);
            std::vector<unsigned char> key;
            activeGroupsMutex.lock();
            for (int i = 0; i < groups.size(); i++){
                if (groups[i].groupId == Group){
                    key = groups[i].key;
                    break;
                }
            }
            activeGroupsMutex.unlock();
            std::vector<unsigned char> iv = readRandomBytes(16);
            std::vector<unsigned char> encData = serializeEncryptedData({iv, encryptData(std::vector<unsigned char>(message.begin(), message.end()), key, iv)});
            send(socket, command.c_str(), command.length(), 0);
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            send(socket, encData.data(), encData.size(), 0);
            continue;
        }
        send(socket, command.c_str(), command.length(), 0);
    }
}

int main(){
    auto data = communicate();
    std::cout<< "Client connected to the server."<<std::endl;
    std::vector<unsigned char> symmetricKey = data.first;
    int socket = data.second;
    auto keys = generateDHKeys();
    pub_key = keys.first;
    pri_key = keys.second;
    std::thread thread1(listening, socket);
    std::thread thread2(sending, socket);
    thread1.join();
    thread2.join();
    return 0;
}
