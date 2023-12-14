#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>
#include <vector>
#include <string>
#include <sstream>
#include <utility>
#include <random>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <mutex>
#include <pwd.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <cerrno>
#include <cstring>

struct ClientInfo{
    int socket;
    uid_t userID;
    std::string username;
};

struct encryptedData{
    std::vector<unsigned char> iv;
    std::vector<unsigned char> data;
};

struct group{
    int groupId;
    std::string name;
    std::vector<int> members;
};

std::vector<group> groups;
std::vector<ClientInfo> clients;
std::mutex clientMutex;
std::mutex groupMutex;
std::mutex fileMutex;

void who(){
    std::cout << "Connected Clients:" << std::endl;
    clientMutex.lock();
    for (const auto& client : clients) {
        std::cout << "User ID: " << client.userID << ", Username: " << client.username << std::endl;
    }
    clientMutex.unlock();
}

void write_all(ClientInfo info, const std::string& message){
    clientMutex.lock();
    for (ClientInfo socks: clients){
        if (socks.socket != info.socket){
            std::string str = info.username + std::string(": ") + message;
            send(socks.socket, str.c_str(), str.length(), 0);
        }
    }
    clientMutex.unlock();
}

int create_group(int socket){
    group Group;
    groupMutex.lock();
    Group.groupId = groups.size();
    Group.name = std::string("Group_") + std::to_string(groups.size());
    Group.members.push_back(socket);
    groups.push_back(Group);
    groupMutex.unlock();
    std::string message = "New Group " + Group.name + " with group ID " + std::to_string(Group.groupId) + " has been created";
    send(socket, message.c_str(), message.length(), 0);
    return Group.groupId;
}

void group_invite(uid_t user, int gid){
    clientMutex.lock();
    for (int i = 0; i < clients.size(); i++){
        if (clients[i].userID == user){
            std::string message = std::string("You have been invited to join group number ") + std::to_string(gid);
            send(clients[i].socket, message.c_str(), message.length(), 0);
            break;
        }
    }
    clientMutex.unlock();
}

void group_invite_accept(int socket, int gid){
    groupMutex.lock();
    for (int i = 0; i < groups.size(); i++){
        if (groups[i].groupId == gid){
            groups[i].members.push_back(socket);
            break;
        }
    }
    groupMutex.unlock();
}

void request_public_key(int socket, int receiverSocket){
    int senderId;
    clientMutex.lock();
    for (int i = 0; i < clients.size(); i++){
        if (clients[i].socket == socket){
            senderId = clients[i].userID;
            break;
        }
    }
    clientMutex.unlock();
    std::string message = "User Id(" + std::to_string(senderId) + ") has requested you to send your public Key";
    send(receiverSocket, message.c_str(), message.length(), 0);
}

void send_public_key(int senderSocket, uid_t userId){
    int receiverSocket, senderId;
    clientMutex.lock();
    for (int i = 0; i < clients.size(); i++){
        if (clients[i].userID == userId){
            receiverSocket = clients[i].socket;
        }
        if (clients[i].socket == senderSocket){
            senderId = clients[i].userID;
        }
    }
    clientMutex.unlock();
    std::string message = "Sending the public key of user for user ID " + std::to_string(senderId);
    send(senderSocket, message.c_str(), message.length(), 0);
    char publicKey[8192];
    int bytesReceived = recv(senderSocket, publicKey, sizeof(publicKey), 0);
    if (bytesReceived == -1){
        std::cerr << "Failed to receive data over the socket"<< std::endl;
        close(receiverSocket);
        exit(EXIT_FAILURE);
    }
    std::string key(publicKey);
    message = "Receiving public key from user with user ID " + std::to_string(senderId);
    send(receiverSocket, message.data(), message.length(), 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    send(receiverSocket, key.data(), key.size(), 0);
}

void init_group_dhxchg(int socket, uid_t userId, int groupId){
    int receiverSocket;
    clientMutex.lock();
    for (int i = 0; i < clients.size(); i++){
        if (clients[i].userID == userId){
            receiverSocket = clients[i].socket;
            break;
        }
    }
    clientMutex.unlock();
    std::string message = "Intiating DH exchange with user ID " + std::to_string(userId);
    send(socket, message.data(), message.length(), 0);
    std::vector<unsigned char> encData(8192);
    int bytes = recv(socket, encData.data(), encData.size(), 0);
    if (bytes == -1){
        std::cerr <<"Receive Error"<<std::endl;
        return;
    }
    encData.resize(bytes);
    message = "Receiving DH exchange with user ID " + std::to_string(getuid()) + " and Group " + std::to_string(groupId);
    send(receiverSocket, message.c_str(), message.length(), 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    send(receiverSocket, encData.data(), encData.size(), 0);
    std::vector<unsigned char> ticket(8192);
    recv(receiverSocket, ticket.data(), ticket.size(), 0);
    message = "Shared key established for group_" + std::to_string(groupId);
    send(socket, message.c_str(), message.length(), 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    send(socket, ticket.data(), ticket.size(), 0);
}

void sendKeys(int socket, uid_t userId, int groupID){
    int receiverSocket;
    clientMutex.lock();
    for (int i = 0; i < clients.size(); i++){
        if (clients[i].userID == userId){
            receiverSocket = clients[i].socket;
            break;
        }
    }
    clientMutex.unlock();
    std::string message = "Sending group key to uid" + std::to_string(userId) + "for group ID " + std::to_string(groupID);
    send(socket, message.c_str(), message.length(), 0);
    std::vector<unsigned char> encKey(8192);
    recv(socket, encKey.data(), encKey.size(), 0);
    message = "Receiving group key for Group " + std::to_string(groupID);
    send(receiverSocket, message.c_str(), message.length(), 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    send(receiverSocket, encKey.data(), encKey.size(), 0);
}

std::vector<unsigned char> readRandomBytes(size_t numBytes){
    std::vector<unsigned char> data(numBytes);
    std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
    if (urandom){
        urandom.read(reinterpret_cast<char*>(data.data()), numBytes);
    }
    return data;
}

std::vector<std::string> splitString(const std::string& input) {
    std::vector<std::string> words;
    std::istringstream iss(input);
    std::string word;
    while (iss >> word) {
        words.push_back(word);
    }
    return words;
}

std::vector<unsigned char> intToBytes(int value) {
    std::vector<unsigned char> result(sizeof(int));
    for (size_t i = 0; i < sizeof(int); ++i) {
        result[i] = (value >> (i * 8)) & 0xFF;
    }
    return result;
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

int generateRandomInteger(int min, int max) {
    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<int> distribution(min, max);
    return distribution(mt);
}

std::vector<unsigned char> readKey(std::string user, const std::string filename){
    fileMutex.lock();
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()){
        std::cerr << "Error opening the file: " << strerror(errno)<< std::endl;
        fileMutex.unlock();
        return std::vector<unsigned char>(1024);
    }
    file.seekg(0, std::ios::end);
    std::streampos fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<unsigned char> buffer(fileSize);
    file.read(reinterpret_cast<char*>(buffer.data()), fileSize);
    file.close();
    fileMutex.unlock();
    return buffer;
}

std::vector<unsigned char> deriveSessionKey(const std::vector<unsigned char>& key1, const std::vector<unsigned char>& key2){
    const size_t AES_256_KEY_SIZE = 32;
    std::vector<unsigned char> nonce(16);
    RAND_bytes(nonce.data(), nonce.size());
    std::vector<unsigned char> input;
    input.insert(input.end(), key1.begin(), key1.end());
    input.insert(input.end(), key2.begin(), key2.end());
    input.insert(input.end(), nonce.begin(), nonce.end());
    std::vector<unsigned char> sessionKey(AES_256_KEY_SIZE);
    unsigned int sessionKeyLen;
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) && EVP_DigestUpdate(mdctx, input.data(), input.size()) && EVP_DigestFinal_ex(mdctx, sessionKey.data(), &sessionKeyLen)){
        sessionKey.resize(sessionKeyLen);
    } 
    else{
        std::cerr << "Error deriving session key." << std::endl;
    }
    EVP_MD_CTX_free(mdctx);
    return sessionKey;
}

void write_group(int socket, int groupId){
    std::vector<unsigned char> groupMessage(8192);
    int bytes = recv(socket, groupMessage.data(), groupMessage.size(), 0);
    groupMessage.resize(bytes);
    std::vector<int> members;
    groupMutex.lock();
    for (int i = 0; i < groups.size(); i++){
        if (groups[i].groupId == groupId){
            members = groups[i].members;
            break;
        }
    }
    groupMutex.unlock();
    std::string message = "Received a message from group " + std::to_string(groupId);
    for (int i = 0; i < members.size(); i++){
        if (members[i] != socket){
            send(members[i], message.c_str(), message.length(), 0);
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            send(members[i], groupMessage.data(), groupMessage.size(), 0);
        }
    }
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

std::vector<unsigned char> deriveTicket(std::vector<unsigned char> serveKey, std::vector<unsigned char> symmKey, std::vector<unsigned char> sender, std::vector<unsigned char> iv){
    std::vector<unsigned char> ticket;
    ticket.insert(ticket.end(), symmKey.begin(), symmKey.end());
    ticket.insert(ticket.end(), sender.begin(), sender.end());
    return encryptData(ticket, serveKey, iv);   
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

void validateUser(int socket){
    int nonce1;
    char name1[256], name2[256];
    recv(socket, &nonce1, sizeof(nonce1), 0);
    recv(socket, name1, sizeof(name1), 0);
    recv(socket, name2, sizeof(name2), 0);
    std::vector<unsigned char> userKey = readKey(std::string(name1), std::string(name1) + std::string(".bin"));
    std::vector<unsigned char> iv = readRandomBytes(AES_BLOCK_SIZE);
    std::vector<unsigned char> nonce = serializeEncryptedData({iv, encryptData(intToBytes(nonce1), userKey, iv)});
    std::vector<unsigned char> serveName = serializeEncryptedData({iv, encryptData(std::vector<unsigned char>(name2, name2 + (sizeof(name2) / sizeof(char))), userKey, iv)});
    std::vector<unsigned char> servKey = readKey(std::string(name2), std::string(name2) + std::string(".bin"));
    std::vector<unsigned char> symmKey = deriveSessionKey(userKey, servKey);
    std::vector<unsigned char> sessionKey = serializeEncryptedData({iv, encryptData(symmKey, userKey, iv)});
    std::vector<unsigned char> ticket = serializeEncryptedData({iv, deriveTicket(servKey, symmKey, std::vector<unsigned char>(name1, name1 + (sizeof(name1) / sizeof(char))), iv)});
    send(socket, nonce.data(), nonce.size(), 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    send(socket, serveName.data(), serveName.size(), 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    send(socket, sessionKey.data(), sessionKey.size(), 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    send(socket, ticket.data(), ticket.size(), 0);
    close(socket);
}

std::pair<std::vector<unsigned char>, std::vector<unsigned char>> getSymmetricKey(int socket, ClientInfo info){
    std::vector<unsigned char> ticket(8192);
    int bytesReceived = recv(socket, ticket.data(), ticket.size(), 0);
    if (bytesReceived == -1) {
        std::cerr << "Failed to receive data over the socket"<< std::endl;
        close(socket);
        exit(EXIT_FAILURE);
    }
    ticket.resize(bytesReceived);
    encryptedData enData = deserializeEncryptedData(ticket);
    std::vector<unsigned char> key = readKey("server", "server.bin");
    std::vector<unsigned char> decryptedTicket = decryptData(enData.data, key, enData.iv);
    std::vector<unsigned char> symmetricKey (decryptedTicket.begin(), decryptedTicket.begin() + 32);
    std::vector<unsigned char> name (decryptedTicket.begin() + 32, decryptedTicket.end());
    return std::make_pair(symmetricKey, name);
}

bool mutualAuthenticate(int socket, std::vector<unsigned char> symmetricKey){
    std::vector<unsigned char> nonce2(4096);
    int bytes = recv(socket, nonce2.data(), nonce2.size(), 0);
    if (bytes == -1){
        std::cerr << "Failed to receive data over the socket"<< std::endl;
        close(socket);
        exit(EXIT_FAILURE);
    }
    nonce2.resize(bytes);
    encryptedData enData = deserializeEncryptedData(nonce2);
    int n2 = bytesToInt(decryptData(enData.data, symmetricKey, enData.iv));
    std::vector<unsigned char> N2 = serializeEncryptedData({enData.iv, encryptData(intToBytes(n2 - 1), symmetricKey, enData.iv)});
    send(socket, N2.data(), N2.size(), 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    int n3 = generateRandomInteger(1000, 9999);
    std::vector<unsigned char> nonce = serializeEncryptedData({enData.iv, encryptData(intToBytes(n3), symmetricKey, enData.iv)});
    send(socket, nonce.data(), nonce.size(), 0);
    std::vector<unsigned char> nonce3(4096);
    bytes = recv(socket, nonce3.data(), nonce3.size(), 0);
    if (bytes == -1){
        std::cerr << "Failed to receive data over the socket"<< std::endl;
        close(socket);
        exit(EXIT_FAILURE);
    }
    nonce3.resize(bytes);
    encryptedData eData = deserializeEncryptedData(nonce3);
    int N3 = bytesToInt(decryptData(eData.data, symmetricKey, eData.iv));
    return n3 - 1 == N3;
}

void closeConnection(int socket, ClientInfo info){
    close(socket);
    clientMutex.lock();
    for (auto entry = clients.begin(); entry != clients.end(); ++entry) {
        if (entry->socket == socket || entry -> userID == info.userID || entry -> username == info.username) {
            clients.erase(entry);
            break;
        }
    }
    clientMutex.unlock();
}

void server(int socket){
    ClientInfo info;
    auto ticket = getSymmetricKey(socket, info);
    std::vector<unsigned char> symmetricKey = ticket.first;
    std::string name (ticket.second.begin(), ticket.second.end());
    struct passwd *pwd = getpwnam(name.c_str());
    if (pwd != nullptr){
        info.socket = socket;
        info.userID = pwd->pw_uid;
        info.username = name;
    }
    else{
        std::cout << "User information not available."<< std::endl;
        closeConnection(socket, info);
    }
    clientMutex.lock();
    clients.push_back(info);
    clientMutex.unlock();
    if (!mutualAuthenticate(socket, symmetricKey)){
        std::cout<<info.username<<" client not authenticated"<<std::endl;
        closeConnection(socket, info);
        return;
    }
    while (true){
        char buffer[8192];
        std::string receivedString;
        ssize_t bytes = recv(socket, buffer, sizeof(buffer), 0);
        if (bytes <= 0){
            continue;
        }
        receivedString.append(buffer, bytes);
        std::vector<std::string> words = splitString(receivedString);
        if (words[0] == "who")
            who();
        else if (words[0] == "write_all"){
            if (words.size() == 2){
                write_all(info, words[1]);
            }
        }
        else if (words[0] == "create_group")
            create_group(socket);
        else if (words[0] == "group_invite"){
            if (words.size() == 3){
                group_invite(std::stoi(words[1]), std::stoi(words[2]));
            }
        }
        else if (words[0] == "group_invite_accept"){
            if (words.size() == 2){
                group_invite_accept(socket, std::stoi(words[1]));
            }
        }
        else if (words[0] == "request_public_key"){
            if (words.size() == 2){
                int receiverSocket;
                clientMutex.lock();
                for (int i = 0; i < clients.size(); i++){
                    if (clients[i].userID == std::stoi(words[1])){
                        receiverSocket = clients[i].socket;
                        break;
                    }
                }
                clientMutex.unlock();
                request_public_key(socket, receiverSocket);
            }
        }
        else if (words[0] == "send_public_key"){
            if (words.size() == 2){
                send_public_key(socket, std::stoi(words[1]));
            }
        }
        else if (words[0] == "init_group_dhxchg"){
            if (words.size() == 3){
                init_group_dhxchg(socket, std::stoi(words[1]), std::stoi(words[2]));
            }
        }
        else if (words[0] == "write_group"){
            if (words.size() == 2){
                write_group(socket, std::stoi(words[1]));
            }
        }
        else if (words[0] == "send_keys"){
            if (words.size() == 3){
                sendKeys(socket, std::stoi(words[1]), std::stoi(words[2]));
            }
        }
    }
}

void kdc(){
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Error creating socket"<<std::endl;
        return;
    }
    struct sockaddr_in servAddr;
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servAddr.sin_port = htons(8080);
    if (bind(sock, (struct sockaddr *)&servAddr, sizeof(servAddr)) < 0) {
        std::cerr << "Binding failed"<< std::endl;
        return;
    }
    while (true){
        listen(sock, 20);
        int socket = accept(sock, NULL, NULL);
        if (socket < 0){
            std::cerr << "Error accepting connection"<< std::endl;
            continue;
        }
        std::thread clientThread(validateUser, socket);
        clientThread.detach();
    }
}

void chatServer(){
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Error creating socket"<<std::endl;
        return;
    }
    struct sockaddr_in servAddr;
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servAddr.sin_port = htons(8888);
    if (bind(sock, (struct sockaddr *)&servAddr, sizeof(servAddr)) < 0) {
        std::cerr << "Binding failed"<< std::endl;
        return;
    }
    while (true){
        listen(sock, 20);
        int socket = accept(sock, NULL, NULL);
        if (socket < 0){
            std::cerr << "Error accepting connection"<< std::endl;
            return;
        }
        std::thread clientThread(server, socket);
        clientThread.detach();
    }
}

int main(){
    std::thread thread1(kdc);
    std::thread thread2(chatServer);
    thread1.join();
    thread2.join();
    return 0;
}
