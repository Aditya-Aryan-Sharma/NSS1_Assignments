#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rand.h>

bool deriveKey(const unsigned char* hashedPassword, size_t passwordLen, const unsigned char* salt, size_t saltLen, unsigned char* key, size_t keyLen) {
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    int iterations = 1000;
    int result = PKCS5_PBKDF2_HMAC(
        reinterpret_cast<const char*>(hashedPassword), passwordLen,
        salt, saltLen,
        iterations, EVP_sha256(),
        keyLen, key
    );

    return (result == 1);
}

bool hashPassword(const char* password, unsigned char* hash, unsigned int* hashLen) {
    const EVP_MD* digest = EVP_sha256();
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!EVP_DigestInit_ex(mdctx, digest, NULL) || !EVP_DigestUpdate(mdctx, password, strlen(password)) || !EVP_DigestFinal_ex(mdctx, hash, hashLen)){
        EVP_MD_CTX_free(mdctx);
        return false;
    }
    EVP_MD_CTX_free(mdctx);
    return true;
}

void storeKey(const unsigned char *password, size_t passwordLen, const char *filename) {
    unsigned char salt[16];
    RAND_bytes(salt, 16);
    size_t keyLen = 32;
    unsigned char key[32];
    if (deriveKey(password, passwordLen, salt, 16, key, keyLen)){
         std::ofstream outFile(filename, std::ios::out | std::ios::binary);
        if (!outFile.is_open()) {
            std::cerr << "Failed to open the file for writing." << std::endl;
            return;
        }
        outFile.write(reinterpret_cast<char*>(key), keyLen);
        std::cout<< "Long term symmetric key stored in " <<filename<<std::endl;
        outFile.close();
    } 
    else{
        std::cerr << "Failed to derive the key." << std::endl;
    }
}

int main(){
    std::vector<const char*> pass = {"bill", "steve", "kane", "joe", "travis", "david", "server"};
    std::vector<unsigned char *> hashes;
    for (int i = 0; i < pass.size(); i++){
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hashLen;
        if (hashPassword(pass[i], hash, &hashLen)){
            hashes.push_back(hash);
        } 
        else{
            std::cerr << "Failed to hash the password." << std::endl;
        }
    }
    for (int i = 0; i < pass.size(); i++){
        storeKey(hashes[i], 32, (std::string(pass[i]) + ".bin").c_str());
    }
    return 0;
}
