#include <iostream>
#include <vector>
#include <openssl/rsa.h>
#include <openssl/pem.h>

void saveKeys(std::string user){
    RSA* keyPair = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
    const BIGNUM* n = RSA_get0_n(keyPair);
    const BIGNUM* e = RSA_get0_e(keyPair);
    const BIGNUM* d = RSA_get0_d(keyPair);
    const BIGNUM* p = RSA_get0_p(keyPair);
    const BIGNUM* q = RSA_get0_q(keyPair);
    FILE* privateFile = fopen((user + "_private_key.pem").c_str(), "wb");
    if (privateFile == nullptr){
        perror("Error opening private key file");
        return;
    }
    PEM_write_RSAPrivateKey(privateFile, keyPair, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(privateFile);
    FILE* publicFile = fopen((user + "_public_key.pem").c_str(), "wb");
    if (publicFile == nullptr){
        perror("Error opening public key file");
        return;
    }
    PEM_write_RSAPublicKey(publicFile, keyPair);
    fclose(publicFile);
    RSA_free(keyPair);
}
int main(){
    std::vector<std::string> users {"bill", "joe", "kane", "steve", "travis", "david"};
    for (int i = 0; i < users.size(); i++){
        saveKeys(users[i]);
    }
    std::cout<< "All pairs of public-private keys saved in user_public_key.pem and user_private_key.pem files\n";
    return 0;
}
