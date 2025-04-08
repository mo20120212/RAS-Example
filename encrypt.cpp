#include <iostream>
#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>

using namespace std;

// ����SHA-512��ϣ��Ϊ��Կ
string generate_key(const string& password) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char*>(password.c_str()), password.length(), hash);
    
    stringstream ss;
    for(int i = 0; i < 32; i++) { // ȡǰ32�ֽ���ΪAES-256��Կ
        ss << hex << setw(2) << setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

// AES���ܺ���
string aes_encrypt(const string& plaintext, const string& password) {
    string key_hex = generate_key(password);
    
    // ת��Hex��ԿΪ������
    vector<unsigned char> key_bin;
    for(size_t i = 0; i < key_hex.length(); i += 2) {
        int byte;
        istringstream(key_hex.substr(i, 2)) >> hex >> byte;
        key_bin.push_back(static_cast<unsigned char>(byte));
    }

    // �������IV
    unsigned char iv[EVP_MAX_IV_LENGTH];
    RAND_bytes(iv, EVP_MAX_IV_LENGTH);

    // ��������������
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, &key_bin[0], iv);

    // ִ�м���
    int len;
    vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    EVP_EncryptUpdate(ctx, &ciphertext[0], &len, 
                     reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size());
    int ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, &ciphertext[0] + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    // ���IV������
    vector<unsigned char> combined;
    combined.insert(combined.end(), iv, iv + EVP_MAX_IV_LENGTH);
    combined.insert(combined.end(), ciphertext.begin(), ciphertext.begin() + ciphertext_len);

    // ת��ΪHex
    stringstream ss;
    for(auto b : combined) {
        ss << hex << setw(2) << setfill('0') << static_cast<int>(b);
    }
    return ss.str();
}

int main() {
    string plaintext, password;
    
    cout << "������Ҫ���ܵ��ַ���: ";
    getline(cin, plaintext);
    
    cout << "������������루���ⳤ�ȣ�: ";
    getline(cin, password);
    
    if(password.empty()) {
        cerr << "�������벻��Ϊ��" << endl;
        return 1;
    }

    string ciphertext = aes_encrypt(plaintext, password);
    cout << "���ܽ����" << endl << ciphertext << endl;
    
    return 0;
}