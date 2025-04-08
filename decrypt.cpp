#include <iostream>
#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>

using namespace std;

// 生成SHA-512哈希作为密钥（与加密相同）
string generate_key(const string& password) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char*>(password.c_str()), password.length(), hash);
    
    stringstream ss;
    for(int i = 0; i < 32; i++) { // 取前32字节作为AES-256密钥
        ss << hex << setw(2) << setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

// AES解密函数
string aes_decrypt(const string& ciphertext_hex, const string& password) {
    string key_hex = generate_key(password);
    
    // 转换Hex密钥为二进制
    vector<unsigned char> key_bin;
    for(size_t i = 0; i < key_hex.length(); i += 2) {
        int byte;
        istringstream(key_hex.substr(i, 2)) >> hex >> byte;
        key_bin.push_back(static_cast<unsigned char>(byte));
    }

    // 转换Hex密文为二进制
    vector<unsigned char> combined;
    for(size_t i = 0; i < ciphertext_hex.length(); i += 2) {
        int byte;
        istringstream(ciphertext_hex.substr(i, 2)) >> hex >> byte;
        combined.push_back(static_cast<unsigned char>(byte));
    }

    // 提取IV和密文
    unsigned char iv[EVP_MAX_IV_LENGTH];
    copy(combined.begin(), combined.begin() + EVP_MAX_IV_LENGTH, iv);
    vector<unsigned char> ciphertext(combined.begin() + EVP_MAX_IV_LENGTH, combined.end());

    // 创建解密上下文
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, &key_bin[0], iv);

    // 执行解密
    int len;
    vector<unsigned char> plaintext(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
    EVP_DecryptUpdate(ctx, &plaintext[0], &len, &ciphertext[0], ciphertext.size());
    int plaintext_len = len;

    EVP_DecryptFinal_ex(ctx, &plaintext[0] + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return string(plaintext.begin(), plaintext.begin() + plaintext_len);
}

int main() {
    string ciphertext, password;
    
    cout << "请输入要解密的Hex字符串: ";
    getline(cin, ciphertext);
    
    cout << "请输入解密密码: ";
    getline(cin, password);
    
    if(password.empty()) {
        cerr << "错误：密码不能为空" << endl;
        return 1;
    }

    try {
        string plaintext = aes_decrypt(ciphertext, password);
        cout << "解密结果：" << endl << plaintext << endl;
    } catch(const exception& e) {
        cerr << "解密失败：" << e.what() << endl;
        return 1;
    }
    
    return 0;
}