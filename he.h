//
// Created by Xiaoyuan Liu on 10/9/20.
//

#ifndef MULTIPARTY_DATABASE_HE_H
#define MULTIPARTY_DATABASE_HE_H

#include <iostream>
#include <vector>
#include <string>
#include <unordered_map>
#include <random>

#include <json.hpp>
#include <seal/seal.h>
#include "myutil.h"

using json = nlohmann::json;

class SEAL_Interface;

class SEAL_KeyGroup {
public:
    seal::SecretKey* secretKey;
    seal::Serializable<seal::PublicKey>* s_publicKey;
    seal::Serializable<seal::GaloisKeys>* s_galoisKeys;
    seal::Serializable<seal::RelinKeys>* s_relinKeys;
    seal::PublicKey* publicKey;
    seal::GaloisKeys* galoisKeys;
    seal::RelinKeys* relinKeys;

    SEAL_KeyGroup(const SEAL_KeyGroup&) = delete;
    SEAL_KeyGroup& operator=(const SEAL_KeyGroup&) = delete;
    SEAL_KeyGroup();
    ~SEAL_KeyGroup();
    void generate(SEAL_Interface& HE);
    void clear();
};

class SEAL_Interface {
public:
    static const size_t NO_KEY=0;
    static const size_t U64_RETRIEVAL_CIPHERTEXT_NUM=8;

    json config;
    std::unordered_map<std::string, SEAL_KeyGroup*> keys;
    std::unordered_map<std::string, seal::Ciphertext*> batchedCiphers;
    size_t previous_poly_modulus_degree_bit_size;
    size_t previous_plain_modulus_bit_size;
    seal::EncryptionParameters* params;
    seal::SEALContext* ctx;
    seal::KeyGenerator* keygen;
    seal::BatchEncoder* batchEncoder;
    size_t slot_count;
    size_t row_size;

    SEAL_Interface(const SEAL_Interface&) = delete;
    SEAL_Interface& operator=(const SEAL_Interface&) = delete;
    ~SEAL_Interface();
    static SEAL_Interface& get_instance() {
        static SEAL_Interface instance;
        return instance;
    }
    static json generate_he_config(size_t poly_modulus_degree_bit_size,
                                   size_t plain_modulus_bit_size);
    void init_SEAL_param(const json& config);

    // member functions
    std::string createKey(const json& config);
    std::string batchEncrypt(const std::vector<uint>& vec,
                             std::string key_id,
                             const json& config);
    std::vector<uint> batchDecrypt(std::string bc_id,
                                   std::string key_id,
                                   const json& config);
    json serializeProcessingKeysToJSON(std::string key_id,
                                       const json& config);
    json serializeSecretKeyToJSON(std::string key_id,
                                  const json& config);
    json serializeBatchedCipherToJSON(std::string batched_cipher_id,
                                      const json& config);
    std::string loadProcessingKeys(const json& keys,
                                   const json& config);
    std::string loadSecretKey(const json& key,
                              const json& config);
    std::string loadBatchedCipher(const json& batched_cipher,
                                  const json& config);
    std::string addBatchedCiphers(std::string lhs,
                                  std::string rhs,
                                  const json &config);
    std::string addBatchedCipherWithPlain(std::string bc_id,
                                          const std::vector<uint> &record_batch,
                                          const json &config);
    std::string negateBatchedCipher(std::string bc_id,
                                    const json &config);
    std::string flipBatchedCipher(std::string bc_id,
                                  const json &config);  // using negate and add
    std::string multiplyBatchedCiphers(std::string lhs,
                                       std::string rhs,
                                       std::string key_id,
                                       const json& config);
    std::string multiplyBatchedCipherWithPlain(std::string bc_id, const std::vector<uint> &record_batch,
                                               const json &config);
    std::string rotateRowBatchedCipher(std::string bc_id,
                                       int offset,
                                       std::string key_id,
                                       const json& config);
    std::string rotateColumnBatchedCipher(std::string bc_id,
                                       std::string key_id,
                                       const json& config);
    // advanced operations
    std::string sumBatchedCipher(std::string bc_id,
                                 std::string key_id,  // key is required for summing
                                 const json& config);
    std::string applyElementwiseMapping(const std::vector<uint>& record_batch,
                                        const std::string mapping_batch_cipher_id,
                                        const size_t mapping_batch_cipher_offset,
                                        const size_t mapping_batch_cipher_bit_width,
                                        std::string key_id,
                                        const json& config);  // basic building block
    std::string generateHistogramCipherWithIndicator(const std::vector<uint>& record_batch,
                                                     const std::string indicator_cipher_id,
                                                     const size_t histogram_bin_count_bit_width,
                                                     std::string key_id,
                                                     const json& config);
    std::vector<std::vector<size_t> > generateRandomOffsetsForRetrieval(size_t ciphertext_count, size_t offset_count);
    std::vector<std::string> retrieveUint64WithIndicators(const std::vector<std::vector<uint64_t> >& record_batches,
                                                          const std::vector<std::string>& indicator_cipher_ids,
                                                          const std::vector<std::vector<size_t> >& offsets,
                                                          std::string key_id,
                                                          const json& config);
                                                          // return U64_RETRIEVAL_CIPHERTEXT_NUM ciphertexts
    std::vector<uint64_t> decodeRetrievedUint64(const std::vector<std::string>& retrieved_cipher_ids,
                                                const std::vector<std::vector<size_t> >& offsets,
                                                std::string key_id,
                                                const json& config);
    void reset(const json& config);

private:
    SEAL_Interface();
};

void print_seal_parameters(seal::SEALContext& ctx);

#endif //MULTIPARTY_DATABASE_HE_H
