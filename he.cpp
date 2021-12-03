//
// Created by Xiaoyuan Liu on 10/9/20.
//

#include "he.h"

// #define MULTIPARTY_DATABASE_HE_USE_STRICT_CHECK

SEAL_KeyGroup::SEAL_KeyGroup() :
secretKey(nullptr),
s_publicKey(nullptr),
s_galoisKeys(nullptr),
s_relinKeys(nullptr),
publicKey(nullptr),
galoisKeys(nullptr),
relinKeys(nullptr) {}

SEAL_KeyGroup::~SEAL_KeyGroup() {
    clear();
}

void SEAL_KeyGroup::generate(SEAL_Interface& HE) {
    clear();
    secretKey = new seal::SecretKey(HE.keygen->secret_key());

    s_publicKey = new seal::Serializable<seal::PublicKey>(HE.keygen->create_public_key());
    std::stringstream public_key_stream;
    s_publicKey->save(public_key_stream);
    publicKey = new seal::PublicKey();
    publicKey->load(*HE.ctx, public_key_stream);

    s_galoisKeys = new seal::Serializable<seal::GaloisKeys>(HE.keygen->create_galois_keys());
    std::stringstream galois_keys_stream;
    s_galoisKeys->save(galois_keys_stream);
    galoisKeys = new seal::GaloisKeys();
    galoisKeys->load(*HE.ctx, galois_keys_stream);

    s_relinKeys = new seal::Serializable<seal::RelinKeys>(HE.keygen->create_relin_keys());
    std::stringstream relin_keys_stream;
    s_relinKeys->save(relin_keys_stream);
    relinKeys = new seal::RelinKeys();
    relinKeys->load(*HE.ctx, relin_keys_stream);
}

void SEAL_KeyGroup::clear() {
    delete secretKey;
    secretKey = nullptr;
    delete s_publicKey;
    s_publicKey = nullptr;
    delete s_galoisKeys;
    s_galoisKeys = nullptr;
    delete s_relinKeys;
    s_relinKeys = nullptr;
    delete publicKey;
    publicKey = nullptr;
    delete galoisKeys;
    galoisKeys = nullptr;
    delete relinKeys;
    relinKeys = nullptr;
}

SEAL_Interface::SEAL_Interface() :
params(nullptr),
ctx(nullptr),
keygen(nullptr),
batchEncoder(nullptr) {}

SEAL_Interface::~SEAL_Interface() {
    delete params;
    delete ctx;
    delete keygen;
    delete batchEncoder;
    for (auto it: keys) {
        delete it.second;
    }
    for (auto it: batchedCiphers) {
        delete it.second;
    }
}

void SEAL_Interface::init_SEAL_param(const json &config) {
    // cache the context for better performance
    size_t poly_modulus_degree_bit_size = config["he"]["poly_modulus_degree_bit_size"].get<size_t>();
    size_t plain_modulus_bit_size = config["he"]["plain_modulus_bit_size"].get<size_t>();
    if (poly_modulus_degree_bit_size == previous_poly_modulus_degree_bit_size
    && plain_modulus_bit_size == previous_plain_modulus_bit_size)
        return;
    previous_poly_modulus_degree_bit_size = poly_modulus_degree_bit_size;
    previous_plain_modulus_bit_size = plain_modulus_bit_size;
    size_t poly_modulus_degree = 1 << poly_modulus_degree_bit_size;
    delete params;
    params = new seal::EncryptionParameters(seal::scheme_type::bfv);
    auto plain_modulus = seal::PlainModulus::Batching(poly_modulus_degree, plain_modulus_bit_size);
    params->set_poly_modulus_degree(poly_modulus_degree);
    params->set_coeff_modulus(seal::CoeffModulus::BFVDefault(poly_modulus_degree));
    params->set_plain_modulus(plain_modulus);
    ctx = new seal::SEALContext(*params);
    delete keygen;
    keygen = new seal::KeyGenerator(*ctx);
    delete batchEncoder;
    batchEncoder = new seal::BatchEncoder(*ctx);
    slot_count = batchEncoder->slot_count();
    row_size = slot_count / 2;
}

std::string SEAL_Interface::createKey(const json &config) {
    init_SEAL_param(config);
    std::string new_key_id = generate_uuid_v4();
    SEAL_KeyGroup* kg = new SEAL_KeyGroup();
    kg->generate(*this);
    keys[new_key_id] = kg;
    return new_key_id;
}

std::string SEAL_Interface::batchEncrypt(const std::vector<uint> &vec,
                                         std::string key_id,
                                         const json &config) {
    init_SEAL_param(config);
    SEAL_KeyGroup* kg = keys[key_id];
    std::string new_bc_id = generate_uuid_v4();
    std::vector<uint64_t> _vec(vec.begin(), vec.end());
    seal::Plaintext plain;
    batchEncoder->encode(_vec, plain);
    seal::Encryptor encryptor(*ctx, *kg->publicKey);
    seal::Ciphertext* cipher = new seal::Ciphertext();
    if (kg->secretKey != nullptr) {
        // use seeded encrypt
        encryptor.set_secret_key(*kg->secretKey);
        encryptor.encrypt_symmetric(plain, *cipher);
    } else {
        encryptor.encrypt(plain, *cipher);
    }
    batchedCiphers[new_bc_id] = cipher;
    return new_bc_id;
}

std::vector<uint> SEAL_Interface::batchDecrypt(std::string bc_id,
                                               std::string key_id,
                                               const json &config) {
    init_SEAL_param(config);
    SEAL_KeyGroup* kg = keys[key_id];
    assert(batchedCiphers.count(bc_id));
    seal::Ciphertext* cipher = batchedCiphers[bc_id];
    seal::Plaintext plain;
    assert(kg->secretKey != nullptr);
    seal::Decryptor decryptor(*ctx, *kg->secretKey);
    decryptor.decrypt(*cipher, plain);
    std::vector<uint64_t> _vec;
    batchEncoder->decode(plain, _vec);
    std::vector<uint> ret(_vec.begin(), _vec.end());
    return ret;
}

json SEAL_Interface::serializeProcessingKeysToJSON(std::string key_id, const json &config) {
    init_SEAL_param(config);
    SEAL_KeyGroup* kg = keys[key_id];
    json ret;
    ret["key_id"] = key_id;

    std::stringstream public_key_stream;
    if (kg->s_publicKey != nullptr) {
        kg->s_publicKey->save(public_key_stream);
    } else {
        kg->publicKey->save(public_key_stream);
    }
    std::string public_key_stream_str = public_key_stream.str();
    ret["public_key"] = Base64::Encode(public_key_stream_str);

    std::stringstream galois_keys_stream;
    if (kg->s_galoisKeys != nullptr) {
        kg->s_galoisKeys->save(galois_keys_stream);
    } else {
        kg->galoisKeys->save(galois_keys_stream);
    }
    std::string galois_keys_stream_str = galois_keys_stream.str();
    ret["galois_keys"] = Base64::Encode(galois_keys_stream_str);

    std::stringstream relin_keys_stream;
    if (kg->s_relinKeys != nullptr) {
        kg->s_relinKeys->save(relin_keys_stream);
    } else {
        kg->relinKeys->save(relin_keys_stream);
    }
    std::string relin_keys_stream_str = relin_keys_stream.str();
    ret["relin_keys"] = Base64::Encode(relin_keys_stream_str);

    if (config["debug"]["output_actual_size"].get<bool>()) {
        ret["stream_size"] = public_key_stream_str.size()
                + galois_keys_stream_str.size()
                + relin_keys_stream_str.size();
    }

    return ret;
}

std::string SEAL_Interface::loadProcessingKeys(const json &keys, const json &config) {
    init_SEAL_param(config);
    std::string key_id = keys["key_id"].get<std::string>();
    if (!this->keys.count(key_id))
        this->keys[key_id] = new SEAL_KeyGroup();
    SEAL_KeyGroup* kg = this->keys[key_id];
    std::string loaded_public_key;
    if (kg->publicKey != nullptr) {
        // if exist, double check to make sure it is the same key
#ifdef MULTIPARTY_DATABASE_HE_USE_STRICT_CHECK
std::stringstream public_key_stream;
kg->publicKey->save(public_key_stream);
Base64::Decode(keys["public_key"].get<std::string>(), loaded_public_key);
seal::PublicKey temp_public_key;
std::stringstream temp_public_key_stream(loaded_public_key);
temp_public_key.load(*ctx, temp_public_key_stream);
std::stringstream cmp_public_key_stream;
temp_public_key.save(cmp_public_key_stream);
assert(public_key_stream.str() == cmp_public_key_stream.str());
#endif
// skipping loading
// since we already checked publickey, we won't check the other two
    } else {
        kg->publicKey = new seal::PublicKey();
        // delete kg->publicKey; // no need, it should be nullptr anyway
        Base64::Decode(keys["public_key"].get<std::string>(), loaded_public_key);
        std::stringstream public_key_stream(loaded_public_key);
        kg->publicKey->load(*ctx, public_key_stream);

        kg->galoisKeys = new seal::GaloisKeys();
        std::string loaded_galois_keys;
        Base64::Decode(keys["galois_keys"].get<std::string>(), loaded_galois_keys);
        std::stringstream galois_keys_stream(loaded_galois_keys);
        kg->galoisKeys->load(*ctx, galois_keys_stream);

        kg->relinKeys = new seal::RelinKeys();
        std::string loaded_relin_keys;
        Base64::Decode(keys["relin_keys"].get<std::string>(), loaded_relin_keys);
        std::stringstream relin_keys_stream(loaded_relin_keys);
        kg->relinKeys->load(*ctx, relin_keys_stream);
    }
    return key_id;
}

json SEAL_Interface::serializeSecretKeyToJSON(std::string key_id, const json &config) {
    init_SEAL_param(config);
    SEAL_KeyGroup* kg = keys[key_id];
    json ret;
    ret["key_id"] = key_id;

    std::stringstream secket_key_stream;
    assert(kg->secretKey != nullptr);
    kg->secretKey->save(secket_key_stream);
    ret["secret_key"] = Base64::Encode(secket_key_stream.str());

    if (config["debug"]["output_actual_size"].get<bool>()) {
        ret["stream_size"] = secket_key_stream.str().size();
    }

    return ret;
}

std::string SEAL_Interface::loadSecretKey(const json &key, const json &config) {
    init_SEAL_param(config);
    std::string key_id = key["key_id"].get<std::string>();
    if (!this->keys.count(key_id))
        this->keys[key_id] = new SEAL_KeyGroup();
    SEAL_KeyGroup* kg = this->keys[key_id];
    std::string loaded_secret_key;
    if (kg->secretKey != nullptr) {
#ifdef MULTIPARTY_DATABASE_HE_USE_STRICT_CHECK
        std::stringstream secret_key_stream;
        kg->secretKey->save(secret_key_stream);
        Base64::Decode(key["secret_key"].get<std::string>(), loaded_secret_key);
        assert(secret_key_stream.str() == loaded_secret_key);
#endif
    } else {
        kg->secretKey = new seal::SecretKey();
        Base64::Decode(key["secret_key"].get<std::string>(), loaded_secret_key);
        std::stringstream secret_key_stream(loaded_secret_key);
        kg->secretKey->load(*ctx, secret_key_stream);
    }
    return key_id;
}

json SEAL_Interface::serializeBatchedCipherToJSON(std::string batched_cipher_id,
                                                  const json &config) {
    init_SEAL_param(config);
    json ret;
    ret["batched_cipher_id"] = batched_cipher_id;

    std::stringstream batched_cipher_stream;
    assert(batchedCiphers.count(batched_cipher_id));
    batchedCiphers[batched_cipher_id]->save(batched_cipher_stream);
    ret["batched_cipher"] = Base64::Encode(batched_cipher_stream.str());

    if (config["debug"]["output_actual_size"].get<bool>()) {
        ret["stream_size"] = batched_cipher_stream.str().size();
    }

    return ret;
}

std::string SEAL_Interface::loadBatchedCipher(const json &batched_cipher,
                                              const json &config) {
    init_SEAL_param(config);
    std::string bc_id = batched_cipher["batched_cipher_id"].get<std::string>();
    std::string loaded_batched_cipher;
    if (this->batchedCiphers.count(bc_id)) {
        // if exist, double check to make sure it is the same cipher
#ifdef MULTIPARTY_DATABASE_HE_USE_STRICT_CHECK
std::stringstream bc_stream;
batchedCiphers[bc_id]->save(bc_stream);
Base64::Decode(batched_cipher["batched_cipher"].get<std::string>(), loaded_batched_cipher);
assert(bc_stream.str() == loaded_batched_cipher);
#endif
    } else {
        Base64::Decode(batched_cipher["batched_cipher"].get<std::string>(), loaded_batched_cipher);
        std::stringstream bc_stream(loaded_batched_cipher);
        batchedCiphers[bc_id] = new seal::Ciphertext();
        batchedCiphers[bc_id]->load(*ctx, bc_stream);
    }
    return bc_id;
}

std::string SEAL_Interface::addBatchedCiphers(
        std::string lhs,
        std::string rhs,
        const json &config) {
    init_SEAL_param(config);
    seal::Ciphertext l_bc = *batchedCiphers.at(lhs);
    seal::Ciphertext r_bc = *batchedCiphers.at(rhs);
    seal::Evaluator evaluator(*ctx);
    seal::Ciphertext* new_bc = new seal::Ciphertext;
    evaluator.add(l_bc, r_bc, *new_bc);
    std::string new_bc_id = generate_uuid_v4();
    batchedCiphers[new_bc_id] = new_bc;
    return new_bc_id;
}

std::string SEAL_Interface::addBatchedCipherWithPlain(
        std::string bc_id,
        const std::vector<uint> &record_batch,
        const json &config) {
    init_SEAL_param(config);
    seal::Ciphertext batch_cipher = *batchedCiphers.at(bc_id);
    seal::Evaluator evaluator(*ctx);
    std::vector<uint64_t> _vec(record_batch.begin(), record_batch.end());
    seal::Plaintext plain;
    batchEncoder->encode(_vec, plain);
    seal::Ciphertext* new_bc = new seal::Ciphertext;
    evaluator.add_plain(batch_cipher, plain, *new_bc);
    std::string new_bc_id = generate_uuid_v4();
    batchedCiphers[new_bc_id] = new_bc;
    return new_bc_id;
}

std::string SEAL_Interface::negateBatchedCipher(
        std::string bc_id,
        const json &config) {
    init_SEAL_param(config);
    seal::Ciphertext batch_cipher = *batchedCiphers.at(bc_id);
    seal::Evaluator evaluator(*ctx);
    seal::Ciphertext* new_bc = new seal::Ciphertext;
    evaluator.negate(batch_cipher, *new_bc);
    std::string new_bc_id = generate_uuid_v4();
    batchedCiphers[new_bc_id] = new_bc;
    return new_bc_id;

}

std::string SEAL_Interface::flipBatchedCipher(
        std::string bc_id,
        const json &config) {
    init_SEAL_param(config);
    seal::Ciphertext batch_cipher = *batchedCiphers.at(bc_id);
    seal::Evaluator evaluator(*ctx);
    size_t poly_modulus_degree = 1 << previous_poly_modulus_degree_bit_size;
    std::vector<uint64_t> _vec(poly_modulus_degree, 1);
    seal::Plaintext plain;
    batchEncoder->encode(_vec, plain);
    seal::Ciphertext* new_bc = new seal::Ciphertext;
    evaluator.negate(batch_cipher, *new_bc);
    evaluator.add_plain_inplace(*new_bc, plain);
    std::string new_bc_id = generate_uuid_v4();
    batchedCiphers[new_bc_id] = new_bc;
    return new_bc_id;
}

std::string SEAL_Interface::multiplyBatchedCiphers(
        std::string lhs,
        std::string rhs,
        std::string key_id,
        const json &config) {
    init_SEAL_param(config);
    SEAL_KeyGroup* kg = keys[key_id];
    seal::RelinKeys relinKeys = *kg->relinKeys;
    seal::Ciphertext l_bc = *batchedCiphers.at(lhs);
    seal::Ciphertext r_bc = *batchedCiphers.at(rhs);
    seal::Evaluator evaluator(*ctx);
    seal::Ciphertext* new_bc = new seal::Ciphertext;
    evaluator.multiply(l_bc, r_bc, *new_bc);
    evaluator.relinearize_inplace(*new_bc, relinKeys);
    std::string new_bc_id = generate_uuid_v4();
    batchedCiphers[new_bc_id] = new_bc;
    return new_bc_id;
}

std::string SEAL_Interface::multiplyBatchedCipherWithPlain(
        std::string bc_id,
        const std::vector<uint> &record_batch,
        const json &config) {
    init_SEAL_param(config);
    seal::Ciphertext batch_cipher = *batchedCiphers.at(bc_id);
    seal::Evaluator evaluator(*ctx);
    std::vector<uint64_t> _vec(record_batch.begin(), record_batch.end());
    seal::Plaintext plain;
    batchEncoder->encode(_vec, plain);
    seal::Ciphertext* new_bc = new seal::Ciphertext;
    evaluator.multiply_plain(batch_cipher, plain, *new_bc);
    std::string new_bc_id = generate_uuid_v4();
    batchedCiphers[new_bc_id] = new_bc;
    return new_bc_id;
}

std::string SEAL_Interface::rotateRowBatchedCipher(
        std::string bc_id,
        int offset,
        std::string key_id,
        const json &config) {
    // note that this rotation operation only rotate the rows
    // eg. [1, 2, 3, 4, 5, 6, 7, 8] --> [2, 3, 4, 1, 6, 7, 8, 5]
    init_SEAL_param(config);
    SEAL_KeyGroup* kg = keys[key_id];
    seal::GaloisKeys galoisKeys = *kg->galoisKeys;
    seal::Ciphertext batch_cipher = *batchedCiphers.at(bc_id);
    seal::Evaluator evaluator(*ctx);
    seal::Ciphertext* new_bc = new seal::Ciphertext;
    evaluator.rotate_rows(batch_cipher, offset, galoisKeys, *new_bc);
    std::string new_bc_id = generate_uuid_v4();
    batchedCiphers[new_bc_id] = new_bc;
    return new_bc_id;
}

std::string SEAL_Interface::rotateColumnBatchedCipher(
        std::string bc_id,
        std::string key_id,
        const json &config) {
    // note that this rotation operation only rotate the columns
    // eg. [1, 2, 3, 4, 5, 6, 7, 8] --> [5, 6, 7, 8, 1, 2, 3, 4]
    init_SEAL_param(config);
    SEAL_KeyGroup* kg = keys[key_id];
    seal::GaloisKeys galoisKeys = *kg->galoisKeys;
    seal::Ciphertext batch_cipher = *batchedCiphers.at(bc_id);
    seal::Evaluator evaluator(*ctx);
    seal::Ciphertext* new_bc = new seal::Ciphertext;
    evaluator.rotate_columns(batch_cipher, galoisKeys, *new_bc);
    std::string new_bc_id = generate_uuid_v4();
    batchedCiphers[new_bc_id] = new_bc;
    return new_bc_id;
}

void SEAL_Interface::reset(const json &config) {
    // DANGEROUS operation!! all existing keys and ciphers will be removed
    // only should be used in debugging mode
    init_SEAL_param(config);
    keys.clear();
    batchedCiphers.clear();
}

json SEAL_Interface::generate_he_config(size_t poly_modulus_degree_bit_size, size_t plain_modulus_bit_size) {
    json j;
    j["he"]["poly_modulus_degree_bit_size"] = poly_modulus_degree_bit_size;
    j["he"]["plain_modulus_bit_size"] = plain_modulus_bit_size;
    j["debug"]["timing"] = true;
    j["debug"]["output_actual_size"] = true;
    return j;
}

void print_seal_parameters(seal::SEALContext& ctx) {
    auto& ctx_data = *ctx.key_context_data();
    std::string scheme_name;
    switch (ctx_data.parms().scheme()) {
        case seal::scheme_type::bfv:
            scheme_name = "BFV";
            break;
            case seal::scheme_type::ckks:
                scheme_name = "CKKS";
                break;
                default:
                    throw std::invalid_argument("unsupported scheme");
    }
    std::cout << "--------------------" << std::endl;
    std::cout << "Encryption params :" << std::endl;
    std::cout << "\tscheme: " << scheme_name << std::endl;
    std::cout << "\tpoly_modulus_degree: " << ctx_data.parms().poly_modulus_degree() << std::endl;
    std::cout << "\tplain_modulus: " << ctx_data.parms().plain_modulus().value() << std::endl;
    // TODO: print out more info, ref:https://github.com/microsoft/SEAL/blob/master/native/examples/examples.h#L56
    std::cout << "--------------------" << std::endl;
}
