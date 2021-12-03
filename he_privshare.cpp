# include "he.h"


std::string SEAL_Interface::sumBatchedCipher(
        std::string bc_id,
        std::string key_id,
        const json &config) {
    // add all slots together with O(log(n)) rotations
    // eg. [1, 2, 3, 4] --> [10, 10, 10, 10]
    init_SEAL_param(config);
    SEAL_KeyGroup* kg = keys[key_id];
    seal::RelinKeys relinKeys = *kg->relinKeys;
    seal::GaloisKeys galoisKeys = *kg->galoisKeys;
    seal::Ciphertext batch_cipher = *batchedCiphers.at(bc_id);
    seal::Evaluator evaluator(*ctx);
    seal::Ciphertext* new_bc = new seal::Ciphertext(batch_cipher);
    seal::Ciphertext new_bc_after_rotation;
    evaluator.rotate_columns(*new_bc, galoisKeys, new_bc_after_rotation);
    evaluator.add_inplace(*new_bc, new_bc_after_rotation);
    for (int i=previous_poly_modulus_degree_bit_size-2; i>=0; --i) {
        evaluator.rotate_rows(*new_bc, (1<<i), galoisKeys, new_bc_after_rotation);
        evaluator.add_inplace(*new_bc, new_bc_after_rotation);
    }
    std::string new_bc_id = generate_uuid_v4();
    batchedCiphers[new_bc_id] = new_bc;
    return new_bc_id;
}

void quick_debug_batch_cipher(seal::Ciphertext& c, std::string key_id, const json &config) {
    SEAL_Interface& HE = SEAL_Interface::get_instance();
    HE.batchedCiphers["temp"] = &c;
    // SEAL_KeyGroup* kg = HE.keys[key_id]; // reserved for later - debugging with secret key
    auto vec = HE.batchDecrypt("temp", key_id, config);
    std::cout << "\t\t\t";
    for (int i=0; i<64; ++i) std::cout << vec[i] << "|";
    std::cout << std::endl;
    HE.batchedCiphers.erase("temp");
}

void check_noise_batch_cipher(seal::Decryptor& decryptor, seal::Ciphertext& c) {
    std::cout << decryptor.invariant_noise_budget(c) << std::endl;
}

void he_balanced_sum_inplace(seal::Evaluator& eval, seal::Ciphertext* cs, size_t l, size_t r) {
    if (l + 1 >= r) return;
    int mid = (l+r+1) / 2;
    he_balanced_sum_inplace(eval, cs, l, mid);
    he_balanced_sum_inplace(eval, cs, mid, r);
    eval.add_inplace(cs[l], cs[mid]);
}

std::string SEAL_Interface::applyElementwiseMapping(
        const std::vector<uint> &record_batch,
        const std::string mapping_batch_cipher_id,
        const size_t mapping_batch_cipher_offset,
        const size_t mapping_batch_cipher_bit_width,
        std::string key_id, const json &config) {
    /*
     * record_batch: record values in the database (v < 2^bit_width)
     * mapping_batch_cipher (indexed by id): [****, ****, 1234, ****]
     * return -> encrypted version of the elementwise mapped value for the record vector
     */
    init_SEAL_param(config);
    SEAL_KeyGroup* kg = keys[key_id];
    seal::RelinKeys relinKeys = *kg->relinKeys;
    seal::GaloisKeys galoisKeys = *kg->galoisKeys;
    seal::Evaluator evaluator(*ctx);
    seal::Encryptor encryptor(*ctx, *kg->publicKey);
    // 1. Prepare the group_cipher [****, ****, 1234, ****] -> [1234, 1234, 1234, 1234] (1-4 should all be 0 or 1)
    seal::Ciphertext group_cipher = *batchedCiphers.at(mapping_batch_cipher_id);
    // std::cout << "group_cipher "; quick_debug_batch_cipher(group_cipher, key_id, config);
    size_t mapping_batch_cipher_width = (1 << mapping_batch_cipher_bit_width);
    std::vector<uint64_t> mask_matrix(slot_count, 0ULL);
    for (std::size_t i=mapping_batch_cipher_offset;
         i < mapping_batch_cipher_offset + mapping_batch_cipher_width;
    ++i) mask_matrix[i] = 1;
    seal::Plaintext mask_plain;
    batchEncoder->encode(mask_matrix, mask_plain);
    seal::Ciphertext masked_group;
    evaluator.multiply_plain(group_cipher, mask_plain, masked_group);
    evaluator.relinearize_inplace(masked_group, relinKeys);
    seal::Ciphertext masked_group_after_rotation;
    evaluator.rotate_columns(masked_group, galoisKeys, masked_group_after_rotation);
    evaluator.add_inplace(masked_group, masked_group_after_rotation);
    for (int i=previous_poly_modulus_degree_bit_size-2; i>=(int) mapping_batch_cipher_bit_width; --i) {
        evaluator.rotate_rows(masked_group, (1<<i), galoisKeys, masked_group_after_rotation);
        evaluator.add_inplace(masked_group, masked_group_after_rotation);
    }
    // 2. Prepare all possible rotation result [1234, 1234, ...], [2341, 2341, ...], [3412, 3412, ...], ...
    seal::Ciphertext* masked_shift = new seal::Ciphertext[mapping_batch_cipher_width];
    masked_shift[0] = masked_group;
    for (int i=1; i<(int) mapping_batch_cipher_width; ++i) {
        evaluator.rotate_rows(masked_shift[i-1], 1, galoisKeys, masked_shift[i]);
    }
    // 3. Fill in actually values from database to build the mapping vector
    std::vector<uint64_t>* record_map_picker = new std::vector<uint64_t>[mapping_batch_cipher_width];
    for (int i=0; i<(int) mapping_batch_cipher_width; ++i)
        record_map_picker[i] = std::vector<uint64_t>(slot_count, 0ULL);
    for (int i=0; i<(int) slot_count; ++i)
        record_map_picker[(record_batch[i] + mapping_batch_cipher_width - i) % mapping_batch_cipher_width][i] = 1;
    // prepare a full-zero plaintext first
    seal::Plaintext zero_plain;
    std::vector<uint64_t> zero_vec(slot_count, 0ULL);
    batchEncoder->encode(zero_vec, zero_plain);

    for (int i=0; i<(int) mapping_batch_cipher_width; ++i) {
        // if all coefficient in the record_map_picker[i] is 0, it will lead to transparent ciphertext which is insecure
        // so we need to check if all coefficient in the record_map_picker[i] is 0
        bool all_zero = true;
        for (int j=0; j<(int) slot_count; ++j) {
            if (record_map_picker[i][j] != 0) {
                all_zero = false;
                break;
            }
        }
        if (!all_zero) {
            seal::Plaintext picker_plain;
            batchEncoder->encode(record_map_picker[i], picker_plain);
            evaluator.multiply_plain_inplace(masked_shift[i], picker_plain);
            evaluator.relinearize_inplace(masked_shift[i], relinKeys);
        } else {
            encryptor.encrypt(zero_plain, masked_shift[i]);
        }
    }
    he_balanced_sum_inplace(evaluator, masked_shift, 0, mapping_batch_cipher_width);
    seal::Ciphertext* ret = new seal::Ciphertext(masked_shift[0]);
    std::string new_bc_id = generate_uuid_v4();
    batchedCiphers[new_bc_id] = ret;
    delete[] masked_shift;
    delete[] record_map_picker;
    return new_bc_id;
}

std::string SEAL_Interface::generateHistogramCipherWithIndicator(
        const std::vector<uint> &record_batch,
        const std::string indicator_cipher_id,
        const size_t histogram_bin_count_bit_width,
        std::string key_id, const json &config) {
    /*
     * record_batch: record values in the database (v < 2^histogram_bin_count_bit_width)
     * indicator_cipher_id: encrypted 0/1 indicating whether record is selected
     * return -> encrypted selected item counting in each bin in each 2^histogram_bin_count_bit_width slots
     */
    init_SEAL_param(config);
    SEAL_KeyGroup* kg = keys[key_id];
    seal::RelinKeys relinKeys = *kg->relinKeys;
    seal::GaloisKeys galoisKeys = *kg->galoisKeys;
    seal::Evaluator evaluator(*ctx);
    seal::Encryptor encryptor(*ctx, *kg->publicKey);
    // 1. Prepare all types of rotations for the indicator cipher
    seal::Ciphertext indicator_cipher = *batchedCiphers.at(indicator_cipher_id);
    // std::cout << "indicator_cipher "; quick_debug_batch_cipher(indicator_cipher, key_id, config);
    size_t histogram_bin_count = 1 << histogram_bin_count_bit_width;
    seal::Ciphertext* rotated_ind = new seal::Ciphertext[histogram_bin_count];
    rotated_ind[0] = indicator_cipher;
    for (int i=1; i<(int) histogram_bin_count; ++i) {
        evaluator.rotate_rows(rotated_ind[i-1], 1, galoisKeys, rotated_ind[i]);
    }

    // 2. Construct picker to get value in the correct slots
    // prepare a full-zero plaintext first
    seal::Plaintext zero_plain;
    std::vector<uint64_t> zero_vec(slot_count, 0ULL);
    batchEncoder->encode(zero_vec, zero_plain);

    for (uint i=0; i<histogram_bin_count; ++i) {
        bool all_zero = true;
        std::vector<uint64_t> picker_vec(slot_count, 0ULL);
        for (int j=0; j<(int) slot_count; ++j) {
            if (record_batch[(j + i) % slot_count] == (j % histogram_bin_count)) {
                picker_vec[j] = 1ULL;
                all_zero = false;
            }
        }
        if (!all_zero) {
            seal::Plaintext picker_plain;
            batchEncoder->encode(picker_vec, picker_plain);
            evaluator.multiply_plain_inplace(rotated_ind[i], picker_plain);
            evaluator.relinearize_inplace(rotated_ind[i], relinKeys);
        } else {
            encryptor.encrypt(zero_plain, rotated_ind[i]);
        }
    }
    he_balanced_sum_inplace(evaluator, rotated_ind, 0, histogram_bin_count);
    seal::Ciphertext* histogram_cipher = new seal::Ciphertext(rotated_ind[0]);

    // 3. Aggregate the slots
    seal::Ciphertext histogram_cipher_after_rotation;
    evaluator.rotate_columns(*histogram_cipher, galoisKeys, histogram_cipher_after_rotation);
    evaluator.add_inplace(*histogram_cipher, histogram_cipher_after_rotation);
    for (std::size_t i=previous_poly_modulus_degree_bit_size - 2; i >= histogram_bin_count_bit_width; --i) {
        evaluator.rotate_rows(*histogram_cipher, (1<<i), galoisKeys, histogram_cipher_after_rotation);
        evaluator.add_inplace(*histogram_cipher, histogram_cipher_after_rotation);
    }

    std::string new_bc_id = generate_uuid_v4();
    batchedCiphers[new_bc_id] = histogram_cipher;
    delete[] rotated_ind;
    return new_bc_id;
}

std::vector<std::vector<size_t>> SEAL_Interface::generateRandomOffsetsForRetrieval(size_t ciphertext_count,
                                                                                   size_t offset_count) {
    std::random_device dev;
    std::mt19937 rng(dev());
    std::uniform_int_distribution<std::mt19937::result_type> dist(0, (slot_count/2)-1);
    std::vector<std::vector<size_t>> ret = std::vector<std::vector<size_t>>(ciphertext_count, std::vector<size_t>(offset_count));
    for (size_t i=0; i<ciphertext_count; ++i) {
        for (size_t j=0; j < offset_count; ++j) {
            ret[i][j] = dist(rng);
        }
    }
    return ret;
}

class Uint64Encoding {
    /*
    LAYOUT:
    17 bits
     16 15 14 13 12 11 10 9  8  7  6  5  4  3  2  1  0
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    data[0]:
     16          12                      4
    +-----------+-----------------------+--------------+
    |  padding  |       addr[7:0]       |  count[4:0]  |
    +-----------+-----------------------+--------------+

    data[1]:
     16          12
    +-----------+--------------------------------------+
    |  padding  |              addr[20:8]              |
    +-----------+--------------------------------------+

    data[2]:
     16          12       9
    +-----------+--------+-----------------------------+
    |  padding  |  addr  |          checksum           |
    |           | [23:21]|                             |
    +-----------+--------+-----------------------------+

    data[3+i] (i=0 to 3):
     16          12
    +-----------+--------------------------------------+
    |  padding  |           val[12+13i:13i]            |
    +-----------+--------------------------------------+

    data[7]:
     16           11
    +-----------++-------------------------------------+
    |  padding  ||                val[63:0]            |
    +-----------++-------------------------------------+
    */
    public:
    bool valid;
    uint64_t value;
    size_t count;
    size_t address;
    uint64_t calculated_checksum(const std::vector<uint>& encoded) const {
        uint64_t target_checksum = (encoded[2] >> 10);
        size_t contained_bits = 7;
        for (int i=0; i<8; ++i) {
            if (i == 2) continue;
            uint current = encoded[i];
            size_t remained_bits = 17;
            while (remained_bits) {
                size_t required_bits = std::min(remained_bits, 10 - contained_bits);
                uint64_t extracted_bits = current & ((1<<required_bits)-1);
                current >>= required_bits;
                remained_bits -= required_bits;
                target_checksum ^= (extracted_bits << contained_bits);
                contained_bits += required_bits;
                contained_bits %= 10;
            }
        }
        return target_checksum;
    }
    Uint64Encoding(uint64_t v, size_t a) : valid(true), value(v), count(1), address(a) {}
    Uint64Encoding(const std::vector<uint>& encoded) {
        // check size
        if (encoded.size() != 8) {
            valid = false;
            return;
        }
        for (auto i: encoded) {
            if (i >= (1<<17)) {
                valid = false;
                return;
            }
        }
        // check checksum
        uint64_t extracted_checksum = encoded[2] & 0x7ff;
        uint64_t target_checksum = calculated_checksum(encoded);
        if (extracted_checksum != target_checksum) {
            valid = false;
            return;
        }
        // extract data
        count = encoded[0] & ((1 << 5) - 1);
        if (count != 1) {
            valid = false;
            return;
        }

        valid = true;
        address = ((encoded[0] >> 5) & ((1 << 8) - 1))
                | ((encoded[1] & ((1 << 13) - 1)) << 8)
                | ((((encoded[2] & ((1 << 13) - 1)) >> 10) & ((1 << 3) - 1)) << 21);

        value = 0;
        for (int i=3; i<8; ++i) {
            value |= (((uint64_t)encoded[i] & ((1 << 13) - 1)) << (13*(i-3)));
        }
    }
    std::vector<uint> encode() const {
        std::vector<uint> ret(8);
        // encode data
        ret[0] = (count) | ((address & ((1 << 8) - 1)) << 5);
        ret[1] = (address >> 8) & ((1 << 13) - 1);
        ret[2] = ((address >> 21) << 10);
        for (int i=0; i<5; ++i) {
            ret[3+i] = (value >> (13*i)) & ((1 << 13) - 1);
        }
        ret[2] |= calculated_checksum(ret);
        return ret;
    }
};

std::vector<std::string>
SEAL_Interface::retrieveUint64WithIndicators(const std::vector<std::vector<uint64_t>> &record_batches,
                                             const std::vector<std::string> &indicator_cipher_ids,
                                             const std::vector<std::vector<size_t>> &offsets, std::string key_id,
                                             const json &config) {
    init_SEAL_param(config);
    assert(record_batches.size() == indicator_cipher_ids.size());
    assert(record_batches.size() == offsets.size());
    // prepare rotated indicators once
    std::vector<std::vector<std::string>> rotated_indicator_cipher_ids = std::vector<std::vector<std::string>>();
    for (auto i=0; i<(int)offsets.size(); ++i) {
        std::vector<std::string> cur_rotated_indicator_cipher_ids = std::vector<std::string>();
        for (auto offset: offsets[i]) {
            cur_rotated_indicator_cipher_ids.push_back(rotateRowBatchedCipher(indicator_cipher_ids[i], offset, key_id, config));
        }
        rotated_indicator_cipher_ids.push_back(cur_rotated_indicator_cipher_ids);
    }
    // prepare results
    int half_slot_count = slot_count / 2;
    std::vector<uint> zero_vec(slot_count, 0);


    std::vector<std::vector<std::string>> results(U64_RETRIEVAL_CIPHERTEXT_NUM);
    for (int i=0; i<(int)record_batches.size(); ++i) {
        auto current_record_batch = record_batches[i];
        for (int j=0; j<(int)offsets[i].size(); ++j) {
            auto current_offset = offsets[i][j];
            std::vector<std::vector<uint>> to_be_retrieved(U64_RETRIEVAL_CIPHERTEXT_NUM, std::vector<uint>(slot_count));
            for (int k=0; k<half_slot_count; ++k) {
                if (k < current_record_batch.size()) {
                    // cur_record_batch[(k + current_offset) % half_slot_count] = current_record_batch[k];
                    auto encoded = Uint64Encoding(current_record_batch[k], k + i * slot_count).encode();
                    for (int l=0; l<(int)U64_RETRIEVAL_CIPHERTEXT_NUM; ++l) {
                        to_be_retrieved[l][(k + half_slot_count - current_offset) % half_slot_count] = encoded[l];
                    }
                }
                if (k + half_slot_count < current_record_batch.size()) {
                    // cur_record_batch[((k + current_offset) % half_slot_count) + half_slot_count] = current_record_batch[k + half_slot_count];
                    auto encoded = Uint64Encoding(current_record_batch[k + half_slot_count], k + half_slot_count + i * slot_count).encode();
                    for (int l=0; l<(int)U64_RETRIEVAL_CIPHERTEXT_NUM; ++l) {
                        to_be_retrieved[l][((k + half_slot_count - current_offset) % half_slot_count) + half_slot_count] = encoded[l];
                    }
                }
            }
            for (int k=0; k<(int)U64_RETRIEVAL_CIPHERTEXT_NUM; ++k) {
                auto bc_id = rotated_indicator_cipher_ids[i][j];
                auto plain = to_be_retrieved[k];
                bool all_zero = true;
                for (auto p: plain) {
                    if (p != 0) {
                        all_zero = false;
                        break;
                    }
                }
                if (!all_zero) {
                    results[k].push_back(multiplyBatchedCipherWithPlain(bc_id, plain, config));
                } else {
                    results[k].push_back(batchEncrypt(zero_vec, key_id, config));
                }
            }
        }
    }
    seal::Evaluator evaluator(*ctx);
    std::vector<std::string> ret;
    report_timing("RETRIEVAL-merging", true);
    for (int i=0; i<(int)U64_RETRIEVAL_CIPHERTEXT_NUM; ++i) {
        assert(record_batches.size() * offsets[0].size() == results[i].size());
        seal::Ciphertext* cs = new seal::Ciphertext[results[i].size()];
        for (int j=0; j<(int)results[i].size(); ++j) {
            cs[j] = *batchedCiphers.at(results[i][j]);
        }
        he_balanced_sum_inplace(evaluator, cs, 0, results[i].size());
        seal::Ciphertext* current = new seal::Ciphertext(cs[0]);
        std::string new_bc_id = generate_uuid_v4();
        batchedCiphers[new_bc_id] = current;
        delete[] cs;
        ret.push_back(new_bc_id);
    }
    report_timing("RETRIEVAL-merging", false);
    return ret;
}

std::vector<uint64_t> peel(std::vector<std::vector<uint>>& to_be_decoded, size_t loc, const std::vector<std::vector<size_t>> &offsets, const size_t slot_count) {
    size_t half_slot_count = slot_count / 2;

    auto decoded = Uint64Encoding(to_be_decoded[loc]);
    std::vector<uint64_t> ret;
    if (decoded.valid) {
        ret.push_back(decoded.value);
        // calculate locations to peel
        size_t block_id = decoded.address / slot_count;
        bool sanity = false;
        for (int i=0; i<(int)offsets[block_id].size(); ++i) {
            auto offset = offsets[block_id][i];
            size_t row_offset = (loc >= half_slot_count) ? half_slot_count : 0;
            auto target_loc = row_offset + (decoded.address + half_slot_count - offset) % half_slot_count;
            if (target_loc == loc) {
                assert(sanity == false);
                sanity = true;
                continue;
            }
            for (int j=0; j<(int)SEAL_Interface::U64_RETRIEVAL_CIPHERTEXT_NUM; ++j) {
                to_be_decoded[target_loc][j] += (1 << 17) - to_be_decoded[loc][j];
                to_be_decoded[target_loc][j] &= ((1 << 17) - 1);
            }
        }
        assert(sanity);
        for (int j=0; j<(int)SEAL_Interface::U64_RETRIEVAL_CIPHERTEXT_NUM; ++j) {
            to_be_decoded[loc][j] = 0;
            to_be_decoded[loc][j] = 0;
        }
        for (int i=0; i<(int)offsets[block_id].size(); ++i) {
            auto offset = offsets[block_id][i];
            size_t row_offset = (loc >= half_slot_count) ? half_slot_count : 0;
            auto target_loc = row_offset + (decoded.address + half_slot_count - offset) % half_slot_count;
            auto current = peel(to_be_decoded, target_loc, offsets, slot_count);
            ret.insert(ret.end(), current.begin(), current.end());
        }
    }
    return ret;
}

std::vector<uint64_t> SEAL_Interface::decodeRetrievedUint64(const std::vector<std::string>& retrieved_cipher_ids,
                                                            const std::vector<std::vector<size_t>> &offsets,
                                                            std::string key_id, const json &config) {
    assert(retrieved_cipher_ids.size() == U64_RETRIEVAL_CIPHERTEXT_NUM);
    std::vector<std::vector<uint>> to_be_decoded(slot_count, std::vector<uint>(U64_RETRIEVAL_CIPHERTEXT_NUM));
    for (int i=0; i<(int)retrieved_cipher_ids.size(); ++i) {
        auto retrieved_cipher_id = retrieved_cipher_ids[i];
        auto current = batchDecrypt(retrieved_cipher_id, key_id, config);
        for (int j=0; j<(int)current.size(); ++j) {
            to_be_decoded[j][i] = current[j];
        }
    }
    std::vector<uint64_t> ret;
    for (int i=0; i<(int)slot_count; ++i) {
        auto current = peel(to_be_decoded, i, offsets, slot_count);
        ret.insert(ret.end(), current.begin(), current.end());
    }
    for (int i=0; i<(int)slot_count; ++i) {
        for (int j=0; j<(int)U64_RETRIEVAL_CIPHERTEXT_NUM; ++j) {
            if (to_be_decoded[i][j] != 0) {
                throw std::runtime_error("decoding failed");
            }
        }
    }
    return ret;
}
