// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <stdexcept>

// APSI
#include "apsi/network/secret_shared_query.h"

using namespace std;

namespace apsi {
    namespace network {
        
        size_t SecretSharedQuery::save(ostream &out) const
        {
            size_t bytes_written = 0;
            
            // Write modulus
            out.write(reinterpret_cast<const char*>(&modulus), sizeof(modulus));
            bytes_written += sizeof(modulus);
            
            // Write party A shares
            uint32_t party_a_size = static_cast<uint32_t>(party_a_shares.size());
            out.write(reinterpret_cast<const char*>(&party_a_size), sizeof(party_a_size));
            bytes_written += sizeof(party_a_size);
            
            for (const auto& power_shares : party_a_shares) {
                // Write power key
                out.write(reinterpret_cast<const char*>(&power_shares.first), sizeof(power_shares.first));
                bytes_written += sizeof(power_shares.first);
                
                // Write number of bundles
                uint32_t num_bundles = static_cast<uint32_t>(power_shares.second.size());
                out.write(reinterpret_cast<const char*>(&num_bundles), sizeof(num_bundles));
                bytes_written += sizeof(num_bundles);
                
                // Write each bundle's shares
                for (const auto& bundle_shares : power_shares.second) {
                    uint32_t bundle_size = static_cast<uint32_t>(bundle_shares.size());
                    out.write(reinterpret_cast<const char*>(&bundle_size), sizeof(bundle_size));
                    bytes_written += sizeof(bundle_size);
                    
                    out.write(reinterpret_cast<const char*>(bundle_shares.data()), 
                             bundle_size * sizeof(uint64_t));
                    bytes_written += bundle_size * sizeof(uint64_t);
                }
            }
            
            // Write party B shares (same structure as party A)
            uint32_t party_b_size = static_cast<uint32_t>(party_b_shares.size());
            out.write(reinterpret_cast<const char*>(&party_b_size), sizeof(party_b_size));
            bytes_written += sizeof(party_b_size);
            
            for (const auto& power_shares : party_b_shares) {
                // Write power key
                out.write(reinterpret_cast<const char*>(&power_shares.first), sizeof(power_shares.first));
                bytes_written += sizeof(power_shares.first);
                
                // Write number of bundles
                uint32_t num_bundles = static_cast<uint32_t>(power_shares.second.size());
                out.write(reinterpret_cast<const char*>(&num_bundles), sizeof(num_bundles));
                bytes_written += sizeof(num_bundles);
                
                // Write each bundle's shares
                for (const auto& bundle_shares : power_shares.second) {
                    uint32_t bundle_size = static_cast<uint32_t>(bundle_shares.size());
                    out.write(reinterpret_cast<const char*>(&bundle_size), sizeof(bundle_size));
                    bytes_written += sizeof(bundle_size);
                    
                    out.write(reinterpret_cast<const char*>(bundle_shares.data()), 
                             bundle_size * sizeof(uint64_t));
                    bytes_written += bundle_size * sizeof(uint64_t);
                }
            }
            
            return bytes_written;
        }
        
        size_t SecretSharedQuery::load(istream &in, shared_ptr<seal::SEALContext> /* context */)
        {
            size_t bytes_read = 0;
            
            // Read modulus
            in.read(reinterpret_cast<char*>(&modulus), sizeof(modulus));
            bytes_read += sizeof(modulus);
            
            // Read party A shares
            uint32_t party_a_size;
            in.read(reinterpret_cast<char*>(&party_a_size), sizeof(party_a_size));
            bytes_read += sizeof(party_a_size);
            
            party_a_shares.clear();
            for (uint32_t i = 0; i < party_a_size; ++i) {
                // Read power key
                uint32_t power_key;
                in.read(reinterpret_cast<char*>(&power_key), sizeof(power_key));
                bytes_read += sizeof(power_key);
                
                // Read number of bundles
                uint32_t num_bundles;
                in.read(reinterpret_cast<char*>(&num_bundles), sizeof(num_bundles));
                bytes_read += sizeof(num_bundles);
                
                vector<vector<uint64_t>> bundles;
                bundles.reserve(num_bundles);
                
                // Read each bundle's shares
                for (uint32_t j = 0; j < num_bundles; ++j) {
                    uint32_t bundle_size;
                    in.read(reinterpret_cast<char*>(&bundle_size), sizeof(bundle_size));
                    bytes_read += sizeof(bundle_size);
                    
                    vector<uint64_t> bundle_shares(bundle_size);
                    in.read(reinterpret_cast<char*>(bundle_shares.data()), 
                           bundle_size * sizeof(uint64_t));
                    bytes_read += bundle_size * sizeof(uint64_t);
                    
                    bundles.push_back(move(bundle_shares));
                }
                
                party_a_shares[power_key] = move(bundles);
            }
            
            // Read party B shares (same structure as party A)
            uint32_t party_b_size;
            in.read(reinterpret_cast<char*>(&party_b_size), sizeof(party_b_size));
            bytes_read += sizeof(party_b_size);
            
            party_b_shares.clear();
            for (uint32_t i = 0; i < party_b_size; ++i) {
                // Read power key
                uint32_t power_key;
                in.read(reinterpret_cast<char*>(&power_key), sizeof(power_key));
                bytes_read += sizeof(power_key);
                
                // Read number of bundles
                uint32_t num_bundles;
                in.read(reinterpret_cast<char*>(&num_bundles), sizeof(num_bundles));
                bytes_read += sizeof(num_bundles);
                
                vector<vector<uint64_t>> bundles;
                bundles.reserve(num_bundles);
                
                // Read each bundle's shares
                for (uint32_t j = 0; j < num_bundles; ++j) {
                    uint32_t bundle_size;
                    in.read(reinterpret_cast<char*>(&bundle_size), sizeof(bundle_size));
                    bytes_read += sizeof(bundle_size);
                    
                    vector<uint64_t> bundle_shares(bundle_size);
                    in.read(reinterpret_cast<char*>(bundle_shares.data()), 
                           bundle_size * sizeof(uint64_t));
                    bytes_read += bundle_size * sizeof(uint64_t);
                    
                    bundles.push_back(move(bundle_shares));
                }
                
                party_b_shares[power_key] = move(bundles);
            }
            
            return bytes_read;
        }
        
    } // namespace network
} // namespace apsi