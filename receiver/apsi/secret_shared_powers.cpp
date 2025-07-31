// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <iterator>
#include <stdexcept>
#include <utility>

// APSI
#include "apsi/log.h"
#include "apsi/secret_shared_powers.h"
#include "apsi/util/utils.h"

using namespace std;

namespace apsi {
    namespace receiver {
        
        SecretSharedPowers::SecretSharedPowers(
            vector<uint64_t> values, const PSIParams &params, const PowersDag &pd)
            : modulus_(params.seal_params().plain_modulus().value())
        {
            if (values.empty()) {
                throw invalid_argument("values cannot be empty");
            }
            
            // Extract required powers from PowersDag
            vector<uint32_t> required_powers = extract_powers(pd);
            if (required_powers.empty()) {
                throw invalid_argument("no powers specified in PowersDag");
            }
            
            // Estimate number of Beaver triples needed
            size_t estimated_triples = values.size() * required_powers.size() * 20;
            
            // Initialize secret sharing manager
            sharing_manager_ = make_unique<SecretSharingManager>(modulus_, estimated_triples);
            
            // Compute shared powers
            compute_shared_powers(move(values), pd);
            
            APSI_LOG_DEBUG("SecretSharedPowers initialized with " << power_shares_.size() 
                          << " power computations");
        }
        
        SecretSharedPowers::~SecretSharedPowers() = default;
        
        vector<uint64_t> SecretSharedPowers::get_party_a_shares() const
        {
            vector<uint64_t> party_a_shares;
            
            for (const auto& power_entry : power_shares_) {
                for (const auto& share_pair : power_entry.second) {
                    party_a_shares.push_back(share_pair.first);
                }
            }
            
            return party_a_shares;
        }
        
        vector<uint64_t> SecretSharedPowers::get_party_b_shares() const
        {
            vector<uint64_t> party_b_shares;
            
            for (const auto& power_entry : power_shares_) {
                for (const auto& share_pair : power_entry.second) {
                    party_b_shares.push_back(share_pair.second);
                }
            }
            
            return party_b_shares;
        }
        
        vector<uint64_t> SecretSharedPowers::combine_shares(
            const vector<uint64_t>& shares_a,
            const vector<uint64_t>& shares_b) const
        {
            vector<uint64_t> combined_result;
            sharing_manager_->combine_polynomial_shares(shares_a, shares_b, combined_result);
            return combined_result;
        }
        
        void SecretSharedPowers::compute_shared_powers(vector<uint64_t> values, const PowersDag &pd)
        {
            auto source_powers = pd.source_nodes();
            
            for (const auto& source : source_powers) {
                uint32_t power = source.power;
                
                // Compute polynomial shares for this power
                vector<pair<uint64_t, uint64_t>> polynomial_shares;
                vector<uint32_t> single_power = { power };
                
                sharing_manager_->compute_polynomial_powers(values, single_power, polynomial_shares);
                
                // Store the shares
                power_shares_[power] = polynomial_shares;
                
                APSI_LOG_DEBUG("Computed secret shared power " << power 
                              << " for " << values.size() << " values");
            }
            
            // Log summary of computed powers
            vector<uint32_t> powers_vec;
            transform(power_shares_.begin(), power_shares_.end(), back_inserter(powers_vec), 
                     [](const auto& p) { return p.first; });
            APSI_LOG_DEBUG("Secret shared powers computed: " << util::to_string(powers_vec));
        }
        
        vector<uint32_t> SecretSharedPowers::extract_powers(const PowersDag &pd)
        {
            vector<uint32_t> powers;
            auto source_powers = pd.source_nodes();
            
            for (const auto& source : source_powers) {
                powers.push_back(source.power);
            }
            
            // Remove duplicates and sort
            sort(powers.begin(), powers.end());
            powers.erase(unique(powers.begin(), powers.end()), powers.end());
            
            return powers;
        }
        
    } // namespace receiver
} // namespace apsi