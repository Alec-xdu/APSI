#pragma once

// STD
#include <cstdint>
#include <unordered_map>
#include <vector>
#include <memory>

// APSI
#include "apsi/crypto_context.h"
#include "apsi/powers.h"
#include "apsi/psi_params.h"
#include "apsi/secret_sharing_manager.h"

// SEAL
#include "seal/modulus.h"

namespace apsi {
    namespace receiver {
        
        /**
         * SecretSharedPowers replaces PlaintextPowers to use secret sharing
         * instead of homomorphic encryption for computing polynomial powers
         */
        class SecretSharedPowers {
        public:
            /**
             * Constructor
             * @param values Input values to compute powers for
             * @param params PSI parameters
             * @param pd Powers DAG specifying which powers to compute
             */
            SecretSharedPowers(
                std::vector<std::uint64_t> values, 
                const PSIParams &params, 
                const PowersDag &pd);
            
            /**
             * Destructor
             */
            ~SecretSharedPowers();
            
            /**
             * Get the polynomial coefficient shares for party A
             * @return Vector of shares for party A
             */
            std::vector<std::uint64_t> get_party_a_shares() const;
            
            /**
             * Get the polynomial coefficient shares for party B
             * @return Vector of shares for party B
             */
            std::vector<std::uint64_t> get_party_b_shares() const;
            
            /**
             * Combine shares from both parties to get final polynomial coefficients
             * @param shares_a Party A's shares
             * @param shares_b Party B's shares
             * @return Final polynomial coefficients
             */
            std::vector<std::uint64_t> combine_shares(
                const std::vector<std::uint64_t>& shares_a,
                const std::vector<std::uint64_t>& shares_b) const;
            
            /**
             * Get the modulus used for arithmetic operations
             * @return The modulus
             */
            std::uint64_t get_modulus() const { return modulus_; }
            
            /**
             * Get the number of computed powers
             * @return Number of powers
             */
            std::size_t get_num_powers() const { return power_shares_.size(); }
            
        private:
            std::uint64_t modulus_;
            std::unique_ptr<SecretSharingManager> sharing_manager_;
            
            // Store polynomial coefficient shares as pairs (party_a_share, party_b_share)
            std::unordered_map<std::uint32_t, std::vector<std::pair<std::uint64_t, std::uint64_t>>> power_shares_;
            
            /**
             * Compute powers using secret sharing
             * @param values Input values
             * @param pd Powers DAG
             */
            void compute_shared_powers(std::vector<std::uint64_t> values, const PowersDag &pd);
            
            /**
             * Extract powers from PowersDag
             * @param pd Powers DAG
             * @return Vector of required powers
             */
            std::vector<std::uint32_t> extract_powers(const PowersDag &pd);
        };
        
    } // namespace receiver
} // namespace apsi