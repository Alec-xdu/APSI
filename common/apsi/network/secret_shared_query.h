#pragma once

// STD
#include <cstdint>
#include <iostream>
#include <memory>
#include <unordered_map>
#include <vector>

// APSI
#include "apsi/network/sender_operation.h"

namespace apsi {
    namespace network {
        
        /**
         * A kind of SenderOperation for representing a PSI query using secret sharing
         * instead of homomorphic encryption
         */
        class SecretSharedQuery final : public SenderOperation {
        public:
            std::size_t save(std::ostream &out) const override;
            
            std::size_t load(std::istream &in, std::shared_ptr<seal::SEALContext> context) override;
            
            SenderOperationType type() const noexcept override
            {
                return SenderOperationType::sop_query; // Reuse the same type for compatibility
            }
            
            /**
             * Holds the secret shares for party A. In the map the key labels the power
             * and the vector holds the share data for different bundle indices.
             */
            std::unordered_map<std::uint32_t, std::vector<std::vector<std::uint64_t>>> party_a_shares;
            
            /**
             * Holds the secret shares for party B. In the map the key labels the power
             * and the vector holds the share data for different bundle indices.
             */
            std::unordered_map<std::uint32_t, std::vector<std::vector<std::uint64_t>>> party_b_shares;
            
            /**
             * The modulus used for arithmetic operations
             */
            std::uint64_t modulus;
            
        }; // class SecretSharedQuery
        
    } // namespace network
} // namespace apsi