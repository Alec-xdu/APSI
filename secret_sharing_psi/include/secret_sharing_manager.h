#pragma once

// STD
#include <vector>
#include <cstdint>
#include <random>
#include <memory>
#include <utility>

// OpenSSL
#include <openssl/rand.h>
#include <openssl/evp.h>

namespace secret_sharing_psi {
    
    /**
     * Beaver triple structure for secret sharing multiplication
     */
    struct BeaverTriple {
        std::uint64_t a0, b0, c0;  // Party A's share
        std::uint64_t a1, b1, c1;  // Party B's share
    };
    
    /**
     * Secret sharing manager class that implements TEE-based secret slice distribution
     * using Beaver triples for arithmetic secret sharing multiplication
     */
    class SecretSharingManager {
    public:
        /**
         * Constructor
         * @param modulus The modulus for arithmetic operations
         * @param num_triples Number of Beaver triples to generate
         */
        SecretSharingManager(std::uint64_t modulus, std::size_t num_triples);
        
        /**
         * Destructor
         */
        ~SecretSharingManager();
        
        /**
         * Generate and distribute seeds to party A and party B
         * @param seed_a Output seed for party A
         * @param seed_b Output seed for party B
         */
        void distribute_seeds(std::vector<std::uint8_t>& seed_a, std::vector<std::uint8_t>& seed_b);
        
        /**
         * Generate Beaver triples using the distributed seeds
         * @param seed_a Seed for party A
         * @param seed_b Seed for party B
         * @param triples Output vector of Beaver triples
         */
        void generate_beaver_triples(
            const std::vector<std::uint8_t>& seed_a,
            const std::vector<std::uint8_t>& seed_b,
            std::vector<BeaverTriple>& triples);
        
        /**
         * Perform secret sharing multiplication using Beaver triples
         * @param x_shares Input shares of first operand (x0, x1)
         * @param y_shares Input shares of second operand (y0, y1)  
         * @param triple Beaver triple for multiplication
         * @param result_shares Output shares of multiplication result
         */
        void multiply_shares(
            const std::pair<std::uint64_t, std::uint64_t>& x_shares,
            const std::pair<std::uint64_t, std::uint64_t>& y_shares,
            const BeaverTriple& triple,
            std::pair<std::uint64_t, std::uint64_t>& result_shares);
        
        /**
         * Compute polynomial powers using secret sharing
         * @param values Input values to compute powers for
         * @param powers Powers to compute
         * @param polynomial_shares Output polynomial coefficient shares
         */
        void compute_polynomial_powers(
            const std::vector<std::uint64_t>& values,
            const std::vector<std::uint32_t>& powers,
            std::vector<std::pair<std::uint64_t, std::uint64_t>>& polynomial_shares);
        
        /**
         * Combine shares to get final polynomial result
         * @param shares_a Party A's polynomial shares
         * @param shares_b Party B's polynomial shares
         * @param result Final polynomial coefficients
         */
        void combine_polynomial_shares(
            const std::vector<std::uint64_t>& shares_a,
            const std::vector<std::uint64_t>& shares_b,
            std::vector<std::uint64_t>& result);
        
        /**
         * Get the modulus used for arithmetic operations
         */
        std::uint64_t get_modulus() const { return modulus_; }
        
        /**
         * Get the number of triples this manager can generate
         */
        std::size_t get_num_triples() const { return num_triples_; }
        
    private:
        std::uint64_t modulus_;
        std::size_t num_triples_;
        std::mt19937_64 rng_;
        
        // Seed length in bytes
        static constexpr std::size_t SEED_LENGTH = 32;
        
        /**
         * Generate secure random seed using OpenSSL
         * @param seed Output seed buffer
         */
        void generate_secure_seed(std::vector<std::uint8_t>& seed);
        
        /**
         * Initialize RNG with seed
         * @param seed Input seed
         * @param rng Output RNG
         */
        void init_rng_with_seed(const std::vector<std::uint8_t>& seed, std::mt19937_64& rng);
        
        /**
         * Modular arithmetic operations
         */
        std::uint64_t mod_add(std::uint64_t a, std::uint64_t b) const;
        std::uint64_t mod_sub(std::uint64_t a, std::uint64_t b) const;
        std::uint64_t mod_mul(std::uint64_t a, std::uint64_t b) const;
    };
    
} // namespace secret_sharing_psi