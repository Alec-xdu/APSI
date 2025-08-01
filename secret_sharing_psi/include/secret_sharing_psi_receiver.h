#pragma once

// STD
#include <vector>
#include <string>
#include <unordered_set>
#include <memory>
#include <cstdint>

// Project
#include "secret_sharing_manager.h"

namespace secret_sharing_psi {
    
    /**
     * Simple item representation for PSI
     */
    class Item {
    public:
        Item() = default;
        explicit Item(const std::string& data);
        explicit Item(std::uint64_t value);
        
        std::uint64_t to_uint64() const { return value_; }
        std::string to_string() const;
        
        bool operator==(const Item& other) const { return value_ == other.value_; }
        bool operator!=(const Item& other) const { return value_ != other.value_; }
        
    private:
        std::uint64_t value_ = 0;
        
        void hash_string_to_value(const std::string& data);
    };
    
    /**
     * Secret Sharing PSI Receiver implementation
     * This class implements the receiver side of the PSI protocol using secret sharing
     * instead of homomorphic encryption
     */
    class SecretSharingPSIReceiver {
    public:
        /**
         * Constructor
         * @param modulus The modulus for field operations
         * @param max_items Maximum number of items to handle
         */
        SecretSharingPSIReceiver(std::uint64_t modulus, std::size_t max_items);
        
        /**
         * Destructor
         */
        ~SecretSharingPSIReceiver();
        
        /**
         * Set the receiver's items
         * @param items Vector of items for PSI
         */
        void set_items(const std::vector<Item>& items);
        
        /**
         * Set the receiver's items from strings
         * @param item_strings Vector of string items
         */
        void set_items(const std::vector<std::string>& item_strings);
        
        /**
         * Create PSI query using secret sharing
         * @param powers Powers to compute for polynomial
         * @return Query data structure containing secret shares
         */
        struct QueryData {
            std::vector<std::uint8_t> seed_a;
            std::vector<std::uint8_t> seed_b;
            std::vector<std::pair<std::uint64_t, std::uint64_t>> polynomial_shares;
            std::vector<std::uint32_t> powers;
            std::uint64_t modulus;
        };
        
        QueryData create_query(const std::vector<std::uint32_t>& powers);
        
        /**
         * Process response from sender and compute intersection
         * @param sender_shares Sender's polynomial shares
         * @param query_data Original query data
         * @return Set of items in intersection
         */
        std::unordered_set<Item> process_response(
            const std::vector<std::uint64_t>& sender_shares,
            const QueryData& query_data);
        
        /**
         * Get the receiver's items
         */
        const std::vector<Item>& get_items() const { return items_; }
        
        /**
         * Get the modulus
         */
        std::uint64_t get_modulus() const { return modulus_; }
        
    private:
        std::uint64_t modulus_;
        std::size_t max_items_;
        std::vector<Item> items_;
        std::unique_ptr<SecretSharingManager> sharing_manager_;
        
        /**
         * Convert items to field elements
         */
        std::vector<std::uint64_t> items_to_field_elements() const;
        
        /**
         * Evaluate polynomial at given points
         */
        std::vector<std::uint64_t> evaluate_polynomial(
            const std::vector<std::uint64_t>& coefficients,
            const std::vector<std::uint64_t>& points) const;
    };
    
} // namespace secret_sharing_psi

// Hash function for Item to use in unordered_set
namespace std {
    template<>
    struct hash<secret_sharing_psi::Item> {
        std::size_t operator()(const secret_sharing_psi::Item& item) const {
            return std::hash<std::uint64_t>()(item.to_uint64());
        }
    };
}