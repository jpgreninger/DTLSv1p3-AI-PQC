#include <dtls/connection.h>
#include <dtls/crypto/provider_factory.h>
#include <iostream>

using namespace dtls::v13;

int main() {
    // Test that the record layer integration compiles and basic instantiation works
    try {
        auto crypto_provider = crypto::ProviderFactory::instance().create_default_provider();
        if (!crypto_provider) {
            std::cout << "Failed to create crypto provider" << std::endl;
            return 1;
        }
        
        ConnectionConfig config;
        NetworkAddress server_addr("127.0.0.1", 12345);
        
        auto connection_result = Connection::create_client(
            config,
            std::move(crypto_provider.value()),
            server_addr
        );
        
        if (!connection_result) {
            std::cout << "Failed to create connection" << std::endl;
            return 1;
        }
        
        auto connection = std::move(connection_result.value());
        
        // Test initialization (this will exercise record layer creation)
        auto init_result = connection->initialize();
        if (!init_result) {
            std::cout << "Failed to initialize connection" << std::endl;
            return 1;
        }
        
        std::cout << "Record layer integration test PASSED" << std::endl;
        return 0;
        
    } catch (const std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
        return 1;
    }
}