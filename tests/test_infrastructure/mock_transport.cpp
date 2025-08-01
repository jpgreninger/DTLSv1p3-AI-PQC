#include "mock_transport.h"
#include <algorithm>
#include <random>
#include <iostream>
#include <thread>

namespace dtls {
namespace test {

MockTransport::MockTransport(const std::string& local_addr, uint16_t local_port)
    : local_address_(local_addr)
    , local_port_(local_port)
    , random_generator_(random_device_()) {
}

MockTransport::~MockTransport() {
    MockTransport::shutdown();
}

dtls::v13::Result<void> MockTransport::bind() {
    if (bound_.load()) {
        return dtls::v13::make_error<void>(dtls::v13::DTLSError::TRANSPORT_ERROR, "Transport already bound");
    }
    
    bound_.store(true);
    return dtls::v13::make_result();
}

} // namespace test
} // namespace dtls