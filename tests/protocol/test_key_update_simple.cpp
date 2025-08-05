#include <gtest/gtest.h>
#include <dtls/protocol/handshake.h>
#include <dtls/types.h>

using namespace dtls::v13;
using namespace dtls::v13::protocol;

class KeyUpdateSimpleTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Simple test setup
    }
};

TEST_F(KeyUpdateSimpleTest, KeyUpdateMessageConstruction) {
    // Test default construction
    KeyUpdate default_key_update;
    EXPECT_EQ(default_key_update.update_request(), KeyUpdateRequest::UPDATE_NOT_REQUESTED);
    EXPECT_FALSE(default_key_update.requests_peer_update());
    EXPECT_TRUE(default_key_update.is_valid());
    
    // Test explicit construction
    KeyUpdate request_update(KeyUpdateRequest::UPDATE_REQUESTED);
    EXPECT_EQ(request_update.update_request(), KeyUpdateRequest::UPDATE_REQUESTED);
    EXPECT_TRUE(request_update.requests_peer_update());
    EXPECT_TRUE(request_update.is_valid());
}

TEST_F(KeyUpdateSimpleTest, KeyUpdateRequestEnum) {
    // Test enum values
    EXPECT_EQ(static_cast<uint8_t>(KeyUpdateRequest::UPDATE_NOT_REQUESTED), 0);
    EXPECT_EQ(static_cast<uint8_t>(KeyUpdateRequest::UPDATE_REQUESTED), 1);
}

TEST_F(KeyUpdateSimpleTest, KeyUpdateComparison) {
    KeyUpdate update1(KeyUpdateRequest::UPDATE_NOT_REQUESTED);
    KeyUpdate update2(KeyUpdateRequest::UPDATE_NOT_REQUESTED);
    KeyUpdate update3(KeyUpdateRequest::UPDATE_REQUESTED);
    
    EXPECT_EQ(update1, update2);
    EXPECT_NE(update1, update3);
    EXPECT_NE(update2, update3);
}

TEST_F(KeyUpdateSimpleTest, KeyUpdateHandshakeType) {
    // Verify that KeyUpdate has the correct handshake type
    EXPECT_EQ(static_cast<uint8_t>(HandshakeType::KEY_UPDATE), 24);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}