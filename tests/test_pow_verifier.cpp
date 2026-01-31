#include <gtest/gtest.h>
#include "pow_verifier.hpp"
#include "metrics.hpp"

using namespace entropy;

class PoWVerifierTest : public ::testing::Test {
protected:
    void SetUp() override {
        
        MetricsRegistry::instance().set_gauge("active_connections", 0);
    }
};

TEST_F(PoWVerifierTest, DifficultyCalculations) {
    
    EXPECT_EQ(PoWVerifier::get_required_difficulty(), 4);
    
    
    EXPECT_EQ(PoWVerifier::get_required_difficulty(2), 6);
    
    
    EXPECT_EQ(PoWVerifier::get_required_difficulty(0, 3000000), 3); 
    EXPECT_EQ(PoWVerifier::get_required_difficulty(0, 16000000), 2); 
    
    
    MetricsRegistry::instance().set_gauge("active_connections", 1500);
    EXPECT_EQ(PoWVerifier::get_required_difficulty(), 6); 
    
    MetricsRegistry::instance().set_gauge("active_connections", 6000);
    EXPECT_EQ(PoWVerifier::get_required_difficulty(), 7); 
}

TEST_F(PoWVerifierTest, NicknameDifficulty) {
    
    EXPECT_EQ(PoWVerifier::get_difficulty_for_nickname("verylongnickname"), 4);
    EXPECT_EQ(PoWVerifier::get_difficulty_for_nickname("shorty"), 6); 
    EXPECT_EQ(PoWVerifier::get_difficulty_for_nickname("abc"), 7); 
}

TEST_F(PoWVerifierTest, Verification) {
    
    
    
    std::string seed = "test_seed";
    std::string context = "test_context";
    
    
    EXPECT_FALSE(PoWVerifier::verify(seed, "wrong_nonce", context, 10));
}


std::string solve_pow(const std::string& seed, const std::string& context, int difficulty) {
    for (int i = 0; i < 1000000; ++i) {
        std::string nonce = std::to_string(i);
        if (PoWVerifier::verify(seed, nonce, context, difficulty)) {
            return nonce;
        }
    }
    return "";
}

TEST_F(PoWVerifierTest, SuccessfulVerification) {
    std::string seed = "seed123";
    std::string context = "ctx";
    int diff = 2; 
    
    std::string nonce = solve_pow(seed, context, diff);
    ASSERT_FALSE(nonce.empty());
    EXPECT_TRUE(PoWVerifier::verify(seed, nonce, context, diff));
}
