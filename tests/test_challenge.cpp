#include <gtest/gtest.h>
#include "challenge.hpp"
#include <unordered_set>

using namespace entropy;

TEST(ChallengeTest, SeedUniqueness) {
    std::unordered_set<std::string> seeds;
    for (int i = 0; i < 100; ++i) {
        std::string seed = ChallengeGenerator::generate_seed();
        EXPECT_EQ(seed.length(), 64); 
        EXPECT_TRUE(seeds.insert(seed).second) << "Duplicate seed generated: " << seed;
    }
}

TEST(ChallengeTest, SeedDifferentiation) {
    std::string s1 = ChallengeGenerator::generate_seed();
    std::string s2 = ChallengeGenerator::generate_seed();
    EXPECT_NE(s1, s2);
}
