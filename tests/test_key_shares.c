#include "tests.h"

void test_key_shares(void) {
  uint8_t key[32], restored[32];
  sss_Keyshare key_shares[256];
  size_t idx;

  for (idx = 0; idx < 32; idx++) {
    key[idx] = idx;
  }

  sss_create_keyshares(key_shares, key, 1, 1);
  sss_combine_keyshares(restored, (const sss_Keyshare *)key_shares, 1);
  TEST_ASSERT_EQUAL(memcmp(key, restored, 32), 0);

  sss_create_keyshares(key_shares, key, 3, 2);
  sss_combine_keyshares(restored, (const sss_Keyshare *)key_shares[1], 2);
  TEST_ASSERT_EQUAL(memcmp(key, restored, 32), 0);

  sss_create_keyshares(key_shares, key, 255, 127);
  sss_combine_keyshares(restored, (const sss_Keyshare *)key_shares[128], 127);
  TEST_ASSERT_EQUAL(memcmp(key, restored, 32), 0);

  sss_create_keyshares(key_shares, key, 255, 255);
  sss_combine_keyshares(restored, (const sss_Keyshare *)key_shares, 255);
  TEST_ASSERT_EQUAL(memcmp(key, restored, 32), 0);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_key_shares);
  return UNITY_END();
}
