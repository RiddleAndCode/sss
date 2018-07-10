#include "tests.h"

void test_shares(void) {
  unsigned char data[sss_MLEN] = {42}, restored[sss_MLEN];
  sss_Share shares[256];
  int tmp;

  /* Normal operation */
  sss_create_shares(shares, data, 1, 1);
  tmp = sss_combine_shares(restored, (const sss_Share *)shares, 1);
  TEST_ASSERT_EQUAL(tmp, 0);
  TEST_ASSERT_EQUAL(memcmp(restored, data, sss_MLEN), 0);

  /* A lot of shares */
  sss_create_shares(shares, data, 255, 255);
  tmp = sss_combine_shares(restored, (const sss_Share *)shares, 255);
  TEST_ASSERT_EQUAL(tmp, 0);
  TEST_ASSERT_EQUAL(memcmp(restored, data, sss_MLEN), 0);

  /* Not enough shares to restore secret */
  sss_create_shares(shares, data, 100, 100);
  tmp = sss_combine_shares(restored, (const sss_Share *)shares, 99);
  TEST_ASSERT_EQUAL(tmp, -1);

  /* Too many secrets should also restore the secret */
  sss_create_shares(shares, data, 200, 100);
  tmp = sss_combine_shares(restored, (const sss_Share *)shares, 200);
  TEST_ASSERT_EQUAL(tmp, 0);
  TEST_ASSERT_EQUAL(memcmp(restored, data, sss_MLEN), 0);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_shares);
  return UNITY_END();
}
