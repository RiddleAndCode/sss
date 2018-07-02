#include "tests.h"

void test_shares(void)
{
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

void test_key_shares(void)
{
    uint8_t key[32], restored[32];
    sss_Keyshare key_shares[256];
    size_t idx;

    for (idx = 0; idx < 32; idx++)
    {
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

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_shares);
    RUN_TEST(test_key_shares);
    return UNITY_END();
}