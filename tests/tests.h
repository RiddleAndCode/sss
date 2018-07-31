#ifndef sss_TESTS_H_
#define sss_TESTS_H_

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#include "sss.h"
#include <assert.h>
#include <string.h>
#include "unity.h"
#include <stdlib.h>
#include <time.h>

int rng(void *buf, size_t n) {
  int rn = 0;
  uint16_t offset = 0;
  while(1) {
    rn = rand();
    memcpy((uint8_t*)buf + offset, (uint8_t*)(&rn), MIN(sizeof(rn), n));
    if(n < sizeof(rn))
      break;
    offset += MIN(sizeof(rn), n);
    n -= sizeof(rn);
  }
  return 1;
}

void test_shares(void);
void test_key_shares(void);

#endif // sss_TESTS_H_