/*
 * Copyright (c) 2014-2018 Cesanta Software Limited
 * All rights reserved
 *
 * Licensed under the Apache License, Version 2.0 (the ""License"");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an ""AS IS"" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "bts_data_store_ram.h"

#include <stdlib.h>
#include <time.h>

#include "common/cs_dbg.h"
#include "common/cs_varint.h"
#include "common/test_main.h"
#include "common/test_util.h"

#include "bts_data_store_test_util.h"

static const char *test_basic(void) {
  struct bts_data_store ds;
  struct bts_data_store_ram_ctx ctx;
  uint8_t buf[16] = {0};
  int i = 0;
  struct mg_str data;
  memset(&ds, 0, sizeof(ds));
  memset(&ctx, 0, sizeof(ctx));
  ds.ctx = &ctx;
  ASSERT_TRUE(bts_data_store_ram_init_with_buffer(&ds, buf, sizeof(buf)));
  struct bts_data_store_stats stats;
  ds.ops->get_stats(&ds, &stats);
  ASSERT_EQ(stats.num_records, 0);
  ASSERT_EQ(stats.bytes_used, 0);
  ASSERT_EQ(stats.bytes_free, 16);
  /* zero-size records are not allowed */
  CHECK_CALL(push_back(&ds, i++, "", BTS_DATA_STATUS_ERR_SIZE));
  CHECK_CALL(push_back(&ds, i++, "foo", BTS_DATA_STATUS_OK));
  CHECK_CALL(push_back(&ds, i++, "bar", BTS_DATA_STATUS_OK));
  ds.ops->get_stats(&ds, &stats);
  ASSERT_EQ(stats.num_records, 2);
  ASSERT_EQ(stats.bytes_used, 8);
  ASSERT_EQ(stats.bytes_free, 8);
  CHECK_CALL(pop_front(&ds, i++, "foo", BTS_DATA_STATUS_OK));
  CHECK_CALL(push_back(&ds, i++, "baz", BTS_DATA_STATUS_OK));
  CHECK_CALL(push_back(&ds, i++, "hello", BTS_DATA_STATUS_OK));
  CHECK_CALL(push_back(&ds, i++, "hi", BTS_DATA_STATUS_ERR_SIZE));
  CHECK_CALL(push_back(&ds, i++, "!", BTS_DATA_STATUS_OK));
  ds.ops->get_stats(&ds, &stats);
  ASSERT_EQ(stats.num_records, 4);
  ASSERT_EQ(stats.bytes_used, 16);
  ASSERT_EQ(stats.bytes_free, 0);
  CHECK_CALL(pop_front(&ds, i++, "bar", BTS_DATA_STATUS_OK));
  CHECK_CALL(pop_front(&ds, i++, "baz", BTS_DATA_STATUS_OK));
  CHECK_CALL(push_back(&ds, i++, "bazooka", BTS_DATA_STATUS_OK));
  ASSERT_EQ(ds.ops->pop_front(&ds, 0, &data), BTS_DATA_STATUS_ERR_SIZE);
  ASSERT_EQ(ds.ops->pop_front(&ds, 1, &data), BTS_DATA_STATUS_ERR_SIZE);
  ASSERT_EQ(ds.ops->pop_front(&ds, 4, &data), BTS_DATA_STATUS_ERR_SIZE);
  CHECK_CALL(pop_front(&ds, i++, "hello", BTS_DATA_STATUS_OK));
  ASSERT_EQ(ds.ops->pop_front(&ds, 0, &data), BTS_DATA_STATUS_ERR_SIZE);
  CHECK_CALL(pop_front(&ds, i++, "!", BTS_DATA_STATUS_OK));
  CHECK_CALL(pop_front(&ds, i++, "bazooka", BTS_DATA_STATUS_OK));
  ds.ops->get_stats(&ds, &stats);
  ASSERT_EQ(stats.num_records, 0);
  ASSERT_EQ(stats.bytes_used, 0);
  ASSERT_EQ(stats.bytes_free, 16);
  ASSERT_EQ(ds.ops->pop_front(&ds, ~0, &data), BTS_DATA_STATUS_ERR_EMPTY);

  CHECK_CALL(push_back(&ds, i++, "plop", BTS_DATA_STATUS_OK));
  CHECK_CALL(pop_front(&ds, i++, "plop", BTS_DATA_STATUS_OK));

  bts_data_store_ram_deinit(&ctx);

  return NULL;
}

#define TEST_MEM_SIZE 4093
#define MAX_LEN 300
#define NUM_ITERATIONS 200000

static const struct mgos_config_bts_data_ram s_cfg = {
    .size = TEST_MEM_SIZE,
};

static struct bts_data_store *create_ram_ds(const struct mg_str meta) {
  (void) meta;
  return bts_data_store_ram_create(&s_cfg);
}

static const char *test_random(void) {
  CHECK_CALL(random_test(create_ram_ds, MAX_LEN, NUM_ITERATIONS,
                         false /* test_reload */));
  return NULL;
}

void tests_setup(void) {
}

const char *tests_run(const char *filter) {
  cs_log_set_level(LL_DEBUG);
  RUN_TEST(test_basic);
  cs_log_set_level(LL_INFO);
  RUN_TEST(test_random);
  return NULL;
}

void tests_teardown(void) {
}
