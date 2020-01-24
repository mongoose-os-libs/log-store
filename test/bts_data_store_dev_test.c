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

#include "bts_data_store_dev.h"

#include <stdlib.h>
#include <time.h>

#include "common/cs_dbg.h"
#include "common/str_util.h"
#include "common/test_util.h"

#include "mgos_vfs_dev_ram.h"

#include "bts_data_store_test_util.h"

static const char *test_basic_no_meta(void) {
  struct mgos_config_bts_data_dev cfg = {
      .type = MGOS_VFS_DEV_TYPE_RAM,
      .opts = "{size: 30, fill_byte: 0, flash_check: true}",
      .block_size = 10,
      .meta_blocks = 0,
  };
  struct bts_data_store *ds =
      bts_data_store_dev_create(&cfg, mg_mk_str(NULL), NULL);
  ASSERT(ds != NULL);
  int i = 0;
  struct mg_str data;
  struct bts_data_store_stats stats;
  ds->ops->get_stats(ds, &stats);
  ASSERT_EQ(stats.num_records, 0);
  ASSERT_EQ(stats.bytes_used, 0);
  ASSERT_EQ(stats.bytes_free, 30);
  // Zero-size records are not allowed.
  CHECK_CALL(push_back(ds, i++, "", BTS_DATA_STATUS_ERR_SIZE));
  CHECK_CALL(pop_front(ds, i++, NULL, BTS_DATA_STATUS_ERR_EMPTY));
  CHECK_CALL(push_back(ds, i++, "foo!", BTS_DATA_STATUS_OK));
  CHECK_CALL(pop_front_str(ds, i++, 1, BTS_DATA_STATUS_ERR_SIZE, &data));
  CHECK_CALL(pop_front_str(ds, i++, 3, BTS_DATA_STATUS_ERR_SIZE, &data));
  CHECK_CALL(push_back(ds, i++, "bar!", BTS_DATA_STATUS_OK));
  // At the block boundary now.
  ds->ops->get_stats(ds, &stats);
  ASSERT_EQ(stats.num_records, 2);
  ASSERT_EQ(stats.bytes_used, 10);
  ASSERT_EQ(stats.bytes_free, 20);

  // Records > block size (incl. length) are not supported.
  CHECK_CALL(push_back(ds, i++, "123456789ab", BTS_DATA_STATUS_ERR_SIZE));
  CHECK_CALL(push_back(ds, i++, "123456789a", BTS_DATA_STATUS_ERR_SIZE));
  CHECK_CALL(push_back(ds, i++, "123456789", BTS_DATA_STATUS_OK));
  // Two full blocks used.
  ds->ops->get_stats(ds, &stats);
  ASSERT_EQ(stats.num_records, 3);
  ASSERT_EQ(stats.bytes_used, 20);
  ASSERT_EQ(stats.bytes_free, 10);

  CHECK_CALL(push_back(ds, i++, "8765432", BTS_DATA_STATUS_OK));
  CHECK_CALL(push_back(ds, i++, "10", BTS_DATA_STATUS_ERR_SIZE));
  ds->ops->get_stats(ds, &stats);
  ASSERT_EQ(stats.num_records, 4);
  ASSERT_EQ(stats.bytes_used, 28);
  ASSERT_EQ(stats.bytes_free, 2);

  CHECK_CALL(pop_front(ds, i++, "foo!", BTS_DATA_STATUS_OK));
  /*
   * Even though we popped a record, space is not yet available because tail
   * cannot follow head in the same block.
   */
  ds->ops->get_stats(ds, &stats);
  ASSERT_EQ(stats.num_records, 3);
  ASSERT_EQ(stats.bytes_used, 28);
  ASSERT_EQ(stats.bytes_free, 2);
  // Can't push yet.
  CHECK_CALL(push_back(ds, i++, "10", BTS_DATA_STATUS_ERR_SIZE));

  CHECK_CALL(pop_front(ds, i++, "bar!", BTS_DATA_STATUS_OK));
  ds->ops->get_stats(ds, &stats);
  ASSERT_EQ(stats.num_records, 2);
  ASSERT_EQ(stats.bytes_used, 18);
  ASSERT_EQ(stats.bytes_free, 12);
  // Now it's ok.
  CHECK_CALL(push_back(ds, i++, "10", BTS_DATA_STATUS_OK));
  ds->ops->get_stats(ds, &stats);
  ASSERT_EQ(stats.num_records, 3);
  ASSERT_EQ(stats.bytes_used, 23 /* 2 for padding at the end */);
  ASSERT_EQ(stats.bytes_free, 7);

  CHECK_CALL(pop_front(ds, i++, "123456789", BTS_DATA_STATUS_OK));
  CHECK_CALL(pop_front(ds, i++, "8765432", BTS_DATA_STATUS_OK));
  CHECK_CALL(pop_front(ds, i++, "10", BTS_DATA_STATUS_OK));

  ds->ops->get_stats(ds, &stats);
  ASSERT_EQ(stats.num_records, 0);
  ASSERT_EQ(stats.bytes_used, 3);
  ASSERT_EQ(stats.bytes_free, 27);

  CHECK_CALL(push_back(ds, i++, "aa", BTS_DATA_STATUS_OK));
  CHECK_CALL(pop_front(ds, i++, "aa", BTS_DATA_STATUS_OK));

  ds->ops->get_stats(ds, &stats);
  ASSERT_EQ(stats.num_records, 0);
  ASSERT_EQ(stats.bytes_used, 6);
  ASSERT_EQ(stats.bytes_free, 24);

  ds->ops->destroy(ds);

  return NULL;
}

static const char *test_basic_meta(void) {
  struct mgos_vfs_dev *dev = mgos_vfs_dev_create(
      MGOS_VFS_DEV_TYPE_RAM, "{size: 400, fill_byte: 0, flash_check: true}");
  ASSERT(dev != NULL);
  const struct mgos_config_bts_data_dev cfg = {
      .block_size = 80, .meta_blocks = 2,
  };
  struct bts_data_store *ds =
      bts_data_store_dev_create(&cfg, mg_mk_str(NULL), dev);
  ASSERT(ds != NULL);
  int i = 0;
  struct bts_data_store_stats stats;
  ds->ops->get_stats(ds, &stats);
  ASSERT_EQ(stats.num_records, 0);
  ASSERT_EQ(stats.bytes_used, 0);
  ASSERT_EQ(stats.bytes_free, 240);

  CHECK_CALL(pop_front(ds, i++, NULL, BTS_DATA_STATUS_ERR_EMPTY));

  CHECK_CALL(push_back(ds, i++, "foo", BTS_DATA_STATUS_OK));
  ASSERT_TRUE(ds->ops->flush(ds));
  CHECK_CALL(push_back(ds, i++, "bar", BTS_DATA_STATUS_OK));
  ASSERT_TRUE(ds->ops->flush(ds));

  ds->ops->destroy(ds);
  ds = bts_data_store_dev_create(&cfg, mg_mk_str(NULL), dev);
  ASSERT(ds != NULL);

  ds->ops->get_stats(ds, &stats);
  ASSERT_EQ(stats.num_records, 2);
  ASSERT_EQ(stats.bytes_used, 8);
  ASSERT_EQ(stats.bytes_free, 232);

  CHECK_CALL(pop_front(ds, i++, "foo", BTS_DATA_STATUS_OK));
  ds->ops->get_stats(ds, &stats);
  ASSERT_EQ(stats.num_records, 1);
  ASSERT_EQ(stats.bytes_used, 8);
  ASSERT_EQ(stats.bytes_free, 232);

  // State was not saved, should roll back to previous.
  ds->ops->destroy(ds);
  ds = bts_data_store_dev_create(&cfg, mg_mk_str(NULL), dev);
  ASSERT(ds != NULL);
  CHECK_CALL(pop_front(ds, i++, "foo", BTS_DATA_STATUS_OK));

  struct mg_str meta;
  ASSERT_TRUE(ds->ops->get_meta(ds, &meta));
  ASSERT_EQ(meta.len, 29);

  ds->ops->destroy(ds);
  ds = bts_data_store_dev_create(&cfg, meta, dev);
  ASSERT(ds != NULL);
  free((void *) meta.p);
  memset(&meta, 0, sizeof(meta));
  // Meta passed externally takes precedence, if valid.
  CHECK_CALL(pop_front(ds, i++, "bar", BTS_DATA_STATUS_OK));

  ds->ops->destroy(ds);
  ds = bts_data_store_dev_create(&cfg, meta, dev);
  ASSERT(ds != NULL);
  // But if not, it is ignored and loaded from the meta arena.
  CHECK_CALL(pop_front(ds, i++, "foo", BTS_DATA_STATUS_OK));
  CHECK_CALL(pop_front(ds, i++, "bar", BTS_DATA_STATUS_OK));

  CHECK_CALL(pop_front(ds, i++, NULL, BTS_DATA_STATUS_ERR_EMPTY));
  ds->ops->get_stats(ds, &stats);
  ASSERT_EQ(stats.num_records, 0);
  ASSERT_EQ(stats.bytes_used, 8);
  ASSERT_EQ(stats.bytes_free, 232);

  ASSERT_TRUE(ds->ops->flush(ds));

  CHECK_CALL(pop_front(ds, i++, NULL, BTS_DATA_STATUS_ERR_EMPTY));

  CHECK_CALL(push_back(ds, i++, "baz", BTS_DATA_STATUS_OK));
  CHECK_CALL(pop_front(ds, i++, "baz", BTS_DATA_STATUS_OK));

  ds->ops->destroy(ds);
  mgos_vfs_dev_close(dev);

  return NULL;
}

static const char *test_fill1(void) {
  struct mgos_config_bts_data_dev cfg = {
      .type = MGOS_VFS_DEV_TYPE_RAM,
      .opts = "{size: 30, fill_byte: 0, flash_check: true}",
      .block_size = 10,
      .meta_blocks = 0,
  };
  struct bts_data_store *ds =
      bts_data_store_dev_create(&cfg, mg_mk_str(NULL), NULL);
  ASSERT(ds != NULL);
  int i = 0, j = 0;
  struct bts_data_store_stats stats;
  for (j = 0; j < 15; j++) {
    ds->ops->get_stats(ds, &stats);
    CHECK_CALL(push_back(ds, i++, "0", BTS_DATA_STATUS_OK));
  }
  ds->ops->get_stats(ds, &stats);
  ASSERT_EQ(stats.num_records, 15);
  ASSERT_EQ(stats.bytes_used, 30);
  ASSERT_EQ(stats.bytes_free, 0);

  for (j = 0; j < 6; j++) {
    ds->ops->get_stats(ds, &stats);
    CHECK_CALL(pop_front(ds, i++, "0", BTS_DATA_STATUS_OK));
  }
  ds->ops->get_stats(ds, &stats);
  ASSERT_EQ(stats.num_records, 9);
  ASSERT_EQ(stats.bytes_used, 20); /* 2 bytes adj */
  ASSERT_EQ(stats.bytes_free, 10);

  for (j = 0; j < 5; j++) {
    ds->ops->get_stats(ds, &stats);
    CHECK_CALL(push_back(ds, i++, "1", BTS_DATA_STATUS_OK));
  }
  ds->ops->get_stats(ds, &stats);
  ASSERT_EQ(stats.num_records, 14);
  ASSERT_EQ(stats.bytes_used, 30); /* 2 bytes adj */
  ASSERT_EQ(stats.bytes_free, 0);

  ds->ops->destroy(ds);

  return NULL;
}

static const char *test_fill2(void) {
  struct mgos_config_bts_data_dev cfg = {
      .type = MGOS_VFS_DEV_TYPE_RAM,
      .opts = "{size: 30, fill_byte: 0, flash_check: true}",
      .block_size = 10,
      .meta_blocks = 0,
  };
  struct bts_data_store *ds =
      bts_data_store_dev_create(&cfg, mg_mk_str(NULL), NULL);
  ASSERT(ds != NULL);
  int i = 0;
  struct bts_data_store_stats stats;

  CHECK_CALL(push_back(ds, i++, "111111111", BTS_DATA_STATUS_OK));
  CHECK_CALL(push_back(ds, i++, "222222222", BTS_DATA_STATUS_OK));
  CHECK_CALL(push_back(ds, i++, "33333333", BTS_DATA_STATUS_OK));
  ds->ops->get_stats(ds, &stats);
  ASSERT_EQ(stats.num_records, 3);
  ASSERT_EQ(stats.bytes_used, 29);
  ASSERT_EQ(stats.bytes_free, 1);

  CHECK_CALL(pop_front(ds, i++, "111111111", BTS_DATA_STATUS_OK));
  CHECK_CALL(pop_front(ds, i++, "222222222", BTS_DATA_STATUS_OK));
  CHECK_CALL(pop_front(ds, i++, "33333333", BTS_DATA_STATUS_OK));
  CHECK_CALL(push_back(ds, i++, "444444444", BTS_DATA_STATUS_OK));
  CHECK_CALL(pop_front(ds, i++, "444444444", BTS_DATA_STATUS_OK));
  CHECK_CALL(push_back(ds, i++, "55555555", BTS_DATA_STATUS_OK));

  ds->ops->destroy(ds);

  return NULL;
}

#define TEST_DEV_SIZE 2600
#define TEST_BLOCK_SIZE 200
#define MAX_LEN (TEST_BLOCK_SIZE - 2)
#define NUM_ITERATIONS 200000

static struct mgos_vfs_dev *s_dev = NULL;
static const struct mgos_config_bts_data_dev s_cfg = {
    .block_size = TEST_BLOCK_SIZE, .meta_blocks = 3,
};

static struct bts_data_store *create_dev_ds(const struct mg_str meta) {
  return bts_data_store_dev_create(&s_cfg, meta, s_dev);
}

static const char *test_random(void) {
  s_dev = mgos_vfs_dev_create(
      MGOS_VFS_DEV_TYPE_RAM,
      ("{size: " CS_STRINGIFY_MACRO(TEST_DEV_SIZE) ", fill_byte: 0, "
       "flash_check: true}"));
  ASSERT(s_dev != NULL);
  CHECK_CALL(random_test(create_dev_ds, MAX_LEN, NUM_ITERATIONS,
                         true /* test_reload */));
  mgos_vfs_dev_close(s_dev);
  s_dev = NULL;
  return NULL;
}

extern bool mgos_vfs_dev_ram_init(void);

void tests_setup(void) {
  mgos_vfs_dev_ram_init();
}

const char *tests_run(const char *filter) {
  cs_log_set_level(LL_VERBOSE_DEBUG);
  RUN_TEST(test_basic_no_meta);
  RUN_TEST(test_basic_meta);
  RUN_TEST(test_fill1);
  RUN_TEST(test_fill2);
  cs_log_set_level(LL_INFO);
  RUN_TEST(test_random);
  return NULL;
}

void tests_teardown(void) {
}
