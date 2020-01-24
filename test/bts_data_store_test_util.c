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

#include "bts_data_store_test_util.h"

#include "common/cs_dbg.h"
#include "common/test_util.h"

#include "cs_varint32.h"

const char *push_back_str(struct bts_data_store *ds, int i, struct mg_str data,
                          enum bts_data_store_status exp_st) {
  enum bts_data_store_status st = ds->ops->push_back(ds, data);
  struct bts_data_store_stats stats;
  LOG(LL_DEBUG, ("+  %d: push %d -> %d %s %d", i, (int) data.len, st,
                 (st == exp_st ? "==" : "!="), exp_st));
  ds->ops->get_stats(ds, &stats);
  ASSERT_EQ(st, exp_st);
  return NULL;
}

const char *push_back(struct bts_data_store *ds, int i, const char *s,
                      enum bts_data_store_status exp_st) {
  return push_back_str(ds, i, mg_mk_str(s), exp_st);
}

const char *pop_front_str(struct bts_data_store *ds, int i, size_t max_size,
                          enum bts_data_store_status exp_st,
                          struct mg_str *data) {
  enum bts_data_store_status st = ds->ops->pop_front(ds, max_size, data);
  struct bts_data_store_stats stats;
  LOG(LL_DEBUG, ("-  %d: pop -> %d %s %d (%d)", i, st,
                 (st == exp_st ? "==" : "!="), exp_st, (int) data->len));
  ds->ops->get_stats(ds, &stats);
  ASSERT_EQ(st, exp_st);
  return NULL;
}

const char *pop_front(struct bts_data_store *ds, int i, const char *s,
                      enum bts_data_store_status exp_st) {
  struct mg_str data = MG_NULL_STR;
  CHECK_CALL(pop_front_str(ds, i, ~0, exp_st, &data));
  if (exp_st == BTS_DATA_STATUS_OK) {
    if (s != NULL) ASSERT_MG_STREQ(data, s);
    free((void *) data.p);
  }
  return NULL;
}

static char get_ch(size_t i, size_t len) {
  if (len == 1) return '|';
  if (i == 0) {
    return '[';
  } else if (i == len - 1) {
    return ']';
  }
  return '-';
}

static void fill_data(struct mg_str *data) {
  for (size_t i = 0; i < data->len; i++) {
    ((char *) data->p)[i] = get_ch(i, data->len);
  }
}

static const char *check_data(const struct mg_str data) {
  ASSERT_GT(data.len, 0);
  for (size_t i = 0; i < data.len; i++) {
    char exp_ch = get_ch(i, data.len);
    if (data.p[i] != exp_ch) {
      fprintf(stderr, "fail pos: %u\n", (unsigned) i);
    }
    ASSERT_EQ(data.p[i], exp_ch);
  }
  free((void *) data.p);
  return NULL;
}

const char *random_test(ds_create_f cf, size_t max_len, int num_iterations,
                        bool test_reload) {
  struct bts_data_store *ds = cf(mg_mk_str(NULL));
  ASSERT(ds != NULL);
  enum bts_data_store_status st;
  struct bts_data_store_stats stats;
  int num_pushes = 0, num_pops = 0, num_fills = 0, num_drains = 0;
  int num_flushes = 0, num_reloads = 0;
  cs_log_set_level(LL_ERROR);
  char *buf = (char *) malloc(max_len);
  ASSERT(buf != NULL);

  for (int i = 0; i < num_iterations; i++) {
    int op = rand() % 100;
    ds->ops->get_stats(ds, &stats);
    if (op < 49) {  // push
      size_t len = rand() % (max_len + 1);
      enum bts_data_store_status exp_st =
          (len > 0 && cs_varint32_llen(len) + len <= stats.bytes_free
               ? BTS_DATA_STATUS_OK
               : BTS_DATA_STATUS_ERR_SIZE);
      struct mg_str data = mg_mk_str_n(buf, len);
      fill_data(&data);
      CHECK_CALL(push_back_str(ds, i, data, exp_st));
      num_pushes++;
    } else if (op < 98) {  // pop
      struct mg_str data = MG_NULL_STR;
      enum bts_data_store_status exp_st =
          (stats.num_records > 0 ? BTS_DATA_STATUS_OK
                                 : BTS_DATA_STATUS_ERR_EMPTY);
      CHECK_CALL(pop_front_str(ds, i, max_len, exp_st, &data));
      if (exp_st == BTS_DATA_STATUS_OK) {
        CHECK_CALL(check_data(data));
      }
      num_pops++;
    } else if (op < 99) {  // fill
      struct mg_str data = MG_MK_STR("|");
      LOG(LL_DEBUG, ("++ %d: fill", i));
      while (true) {
        enum bts_data_store_status st = ds->ops->push_back(ds, data);
        if (st == BTS_DATA_STATUS_ERR_SIZE) break;
        ASSERT_EQ(st, BTS_DATA_STATUS_OK);
      }
      num_fills++;
    } else {  // drain
      struct mg_str data;
      LOG(LL_DEBUG, ("-- %d: drain", i));
      while (stats.num_records > 0) {
        st = ds->ops->pop_front(ds, max_len, &data);
        ASSERT_EQ(st, BTS_DATA_STATUS_OK);
        CHECK_CALL(check_data(data));
        ds->ops->get_stats(ds, &stats);
      }
      num_drains++;
    }
    if (test_reload) {
      if (op < 5) {
        ASSERT_TRUE(ds->ops->flush(ds));
        num_flushes++;
      }
      if (op < 1) {
        struct bts_data_store_stats stats2;
        ASSERT_TRUE(ds->ops->flush(ds));
        ds->ops->get_stats(ds, &stats);
        ds->ops->destroy(ds);
        ds = cf(mg_mk_str(NULL));
        ASSERT(ds != NULL);
        ds->ops->get_stats(ds, &stats2);
        ASSERT_EQ(memcmp(&stats, &stats2, sizeof(stats)), 0);
        num_reloads++;
      }
    }
  }
  ds->ops->get_stats(ds, &stats);
  cs_log_set_level(LL_INFO);
  LOG(LL_INFO, ("Ran %u iterations: %d pushes, %d pops, %d fills, %d drains; "
                "%d flushes, %d reloads",
                num_iterations, num_pushes, num_pops, num_fills, num_drains,
                num_flushes, num_reloads));
  ds->ops->destroy(ds);
  free(buf);
  return NULL;
}
