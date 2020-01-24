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

#include "bts_data_store_file.h"

static void bts_data_store_file_destroy(struct bts_data_store *ds);

static enum bts_data_store_status bts_data_store_file_push_back(
    struct bts_data_store *ds, const struct mg_str data) {
  (void) ds;
  (void) data;
  return BTS_DATA_STATUS_ERR_SIZE;
}

static enum bts_data_store_status bts_data_store_file_pop_front(
    struct bts_data_store *ds, size_t max_size, struct mg_str *data) {
  (void) ds;
  (void) max_size;
  (void) data;
  return BTS_DATA_STATUS_ERR_EMPTY;
}

static bool bts_data_store_file_flush(struct bts_data_store *ds) {
  (void) ds;
  return true;
}

static bool bts_data_store_file_get_meta(struct bts_data_store *ds,
                                         struct mg_str *meta) {
  meta->len = 0;
  meta->p = NULL;
  return false;
}

static void bts_data_store_file_get_stats(struct bts_data_store *ds,
                                          struct bts_data_store_stats *stats) {
  memset(stats, 0, sizeof(*stats));
  (void) ds;
}

static struct bts_data_store_ops s_bts_data_store_file_ops = {
    .push_back = bts_data_store_file_push_back,
    .pop_front = bts_data_store_file_pop_front,
    .flush = bts_data_store_file_flush,
    .get_meta = bts_data_store_file_get_meta,
    .get_stats = bts_data_store_file_get_stats,
    .destroy = bts_data_store_file_destroy,
};

struct bts_data_store *bts_data_store_file_create(
    const struct mgos_config_bts_data_file *cfg) {
  struct bts_data_store *ds = (struct bts_data_store *) calloc(1, sizeof(*ds));
  ds->ops = &s_bts_data_store_file_ops;
  return ds;
}

static void bts_data_store_file_destroy(struct bts_data_store *ds) {
  memset(ds, 0, sizeof(*ds));
  free(ds);
}
