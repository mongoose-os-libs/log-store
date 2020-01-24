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
#include <string.h>

#ifdef ESP_PLATFORM
#include "esp_attr.h"
#else
#define RTC_DATA_ATTR
#endif

#include "common/cs_dbg.h"

#include "mgos_system.h"

#include "cs_varint32.h"

#define DATA_RAM_LOCK(ctx)                    \
  do {                                        \
    if ((ctx)->lock) mgos_rlock((ctx)->lock); \
  } while (0);
#define DATA_RAM_UNLOCK(ctx)                    \
  do {                                          \
    if ((ctx)->lock) mgos_runlock((ctx)->lock); \
  } while (0);

/* bts_data_store_ram_push_back is defined rtc_wake_stub_bts_data_store_ram.c */
extern enum bts_data_store_status bts_data_store_ram_push_back(
    struct bts_data_store *ds, const struct mg_str data);

static void bts_data_store_ram_destroy(struct bts_data_store *ds);

static enum bts_data_store_status bts_data_store_ram_pop_front(
    struct bts_data_store *ds, size_t max_size, struct mg_str *data) {
  struct bts_data_store_ram_ctx *ctx =
      (struct bts_data_store_ram_ctx *) ds->ctx;
  if (ctx == NULL) return BTS_DATA_STATUS_ERR_EMPTY;
  char *dp = NULL;
  size_t llen = 0;
  uint32_t data_len = 0;
  enum bts_data_store_status st = BTS_DATA_STATUS_ERR;
  DATA_RAM_LOCK(ctx);
  if (ctx->head == ctx->tail) {
    st = BTS_DATA_STATUS_ERR_EMPTY;
    goto out_unlock;
  }
  if (max_size == 0) {
    st = BTS_DATA_STATUS_ERR_SIZE;
    goto out_unlock;
  }
  if (!cs_varint32_decode(ctx->head, ctx->tail - ctx->head, &data_len, &llen)) {
    st = BTS_DATA_STATUS_ERR_CORRUPT;
    goto out_unlock;
  }
  if (data_len > max_size) {
    st = BTS_DATA_STATUS_ERR_SIZE;
    goto out_unlock;
  }
  size_t rec_size = data_len + llen;
  dp = (char *) malloc(data_len);
  if (dp == NULL) goto out_unlock;
  memcpy(dp, ctx->head + llen, data_len);
  ctx->head += rec_size;
  ctx->stats.num_records--;
  ctx->stats.bytes_used -= rec_size;
  ctx->stats.bytes_free += rec_size;
  data->p = dp;
  data->len = data_len;
  st = BTS_DATA_STATUS_OK;

out_unlock:
  DATA_RAM_UNLOCK(ctx);
  if (st != BTS_DATA_STATUS_OK) free(dp);
  LOG(LL_DEBUG, ("max_size %u ll %u dl %u st %d", (unsigned) max_size,
                 (unsigned) llen, (unsigned) data_len, st));
  return st;
}

static bool bts_data_store_ram_flush(struct bts_data_store *ds) {
  (void) ds;
  return true;
}

static bool bts_data_store_ram_get_meta(struct bts_data_store *ds,
                                        struct mg_str *meta) {
  (void) ds;
  (void) meta;
  return false;
}

static void bts_data_store_ram_get_stats(struct bts_data_store *ds,
                                         struct bts_data_store_stats *stats) {
  memset(stats, 0, sizeof(*stats));
  struct bts_data_store_ram_ctx *ctx =
      (struct bts_data_store_ram_ctx *) ds->ctx;
  if (ctx == NULL) return;
  DATA_RAM_LOCK(ctx);
  if (ctx->buf != NULL) {
    memcpy(stats, &ctx->stats, sizeof(*stats));
    LOG(LL_DEBUG, ("sz %u, buf %p ho %d to %d; nr %u bu %u bf %u",
                   (unsigned) ctx->size, ctx->buf, (int) (ctx->head - ctx->buf),
                   (int) (ctx->tail - ctx->buf), (unsigned) stats->num_records,
                   (unsigned) stats->bytes_used, (unsigned) stats->bytes_free));
  }
  DATA_RAM_UNLOCK(ctx);
}

struct bts_data_store *bts_data_store_ram_create(
    const struct mgos_config_bts_data_ram *cfg) {
  bool res = false;
  struct bts_data_store *ds = (struct bts_data_store *) calloc(1, sizeof(*ds));
  struct bts_data_store_ram_ctx *ctx =
      (struct bts_data_store_ram_ctx *) calloc(1, sizeof(*ctx));
  if (ds == NULL || ctx == NULL) goto out;
  int size = cfg->size;

  if (size == 0) {
    res = true;
    goto out;
  }

  if (size < 0) size = mgos_get_free_heap_size() + size;

  if (size <= 0) {
    LOG(LL_ERROR, ("Not enough RAM available!"));
    goto out;
  }

  uint8_t *buf = (uint8_t *) calloc(size, 1);
  if (buf == NULL) {
    LOG(LL_ERROR, ("Failed to allocate RAM buffer!"));
    goto out;
  }

  ds->ctx = ctx;

  res = bts_data_store_ram_init_with_buffer(ds, buf, size);

  ctx->own_buf = true;

out:
  if (!res) {
    if (ctx != NULL) {
      free(ctx->buf);
      free(ctx);
    }
    if (ds != NULL) {
      free(ds);
      ds = NULL;
    }
  }
  return ds;
}

static RTC_DATA_ATTR struct bts_data_store_ops s_bts_data_store_ram_ops = {
    .push_back = bts_data_store_ram_push_back,
    .pop_front = bts_data_store_ram_pop_front,
    .flush = bts_data_store_ram_flush,
    .get_meta = bts_data_store_ram_get_meta,
    .get_stats = bts_data_store_ram_get_stats,
    .destroy = bts_data_store_ram_destroy,
};

bool bts_data_store_ram_init_with_buffer(struct bts_data_store *ds,
                                         uint8_t *buf, size_t size) {
  struct bts_data_store_ram_ctx *ctx =
      (struct bts_data_store_ram_ctx *) ds->ctx;
  ds->ops = &s_bts_data_store_ram_ops;
  memset(ctx, 0, sizeof(*ctx));
  ctx->buf = buf;
  ctx->size = size;
  ctx->head = ctx->tail = ctx->buf;
  ctx->lock = mgos_rlock_create();
  ctx->stats.num_records = 0;
  ctx->stats.bytes_used = 0;
  ctx->stats.bytes_free = ctx->size;
  LOG(LL_INFO, ("RAM buffer: %d bytes @ %p", (int) ctx->size, ctx->buf));
  return true;
}

void bts_data_store_ram_deinit(struct bts_data_store_ram_ctx *ctx) {
  if (ctx->own_buf) free(ctx->buf);
  if (ctx->lock) mgos_rlock_destroy(ctx->lock);
  memset(ctx, 0, sizeof(*ctx));
}

static void bts_data_store_ram_destroy(struct bts_data_store *ds) {
  struct bts_data_store_ram_ctx *ctx =
      (struct bts_data_store_ram_ctx *) ds->ctx;
  bts_data_store_ram_deinit(ctx);
  free(ctx);
  memset(ds, 0, sizeof(*ds));
  free(ds);
}
