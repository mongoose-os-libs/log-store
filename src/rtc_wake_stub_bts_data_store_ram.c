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

#include "mgos_system.h"

#include "cs_varint32.h"

/* Note: this function will be called from deep sleep wakeup stub,
 * it must only use ROM functions, because even IRAM is invalid. */
extern enum bts_data_store_status bts_data_store_ram_push_back(
    struct bts_data_store *ds, const struct mg_str data) {
  struct bts_data_store_ram_ctx *ctx =
      (struct bts_data_store_ram_ctx *) ds->ctx;
  if (ctx == NULL || data.len == 0) return BTS_DATA_STATUS_ERR_SIZE;
  enum bts_data_store_status st = BTS_DATA_STATUS_ERR;
  if (ctx->lock) mgos_rlock(ctx->lock);
  size_t rec_size = data.len + cs_varint32_llen(data.len);
  if (ctx->stats.bytes_free < rec_size) {
    st = BTS_DATA_STATUS_ERR_SIZE;
    goto out_unlock;
  }
  size_t buf_left = ctx->size - (ctx->tail - ctx->buf);
  if (buf_left < rec_size) {
    /* Shift left */
    memmove(ctx->buf, ctx->head, (ctx->tail - ctx->head));
    ctx->tail -= (ctx->head - ctx->buf);
    ctx->head = ctx->buf;
    buf_left = ctx->size - (ctx->tail - ctx->buf);
  }
  ctx->tail += cs_varint32_encode(data.len, ctx->tail, buf_left);
  memcpy(ctx->tail, data.p, data.len);
  ctx->tail += data.len;
  ctx->stats.num_records++;
  ctx->stats.bytes_used += rec_size;
  ctx->stats.bytes_free -= rec_size;
  st = BTS_DATA_STATUS_OK;

out_unlock:
  if (ctx->lock) mgos_runlock(ctx->lock);
  return st;
}
