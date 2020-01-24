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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common/cs_dbg.h"
#include "common/cs_time.h"

#include "mgos_system.h"
#include "mgos_sys_config.h"
#include "mgos_vfs_dev.h"

#include "cs_varint32.h"

#define META_MAGIC 0x4453
#define META_SIZE (sizeof(struct bts_data_store_dev_meta))

/* Persistent part of the state */
struct bts_data_store_dev_meta {
  uint16_t magic;
  uint16_t seq;
  uint32_t head_off, tail_off;
  struct bts_data_store_stats stats;
  uint32_t tail_block_erased : 1;
  uint32_t meta_tail_block_erased : 1;
  uint32_t meta_tail_off;
} __attribute__((packed));

struct bts_data_store_dev_ctx {
  struct mgos_vfs_dev *dev;
  bool own_dev;
  struct mgos_rlock_type *lock;
  struct bts_data_store_dev_meta meta;
  size_t block_size;
  size_t data_arena_size, meta_arena_size;
  uint8_t *tail_block_buf;
  size_t head_block_off, tail_block_off;
  bool data_dirty, meta_dirty;
};

static void bts_data_store_dev_destroy(struct bts_data_store *ds);

static inline size_t get_block_off(struct bts_data_store_dev_ctx *ctx,
                                   size_t off) {
  return (off / ctx->block_size) * ctx->block_size;
}

#define MAX_VAL(n) (2 << (sizeof(n) * 8 - 1))

static bool bts_data_store_dev_flush_data(struct bts_data_store_dev_ctx *ctx) {
  bool res = false;
  enum mgos_vfs_dev_err dres;
  if (!ctx->data_dirty) {
    res = true;
    goto out;
  }
  if (!ctx->meta.tail_block_erased) {
    dres = mgos_vfs_dev_erase(ctx->dev, ctx->tail_block_off, ctx->block_size);
    if (dres != 0) {
      LOG(LL_ERROR, ("Block 0x%x erase failed! %d",
                     (unsigned) ctx->tail_block_off, dres));
      goto out;
    }
    ctx->meta.tail_block_erased = true;
    ctx->meta_dirty = true;
  }
  dres = mgos_vfs_dev_write(ctx->dev, ctx->tail_block_off, ctx->block_size,
                            ctx->tail_block_buf);

  if (dres == 0) ctx->data_dirty = false;
  res = true;

out:
  return res;
}

static void next_meta_rec(struct bts_data_store_dev_ctx *ctx) {
  size_t meta_tail_block_off = get_block_off(ctx, ctx->meta.meta_tail_off);
  ctx->meta.meta_tail_off += META_SIZE;
  size_t meta_tail_block_avail =
      ctx->block_size - (ctx->meta.meta_tail_off - meta_tail_block_off);
  if (meta_tail_block_avail < META_SIZE) {
    ctx->meta.meta_tail_off += meta_tail_block_avail;
    if (ctx->meta.meta_tail_off == ctx->meta_arena_size)
      ctx->meta.meta_tail_off = 0;
    ctx->meta.meta_tail_block_erased = false;
  }
}

static bool bts_data_store_dev_flush_meta(struct bts_data_store_dev_ctx *ctx) {
  bool res = false;
  enum mgos_vfs_dev_err dres;

  if (ctx->meta_arena_size == 0) goto out;

  if (!ctx->meta_dirty) {
    res = true;
    goto out;
  }

  if (!ctx->meta.meta_tail_block_erased) {
    dres = mgos_vfs_dev_erase(
        ctx->dev,
        ctx->data_arena_size + get_block_off(ctx, ctx->meta.meta_tail_off),
        ctx->block_size);
    if (dres != 0) {
      LOG(LL_ERROR, ("Block 0x%x erase failed! %d",
                     (unsigned) ctx->tail_block_off, dres));
      goto out;
    }
    ctx->meta.meta_tail_block_erased = true;
  }

  ctx->meta.seq++;
  if (ctx->meta.seq == 0) ctx->meta.seq++;
  dres = mgos_vfs_dev_write(ctx->dev,
                            ctx->data_arena_size + ctx->meta.meta_tail_off,
                            META_SIZE, (uint8_t *) &ctx->meta);

  if (dres == 0) {
    LOG(LL_DEBUG,
        ("saved meta seq %u @ %u", (unsigned) ctx->meta.seq,
         (unsigned) (ctx->data_arena_size + ctx->meta.meta_tail_off)));
    ctx->meta_dirty = false;
    res = true;
  }

  next_meta_rec(ctx);

out:
  if (!res) LOG(LL_ERROR, ("Failed to save state!"));
  return res;
}

static bool bts_data_store_dev_load_meta(struct bts_data_store_dev_ctx *ctx) {
  bool res = false;
  struct bts_data_store_dev_meta latest_meta, tmp;

  if (ctx->meta_arena_size == 0) goto out;

  ctx->meta.meta_tail_off = 0;
  memset(&latest_meta, 0, sizeof(latest_meta));
  do {
    if (mgos_vfs_dev_read(ctx->dev,
                          ctx->data_arena_size + ctx->meta.meta_tail_off,
                          META_SIZE, (uint8_t *) &tmp) != 0) {
      goto out;
    }
    //    LOG(LL_DEBUG, ("%u %x %u", (unsigned)(ctx->data_arena_size +
    //    ctx->meta_tail_off), tmp.magic, tmp.seq));
    if (tmp.magic != META_MAGIC ||
        tmp.meta_tail_off != ctx->meta.meta_tail_off ||
        (tmp.seq < latest_meta.seq &&
         latest_meta.seq - tmp.seq < MAX_VAL(tmp.seq) / 2)) {
      goto next;
    }
    memcpy(&latest_meta, &tmp, sizeof(latest_meta));

  next:
    next_meta_rec(ctx);
  } while (ctx->meta.meta_tail_off != 0);

  if (latest_meta.seq > 0) {
    memcpy(&ctx->meta, &latest_meta, sizeof(ctx->meta));
    LOG(LL_DEBUG,
        ("loaded meta seq %u @ %u", (unsigned) ctx->meta.seq,
         (unsigned) (ctx->data_arena_size + ctx->meta.meta_tail_off)));
    next_meta_rec(ctx);
    res = true;
  }

out:
  return res;
}

static bool bts_data_store_dev_new_tail_block(
    struct bts_data_store_dev_ctx *ctx, size_t tail_block_off) {
  /* Flush the current block, if dirty. */
  if (!bts_data_store_dev_flush_data(ctx)) return false;
  memset(ctx->tail_block_buf, 0xff, ctx->block_size);
  ctx->tail_block_off = tail_block_off;
  ctx->meta.tail_block_erased = false;
  ctx->data_dirty = false;
  return true;
}

static enum bts_data_store_status bts_data_store_dev_push_back(
    struct bts_data_store *ds, const struct mg_str data) {
  struct bts_data_store_dev_ctx *ctx =
      (struct bts_data_store_dev_ctx *) ds->ctx;
  if (ctx == NULL || data.len == 0) return BTS_DATA_STATUS_ERR_SIZE;
  enum bts_data_store_status st = BTS_DATA_STATUS_ERR;
  mgos_rlock(ctx->lock);
  size_t llen = cs_varint32_llen(data.len);
  size_t rec_size = llen + data.len;
  const uint8_t *db = (const uint8_t *) data.p;

  if (ctx->meta.stats.bytes_free < rec_size || rec_size > ctx->block_size) {
    st = BTS_DATA_STATUS_ERR_SIZE;
    goto out_unlock;
  }
  /*
   * Tail cannot follow head within the same block because head can be
   * corrupted between erase and write of the block.
   * The exception is when storage is empty, then tail can grow.
   */
  if (ctx->tail_block_off == ctx->head_block_off &&
      (ctx->meta.head_off >= ctx->meta.tail_off &&
       ctx->meta.stats.num_records > 0)) {
    st = BTS_DATA_STATUS_ERR_SIZE;
    goto out_unlock;
  }

  bool len_written = false;
  size_t bytes_written = 0;
  size_t tail_block_end = ctx->tail_block_off + ctx->block_size;
  size_t tail_block_used = ctx->meta.tail_off - ctx->tail_block_off;
  size_t tail_block_avail = ctx->block_size - tail_block_used;

  if (rec_size > tail_block_avail) {
    size_t new_tail_block_off = tail_block_end;
    if (new_tail_block_off >= ctx->data_arena_size) new_tail_block_off = 0;
    /* Can't let the tail enter into the same block as head. */
    if (new_tail_block_off == ctx->head_block_off) {
      st = BTS_DATA_STATUS_ERR_SIZE;
      goto out_unlock;
    }
    if (new_tail_block_off != 0 && tail_block_avail >= llen) {
      /* Write length and part of the record into this block and flush it. */
      cs_varint32_encode(data.len, ctx->tail_block_buf + tail_block_used,
                         tail_block_avail);
      rec_size -= llen;
      bytes_written += llen;
      tail_block_used += llen;
      tail_block_avail -= llen;
      len_written = true;
      memcpy(ctx->tail_block_buf + tail_block_used, db, tail_block_avail);
      db += tail_block_avail;
      rec_size -= tail_block_avail;
      bytes_written += tail_block_avail;
    } else {
      /*
       * Either we are about to wrap around the end or current block does not
       * have enough bytes to fit the length.
       * Pad the rest of the block with zeroes, which are empty records and
       * will be skipped on read.
       */
      memset(ctx->tail_block_buf + tail_block_used, 0, tail_block_avail);
      bytes_written += tail_block_avail;
    }
    ctx->data_dirty = true;
    if (!bts_data_store_dev_new_tail_block(ctx, new_tail_block_off))
      goto out_unlock;
    ctx->meta.tail_off = ctx->tail_block_off;
    tail_block_end = ctx->tail_block_off + ctx->block_size;
    tail_block_avail = ctx->block_size;
    tail_block_used = 0;
  }
  /*
   * At this point we are guaranteed to have enough space within the block
   * for (the rest of) the record.
   */
  if (!len_written) {
    cs_varint32_encode(data.len, ctx->tail_block_buf + tail_block_used, llen);
    tail_block_used += llen;
    bytes_written += llen;
    ctx->meta.tail_off += llen;
    rec_size -= llen;
  }
  memcpy(ctx->tail_block_buf + tail_block_used, db, rec_size);
  bytes_written += rec_size;
  ctx->meta.tail_off += rec_size;
  ctx->data_dirty = true;
  if (ctx->meta.tail_off == tail_block_end) {
    size_t new_tail_block_off = tail_block_end;
    if (new_tail_block_off >= ctx->data_arena_size) new_tail_block_off = 0;
    if (!bts_data_store_dev_new_tail_block(ctx, new_tail_block_off))
      goto out_unlock;
    ctx->meta.tail_off = ctx->tail_block_off;
  }

  ctx->meta.stats.num_records++;
  ctx->meta.stats.bytes_used += bytes_written;
  ctx->meta.stats.bytes_free -= bytes_written;
  ctx->meta_dirty = true;

  st = BTS_DATA_STATUS_OK;

out_unlock:
  mgos_runlock(ctx->lock);
  return st;
}

/*
 * Read len bytes starting at off.
 * Note: May cross the tail block boundary on the left,
 *       in which case data from the block buffer must be used.
 *       But only up to tail offset, data in the buffer
 *       after the tail is not valid.
 */
static bool bts_data_store_dev_read(const struct bts_data_store_dev_ctx *ctx,
                                    size_t off, size_t len, void *dst) {
  bool res = false;
  uint8_t *dstb = (uint8_t *) dst;
  size_t to_read = 0, to_copy = 0, copy_off = 0;

  size_t begin = off;
  size_t end = off + len;
  if (end > ctx->data_arena_size) goto out;

  size_t buf_begin = ctx->tail_block_off;
  size_t buf_end = ctx->meta.tail_off;

  if (end <= buf_begin || begin >= buf_end) {
    to_read = len;
    if (mgos_vfs_dev_read(ctx->dev, off, to_read, dstb) != 0) goto out;
  } else if (begin <= buf_begin && end <= buf_end) {
    to_read = buf_begin - begin;
    to_copy = end - buf_begin;
    if (to_read > 0) {
      if (mgos_vfs_dev_read(ctx->dev, off, to_read, dstb) != 0) goto out;
    }
    memcpy(dstb + to_read, ctx->tail_block_buf, to_copy);
  } else if (begin > buf_begin && end <= buf_end) {
    to_copy = len;
    copy_off = begin - buf_begin;
    memcpy(dstb, ctx->tail_block_buf + copy_off, to_copy);
  } else {
    /* end > buf_end - can't happen, head can't go past tail. */
    goto out;
  }
  res = true;

out:
  LOG(LL_DEBUG, ("%u %u, ho %u hbo %u to %u tbo %u => %u %u %u => %d",
                 (unsigned) off, (unsigned) len, (unsigned) ctx->meta.head_off,
                 (unsigned) ctx->head_block_off, (unsigned) ctx->meta.tail_off,
                 (unsigned) ctx->tail_block_off, (unsigned) to_read,
                 (unsigned) to_copy, (unsigned) copy_off, res));
  return res;
}

static void bts_data_store_dev_advance_head(struct bts_data_store_dev_ctx *ctx,
                                            size_t n) {
  ctx->meta.head_off += n;
  if (ctx->meta.head_off >= ctx->data_arena_size) {
    ctx->meta.head_off = 0;
  }
  ctx->head_block_off = get_block_off(ctx, ctx->meta.head_off);
  ctx->meta.stats.bytes_used -= n;
  ctx->meta.stats.bytes_free += n;
}

static enum bts_data_store_status bts_data_store_dev_pop_front(
    struct bts_data_store *ds, size_t max_size, struct mg_str *data) {
  struct bts_data_store_dev_ctx *ctx =
      (struct bts_data_store_dev_ctx *) ds->ctx;
  if (ctx == NULL) return BTS_DATA_STATUS_ERR_EMPTY;
  enum bts_data_store_status st = BTS_DATA_STATUS_ERR;
  uint8_t *dp = NULL;
  size_t llen = 0;
  uint32_t data_len = 0;
  mgos_rlock(ctx->lock);
  if (ctx->meta.stats.num_records == 0) {
    st = BTS_DATA_STATUS_ERR_EMPTY;
    goto out_unlock;
  }
  if (max_size == 0) {
    st = BTS_DATA_STATUS_ERR_SIZE;
    goto out_unlock;
  }
  uint8_t len_buf[10];
  for (size_t num_read = 1; data_len == 0 && num_read <= sizeof(len_buf);
       num_read++) {
    memset(len_buf, 0, sizeof(len_buf));
    if (!bts_data_store_dev_read(ctx, ctx->meta.head_off, num_read, len_buf)) {
      goto out_unlock;
    }
    data_len = 0;
    if (!cs_varint32_decode(len_buf, num_read, &data_len, &llen)) {
      continue;
    }
    if (llen == 1 && data_len == 0) {
      /* No-op record, skip. */
      bts_data_store_dev_advance_head(ctx, 1);
      num_read = 0;
    }
  }
  if (data_len == 0) {
    st = BTS_DATA_STATUS_ERR_CORRUPT;
    goto out_unlock;
  }
  if (data_len > max_size) {
    st = BTS_DATA_STATUS_ERR_SIZE;
    goto out_unlock;
  }
  size_t rec_size = llen + data_len;
  dp = (uint8_t *) malloc(data_len);
  if (dp == NULL) goto out_unlock;
  if (!bts_data_store_dev_read(ctx, ctx->meta.head_off + llen, data_len, dp)) {
    st = BTS_DATA_STATUS_ERR_CORRUPT;
    goto out_unlock;
  }

  bts_data_store_dev_advance_head(ctx, rec_size);
  ctx->meta.stats.num_records--;
  ctx->meta_dirty = true;
  data->p = (char *) dp;
  data->len = data_len;
  st = BTS_DATA_STATUS_OK;

out_unlock:
  mgos_runlock(ctx->lock);
  if (st != BTS_DATA_STATUS_OK) free(dp);
  LOG(LL_DEBUG, ("max_size %u ll %u dl %u st %d", (unsigned) max_size,
                 (unsigned) llen, (unsigned) data_len, st));
  return st;
}

static bool bts_data_store_dev_flush(struct bts_data_store *ds) {
  struct bts_data_store_dev_ctx *ctx =
      (struct bts_data_store_dev_ctx *) ds->ctx;
  if (ctx == NULL) return true;
  bool res = false;
  mgos_rlock(ctx->lock);
  if (bts_data_store_dev_flush_data(ctx)) {
    res = bts_data_store_dev_flush_meta(ctx);
  }
  mgos_runlock(ctx->lock);
  return res;
}

static bool bts_data_store_dev_get_meta(struct bts_data_store *ds,
                                        struct mg_str *meta) {
  struct bts_data_store_dev_ctx *ctx =
      (struct bts_data_store_dev_ctx *) ds->ctx;
  if (ctx == NULL) return false;
  meta->p = malloc(sizeof(ctx->meta));
  if (meta->p == NULL) return false;
  mgos_rlock(ctx->lock);
  memcpy((void *) meta->p, &ctx->meta, sizeof(ctx->meta));
  mgos_runlock(ctx->lock);
  meta->len = sizeof(ctx->meta);
  return true;
}

static void bts_data_store_dev_get_stats(struct bts_data_store *ds,
                                         struct bts_data_store_stats *stats) {
  struct bts_data_store_dev_ctx *ctx =
      (struct bts_data_store_dev_ctx *) ds->ctx;
  memset(stats, 0, sizeof(*stats));
  if (ctx == NULL) return;
  mgos_rlock(ctx->lock);
  memcpy(stats, &ctx->meta.stats, sizeof(*stats));
  /*
   * Since tail cannot follow head in the same block, exclude the head space
   * in the current head block.
   */
  size_t adj = (ctx->meta.head_off - ctx->head_block_off);
  stats->bytes_used += adj;
  stats->bytes_free -= adj;
  LOG(LL_DEBUG,
      ("ho %u hbo %u to %u tbo %u; tbe %d dd %d md %d; "
       "nr %u bu %u bf %u; "
       "mseq %u mto %u mtbe %d",
       (unsigned) ctx->meta.head_off, (unsigned) ctx->head_block_off,
       (unsigned) ctx->meta.tail_off, (unsigned) ctx->tail_block_off,
       ctx->meta.tail_block_erased, ctx->data_dirty, ctx->meta_dirty,
       (unsigned) stats->num_records, (unsigned) stats->bytes_used,
       (unsigned) stats->bytes_free, (unsigned) ctx->meta.seq,
       (unsigned) ctx->meta.meta_tail_off, ctx->meta.meta_tail_block_erased));
  mgos_runlock(ctx->lock);
}

static struct bts_data_store_ops s_bts_data_store_dev_ops = {
    .push_back = bts_data_store_dev_push_back,
    .pop_front = bts_data_store_dev_pop_front,
    .flush = bts_data_store_dev_flush,
    .get_meta = bts_data_store_dev_get_meta,
    .get_stats = bts_data_store_dev_get_stats,
    .destroy = bts_data_store_dev_destroy,
};

struct bts_data_store *bts_data_store_dev_create(
    const struct mgos_config_bts_data_dev *cfg, const struct mg_str meta,
    struct mgos_vfs_dev *dev) {
  bool res = false;
  struct bts_data_store *ds = (struct bts_data_store *) calloc(1, sizeof(*ds));
  struct bts_data_store_dev_ctx *ctx =
      (struct bts_data_store_dev_ctx *) calloc(1, sizeof(*ctx));
  if (ds == NULL || ctx == NULL) goto out;
  ds->ops = &s_bts_data_store_dev_ops;
  ds->ctx = ctx;

  if (dev == NULL) {
    if (cfg->type == NULL) {
      goto out;
    }

    dev = mgos_vfs_dev_create(cfg->type, cfg->opts);
    if (dev == NULL) {
      LOG(LL_ERROR, ("Failed to open storage device"));
      goto out;
    }
    ctx->dev = dev;
    ctx->own_dev = true;
  } else {
    ctx->dev = dev;
    ctx->own_dev = false;
  }

  ctx->lock = mgos_rlock_create();

  size_t cfg_data_arena_size = 0;
  if (cfg->size == 0) {
    cfg_data_arena_size = mgos_vfs_dev_get_size(ctx->dev);
  } else if ((unsigned) cfg->size <= mgos_vfs_dev_get_size(ctx->dev)) {
    cfg_data_arena_size = cfg->size;
  } else {
    LOG(LL_ERROR, ("Arena size (%u) exceeds underlying device size (%u)!",
                   cfg->size, (unsigned) mgos_vfs_dev_get_size(ctx->dev)));
    goto out;
  }

  size_t cfg_block_size = cfg->block_size;
  /* Adjust data_arena_size to be a multiple of buf size. */
  cfg_data_arena_size -= (cfg_data_arena_size % cfg_block_size);
  size_t min_blocks = 3 + cfg->meta_blocks;
  if (cfg_data_arena_size < min_blocks * cfg_block_size) {
    LOG(LL_ERROR,
        ("Device size must be at least %u blocks!", (unsigned) min_blocks));
    goto out;
  }
  if (cfg->meta_blocks > 0) {
    if (cfg_block_size < META_SIZE) {
      LOG(LL_ERROR,
          ("Block size must be at least %u bytes!", (unsigned) META_SIZE));
      goto out;
    }
    ctx->meta_arena_size = cfg->meta_blocks * cfg_block_size;
    cfg_data_arena_size -= ctx->meta_arena_size;
  }

  ctx->data_arena_size = cfg_data_arena_size;
  ctx->block_size = cfg_block_size;

  if (meta.len == META_SIZE &&
      ((struct bts_data_store_dev_meta *) meta.p)->magic == META_MAGIC) {
    memcpy(&ctx->meta, meta.p, META_SIZE);
  } else {
    if (!bts_data_store_dev_load_meta(ctx)) {
      ctx->meta.magic = META_MAGIC;
#ifdef UNIT_TEST
      ctx->meta.seq = MAX_VAL(ctx->meta.seq) - 2;
#else
      ctx->meta.seq = 0;
#endif
      ctx->meta.head_off = 0;
      ctx->meta.tail_off = 0;
      ctx->meta.tail_block_erased = false;
      ctx->meta.stats.num_records = 0;
      ctx->meta.stats.bytes_used = 0;
      ctx->meta.stats.bytes_free = ctx->data_arena_size;
      ctx->meta.meta_tail_off = 0;
      ctx->meta.meta_tail_block_erased = false;
    }
  }
  ctx->tail_block_buf = (uint8_t *) malloc(ctx->block_size);
  if (ctx->tail_block_buf == NULL) {
    LOG(LL_ERROR, ("Failed to allocate block buffer!"));
    goto out;
  }
  ctx->head_block_off = get_block_off(ctx, ctx->meta.head_off);
  ctx->tail_block_off = get_block_off(ctx, ctx->meta.tail_off);
  bts_data_store_dev_new_tail_block(ctx, ctx->tail_block_off);
  size_t to_read = (ctx->meta.tail_off - ctx->tail_block_off);
  if (to_read > 0) {
    /* Page in tail block contents. */
    if (mgos_vfs_dev_read(ctx->dev, ctx->tail_block_off, to_read,
                          ctx->tail_block_buf) != 0) {
      LOG(LL_ERROR, ("Failed to read tail block!"));
      goto out;
    }
  }
  ctx->data_dirty = false;
  ctx->meta_dirty = false;

  LOG(LL_INFO,
      ("dev %p, bs %lu, data/meta %lu/%lu; nr %lu bu %lu bf %lu", ctx->dev,
       (unsigned long) ctx->block_size, (unsigned long) ctx->data_arena_size,
       (unsigned long) ctx->meta_arena_size,
       (unsigned long) ctx->meta.stats.num_records,
       (unsigned long) ctx->meta.stats.bytes_used,
       (unsigned long) ctx->meta.stats.bytes_free));

  res = true;

out:
  if (!res) {
    if (ds != NULL && ctx != NULL) {
      bts_data_store_dev_destroy(ds);
    } else if (ds != NULL) {
      free(ds);
    }
    ds = NULL;
  }
  return ds;
}

static void bts_data_store_dev_destroy(struct bts_data_store *ds) {
  struct bts_data_store_dev_ctx *ctx =
      (struct bts_data_store_dev_ctx *) ds->ctx;
  if (ctx->dev && ctx->own_dev) mgos_vfs_dev_close(ctx->dev);
  free(ctx->tail_block_buf);
  mgos_rlock_destroy(ctx->lock);
  free(ctx);
  memset(ds, 0, sizeof(*ds));
  free(ds);
}
