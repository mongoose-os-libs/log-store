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

/* Nothing to see here, please move along... */

#if 0
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "common/cs_dbg.h"
#include "common/cs_file.h"

#include "frozen.h"
#include "mongoose.h"

#include "mgos_system.h"
#include "mgos_sys_config.h"
#include "mgos_vfs.h"

struct bts_data_store_file_ctx {
  const char *fpfx;
  const char *state_fname;
  int head_id, head_off, head_size;
  int tail_id, tail_off, tail_size;
  FILE *head_fp, *tail_fp;
  int max_size, max_num;
  bool dirty;
  struct bts_data_store_stats stats;
  size_t buf_size;
  struct mgos_rlock_type *lock;
};
#define STATE_FMT                                            \
  ("{head_id: %d, head_off: %d, tail_id: %d, tail_off: %d, " \
   "num_records: %lu, bytes_used: %lu, bytes_free: %lu}")

static FILE *bts_data_store_file_open(const char *fpfx, int id, int off,
                                      int *size, bool create) {
  char *fname = NULL;
  const char *mode;
  FILE *fp = NULL;

  mg_asprintf(&fname, 0, "%s.%04d", fpfx, id);

  struct stat st;
  if (stat(fname, &st) != 0) {
    if (create) {
      mode = "w";
      st.st_size = 0;
    } else {
      goto out;
    }
  } else {
    if (create) {
      mode = (off == 0 ? "w" : "r+");
    } else {
      mode = "r";
    }
  }
  *size = st.st_size;

  fp = fopen(fname, mode);
  if (fp == NULL) {
    LOG(LL_ERROR, ("Failed to open %s (mode %s)", fname, mode));
    goto out;
  }

  if (off <= *size) {
    fseek(fp, off, SEEK_SET);
  } else {
    fseek(fp, 0, SEEK_SET);
  }

  LOG(LL_DEBUG, ("Opened %s @ %d, mode %s", fname, off, mode));

out:
  free(fname);
  return fp;
}

static bool bts_data_store_file_open_head(struct bts_data_store_file_ctx *ctx) {
  ctx->head_fp =
      bts_data_store_file_open(ctx->fpfx, ctx->head_id, ctx->head_off,
                               &ctx->head_size, false /* create */);
  if (ctx->head_fp != NULL) {
    ctx->head_off = ftell(ctx->head_fp);
    setvbuf(ctx->head_fp, NULL, (ctx->buf_size > 0 ? _IOFBF : _IONBF),
            ctx->buf_size);
    LOG(LL_DEBUG, ("Head: %d @ %d", ctx->head_id, ctx->head_off));
  }
  return (ctx->head_fp != NULL);
}

static bool bts_data_store_file_open_tail(struct bts_data_store_file_ctx *ctx) {
  ctx->tail_fp =
      bts_data_store_file_open(ctx->fpfx, ctx->tail_id, ctx->tail_off,
                               &ctx->tail_size, true /* create */);
  if (ctx->tail_fp != NULL) {
    ctx->tail_off = ftell(ctx->tail_fp);
    setvbuf(ctx->tail_fp, NULL, (ctx->buf_size > 0 ? _IOFBF : _IONBF),
            ctx->buf_size);
    LOG(LL_DEBUG, ("Tail: %d @ %d", ctx->tail_id, ctx->tail_off));
  }
  return (ctx->tail_fp != NULL);
}

static bool bts_data_store_file_next_head(struct bts_data_store_file_ctx *ctx) {
  if (ctx->tail_id == ctx->head_id) {
    return true;
  }
  if (ctx->head_fp != NULL) {
    fclose(ctx->head_fp);
    ctx->head_fp = NULL;
  }
  ctx->head_id = (ctx->head_id + 1) % ctx->max_num;
  ctx->head_off = 0;
  return bts_data_store_file_open_head(ctx);
}

static bool bts_data_store_file_next_tail(struct bts_data_store_file_ctx *ctx,
                                          int next_tail_id) {
  if (ctx->tail_fp != NULL) {
    fclose(ctx->tail_fp);
    ctx->tail_fp = NULL;
  }
  ctx->tail_id = next_tail_id;
  ctx->tail_off = 0;
  return bts_data_store_file_open_tail(ctx);
}

static int bts_data_get_tail_avail(const struct bts_data_store_file_ctx *ctx) {
  int file_avail;
  if (ctx->head_id == ctx->tail_id && ctx->tail_off < ctx->head_off) {
    file_avail = ctx->tail_off - ctx->head_off;
  } else {
    file_avail = ctx->max_size - ctx->tail_off;
  }
  return file_avail;
}

enum bts_data_store_status bts_data_store_file_push(
    struct bts_data_store_file_ctx *ctx, const struct bts_data_point *dp) {
  if (ctx == NULL) return BTS_DATA_STATUS_ERR_SIZE;
  int dp_size = 0;
  enum bts_data_store_status st = BTS_DATA_STATUS_ERR;
  mgos_rlock(ctx->lock);
  if (ctx->fpfx == NULL) {
    goto out_unlock;
  }

  dp_size = bts_data_point_size(dp);
  if (dp_size == 0) goto out_unlock;

  int tail_avail = bts_data_get_tail_avail(ctx);
  if (tail_avail < dp_size) {
    int next_tail_id = (ctx->tail_id + 1) % ctx->max_num;
    /*
     * We cannot be reading and writing the same file because there is no
     * support for truncation.
     */
    if (ctx->head_id == next_tail_id) {
      st = BTS_DATA_STATUS_ERR_SIZE;
      goto out_unlock;
    }
    if (!bts_data_store_file_next_tail(ctx, next_tail_id)) goto out_unlock;
  }

  if (fwrite(dp, dp_size, 1, ctx->tail_fp) != 1) {
    goto out_unlock;
  }

  ctx->tail_off = ftell(ctx->tail_fp);
  ctx->tail_size = ctx->tail_off;
  if (ctx->head_id == ctx->tail_id) ctx->head_size = ctx->tail_size;
  ctx->stats.num_records++;
  ctx->stats.bytes_used += dp_size;
  ctx->stats.bytes_free -= dp_size;
  ctx->dirty = true;
  st = BTS_DATA_STATUS_OK;

out_unlock:
  mgos_runlock(ctx->lock);
  LOG(LL_DEBUG, ("dp_size %d st %d", dp_size, st));
  return st;
}

enum bts_data_store_status bts_data_store_file_pop(
    struct bts_data_store_file_ctx *ctx, size_t max_size,
    struct bts_data_point **dpp) {
  if (ctx == NULL) return BTS_DATA_STATUS_ERR_EMPTY;
  enum bts_data_store_status st = BTS_DATA_STATUS_ERR;
  size_t dp_size = 0;
  struct bts_data_point *dp = NULL, *ndp = NULL;
  mgos_rlock(ctx->lock);
  if (ctx->fpfx == NULL ||
      (ctx->head_id == ctx->tail_id &&
       (ctx->tail_off - ctx->head_off < BTS_DATA_HEADER_SIZE))) {
    st = BTS_DATA_STATUS_ERR_EMPTY;
    goto out_unlock;
  }
  if (max_size == 0) {
    st = BTS_DATA_STATUS_ERR_SIZE;
    goto out_unlock;
  }
  dp = (struct bts_data_point *) malloc(BTS_DATA_HEADER_SIZE);
  if (dp == NULL) goto out_unlock;
  if (ctx->head_fp == NULL && !bts_data_store_file_open_head(ctx)) {
    goto out_unlock;
  }
  if (ctx->head_id == ctx->tail_id && ctx->tail_fp != NULL) {
    fflush(ctx->tail_fp);
  }
  if (fread(dp, BTS_DATA_HEADER_SIZE, 1, ctx->head_fp) != 1) {
    /* Advance head and retry. */
    if (!bts_data_store_file_next_head(ctx) ||
        fread(dp, BTS_DATA_HEADER_SIZE, 1, ctx->head_fp) != 1) {
      goto out_unlock;
    }
  }
  dp_size = bts_data_point_size(dp);
  if (dp_size <= BTS_DATA_HEADER_SIZE) goto out_unlock;
  if (dp_size > max_size) {
    fseek(ctx->head_fp, ctx->head_off, SEEK_SET);
    st = BTS_DATA_STATUS_ERR_SIZE;
    goto out_unlock;
  }
  ndp = (struct bts_data_point *) realloc(dp, dp_size);
  if (ndp == NULL) goto out_unlock;
  dp = ndp;
  ndp = NULL;
  size_t to_read = dp_size - BTS_DATA_HEADER_SIZE;
  if (to_read > 0 &&
      fread(((uint8_t *) dp) + BTS_DATA_HEADER_SIZE, 1, to_read,
            ctx->head_fp) != to_read) {
    goto out_unlock;
  }
  ctx->head_off = ftell(ctx->head_fp);
  if (ctx->head_off >= ctx->head_size && !bts_data_store_file_next_head(ctx)) {
    goto out_unlock;
  }
  ctx->stats.num_records--;
  ctx->stats.bytes_used -= dp_size;
  ctx->stats.bytes_free += dp_size;
  ctx->dirty = true;
  st = BTS_DATA_STATUS_OK;

out_unlock:
  mgos_runlock(ctx->lock);
  if (dp != NULL && st != BTS_DATA_STATUS_OK) {
    free(dp);
    dp = NULL;
  }
  *dpp = dp;
  LOG(LL_DEBUG, ("max_size %u dp_size %u st %d", max_size, dp_size, st));
  return st;
}

void bts_data_store_file_get_stats(struct bts_data_store_file_ctx *ctx,
                                   struct bts_data_store_stats *stats) {
  memset(stats, 0, sizeof(*stats));
  if (ctx == NULL) return;
  mgos_rlock(ctx->lock);
  if (ctx->fpfx != NULL) {
    LOG(LL_DEBUG, ("head: %d @ %d size %d, tail: %d @ %d size %d", ctx->head_id,
                   ctx->head_off, ctx->head_size, ctx->tail_id, ctx->tail_off,
                   ctx->tail_size));
    memcpy(stats, &ctx->stats, sizeof(*stats));
  }
  mgos_runlock(ctx->lock);
}

static bool bts_data_store_file_load_state(
    struct bts_data_store_file_ctx *ctx) {
  bool res = false;
  char *fdata = NULL;

  if (ctx->state_fname == NULL) goto out;

  size_t fsize = 0;
  fdata = cs_read_file(ctx->state_fname, &fsize);
  if (fdata == NULL) goto out;

  LOG(LL_DEBUG, ("'%.*s'", (int) fsize, fdata));
  if (json_scanf(fdata, fsize, STATE_FMT, &ctx->head_id, &ctx->head_off,
                 &ctx->tail_id, &ctx->tail_off, &ctx->stats.num_records,
                 &ctx->stats.bytes_used, &ctx->stats.bytes_free) != 8) {
    LOG(LL_ERROR, ("Invalid state: '%.*s'", (int) fsize, fdata));
    goto out;
  }

  res = true;

out:
  free(fdata);
  return res;
}

static bool bts_data_store_file_save_state(
    struct bts_data_store_file_ctx *ctx) {
  bool res = false;
  FILE *fp = NULL;

  if (ctx->state_fname == NULL) goto out;

  fp = fopen(ctx->state_fname, "w");
  if (fp == NULL) goto out;

  struct json_out out = JSON_OUT_FILE(fp);
  if (json_printf(&out, STATE_FMT, ctx->head_id, ctx->head_off, ctx->tail_id,
                  ctx->tail_off, ctx->stats.num_records, ctx->stats.bytes_used,
                  ctx->stats.bytes_free) < 0) {
    goto out;
  }

  res = true;

out:
  if (fp != NULL) fclose(fp);
  if (!res) LOG(LL_ERROR, ("Failed to save state!"));
  return res;
}

void bts_data_store_file_flush(struct bts_data_store_file_ctx *ctx) {
  if (ctx == NULL) return;

  mgos_rlock(ctx->lock);
  if (!ctx->dirty || ctx->state_fname == NULL) goto out_unlock;
  if (ctx->head_fp) fflush(ctx->head_fp);
  if (ctx->tail_fp) fflush(ctx->tail_fp);
  if (ctx->state_fname != NULL && bts_data_store_file_save_state(ctx)) {
    ctx->dirty = false;
  }

out_unlock:
  mgos_runlock(ctx->lock);
}

bool bts_data_store_file_init_mount(
    const struct mgos_config_bts_data_file_mount *mcfg) {
  bool res = false;

  if (mcfg->enable) {
    res = true;
    goto out;
  }

  if (!mgos_vfs_mount("/data", mcfg->dev_type, mcfg->dev_opts, mcfg->fs_type,
                      mcfg->fs_opts)) {
    LOG(LL_WARN, ("/data mount failed, trying to create..."));
    if (!mgos_vfs_mkfs(mcfg->dev_type, mcfg->dev_opts, mcfg->fs_type,
                       mcfg->fs_opts)) {
      LOG(LL_ERROR, ("Failed to create /data FS!"));
      goto out;
    }
    if (!mgos_vfs_mount("/data", mcfg->dev_type, mcfg->dev_opts, mcfg->fs_type,
                        mcfg->fs_opts)) {
      goto out;
    }
  }
  /* Perform GC now to minimize number of erases. */
  mgos_vfs_gc("/data");
  res = true;
out:
  return res;
}

struct bts_data_store_file_ctx *bts_data_store_file_create(
    const struct mgos_config_bts_data_file *cfg) {
  bool res = false;
  struct bts_data_store_file_ctx *ctx =
      (struct bts_data_store_file_ctx *) calloc(1, sizeof(*ctx));
  if (ctx == NULL) goto out;

  ctx->lock = mgos_rlock_create();

  if (!cfg->enable) {
    LOG(LL_INFO, ("Spooling to file disabled"));
    res = true;
    goto out;
  }

  if (!bts_data_store_file_init_mount(&cfg->mount)) goto out;

  ctx->fpfx = cfg->data_prefix;
  if (ctx->fpfx == NULL) {
    LOG(LL_ERROR, ("Data file prefix is not set!"));
    goto out;
  }
  ctx->fpfx = strdup(ctx->fpfx);
  ctx->max_num = cfg->max_num;
  ctx->max_size = cfg->max_size;
  ctx->buf_size = cfg->buf_size;

  if (cfg->state_file != NULL) {
    ctx->state_fname = strdup(cfg->state_file);
  }

  int total_size = ctx->max_num * ctx->max_size;
  if (!bts_data_store_file_load_state(ctx)) {
    LOG(LL_WARN, ("No state file, going to start from scratch."));
    ctx->head_id = ctx->tail_id = 0;
    ctx->head_off = ctx->tail_off = 0;
    ctx->stats.num_records = 0;
    ctx->stats.bytes_used = 0;
    ctx->stats.bytes_free = ctx->max_num * ctx->max_size;
  }

  LOG(LL_INFO, ("%s, %d files, %d max size (%d total)", ctx->fpfx, ctx->max_num,
                ctx->max_size, total_size));

  res =
      bts_data_store_file_open_tail(ctx) && bts_data_store_file_open_head(ctx);
  if (!res) goto out;

  if (ctx->head_id == ctx->tail_id) ctx->head_size = ctx->tail_off;

  res = true;

out:
  if (!res && ctx != NULL) {
    if (ctx->head_fp != NULL) fclose(ctx->head_fp);
    if (ctx->tail_fp != NULL) fclose(ctx->tail_fp);
    free((void *) ctx->fpfx);
    free((void *) ctx->state_fname);
    free(ctx);
    ctx = NULL;
  }

  return ctx;
}
#endif
