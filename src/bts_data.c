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

#include "bts_data.h"

#include <stdlib.h>
#include <string.h>

#include "common/cs_dbg.h"
#include "common/cs_time.h"

#include "mgos_hal.h"
#include "mgos_sys_config.h"
#include "mgos_timers.h"

#include "bts_data_store_dev.h"
#include "bts_data_store_file.h"
#include "bts_data_store_ram.h"

static struct bts_data_store *s_ram_ds = NULL;
static struct bts_data_store *s_dev_ds = NULL;
static struct bts_data_store *s_file_ds = NULL;
static size_t s_num_dropped = 0;

static enum bts_data_store_status bts_data_push_to_file(const struct mg_str dp);

static enum bts_data_store_status bts_data_push_to_dev(const struct mg_str dp) {
  enum bts_data_store_status st = BTS_DATA_STATUS_ERR;
  struct mg_str ddp = MG_NULL_STR, fdp = MG_NULL_STR;
  while (true) {
    st = s_dev_ds->ops->push_back(s_dev_ds, dp);
    if (st != BTS_DATA_STATUS_ERR_SIZE) break;
    st = s_dev_ds->ops->pop_front(s_dev_ds, BTS_DATA_POINT_MAX_SIZE_ANY, &ddp);
    if (st != BTS_DATA_STATUS_OK) {
      if (st != BTS_DATA_STATUS_ERR_EMPTY) break;
      fdp = dp;
    } else {
      fdp = ddp;
    }
    st = bts_data_push_to_file(fdp);
    if (st != BTS_DATA_STATUS_OK) {
      s_num_dropped++;
      free((void *) ddp.p);
      ddp.p = NULL;
    } else if (fdp.p == dp.p) {
      break;
    }
  }

  free((void *) ddp.p);
  return st;
}

static enum bts_data_store_status bts_data_push_to_file(
    const struct mg_str dp) {
  enum bts_data_store_status st = BTS_DATA_STATUS_ERR;
  struct mg_str fdp = MG_NULL_STR;

  while (true) {
    st = s_file_ds->ops->push_back(s_file_ds, dp);
    if (st != BTS_DATA_STATUS_ERR_SIZE) break;
    st =
        s_file_ds->ops->pop_front(s_file_ds, BTS_DATA_POINT_MAX_SIZE_ANY, &fdp);
    if (st != BTS_DATA_STATUS_OK) break;
    /* There is nowhere else for it to go, R.I.P. */
    s_num_dropped++;
    free((void *) fdp.p);
    fdp.p = NULL;
  }

  free((void *) fdp.p);
  return st;
}

enum bts_data_store_status bts_data_push(const struct mg_str data) {
  enum bts_data_store_status st = BTS_DATA_STATUS_ERR;

  while (true) {
    st = s_ram_ds->ops->push_back(s_ram_ds, data);
    if (st != BTS_DATA_STATUS_ERR_SIZE) goto out;
    struct mg_str rdp = MG_NULL_STR;
    st = s_ram_ds->ops->pop_front(s_ram_ds, BTS_DATA_POINT_MAX_SIZE_ANY, &rdp);
    if (st != BTS_DATA_STATUS_OK) goto out;
    st = bts_data_push_to_dev(rdp);
    if (st != BTS_DATA_STATUS_OK) {
      /* Ok this didn't go anywhere, count as a casualty. */
      s_num_dropped++;
    }
    free((void *) rdp.p);
  }

out:
  return st;
}

enum bts_data_store_status bts_data_push_point(
    const struct bts_data_point *dp) {
  struct mg_str data = MG_NULL_STR;
  data.len = bts_data_point_size(dp);
  data.p = (const char *) dp;
  return bts_data_push(data);
}

enum bts_data_store_status bts_data_pop(size_t max_size, struct mg_str *data) {
  enum bts_data_store_status st =
      s_file_ds->ops->pop_front(s_file_ds, max_size, data);
  if (st != BTS_DATA_STATUS_ERR_EMPTY) return st;
  st = s_dev_ds->ops->pop_front(s_dev_ds, max_size, data);
  if (st != BTS_DATA_STATUS_ERR_EMPTY) return st;
  return s_ram_ds->ops->pop_front(s_ram_ds, max_size, data);
}

enum bts_data_store_status bts_data_pop_point(size_t max_size,
                                              struct bts_data_point **dpp) {
  struct mg_str data = MG_NULL_STR;
  enum bts_data_store_status st = bts_data_push(data);
  if (st == BTS_DATA_STATUS_OK) {
    *dpp = (struct bts_data_point *) data.p;
  }
  return st;
}

bool bts_data_get_packet(size_t max_size, struct bts_data_packet_header **dpp) {
  static uint16_t s_seq = 0;

  bool res = false;

  if (max_size < sizeof(struct bts_data_packet_header)) goto out;

  struct bts_data_packet_header *dp =
      (struct bts_data_packet_header *) calloc(max_size, 1);
  *dpp = dp;
  if (dp == NULL) goto out;

  dp->num_points = 0;
  dp->size = sizeof(struct bts_data_packet_header);
  max_size -= sizeof(struct bts_data_packet_header);
  uint8_t *p = ((uint8_t *) dp) + dp->size;

  while (max_size > 0) {
    struct bts_data_point *tdp;
    if (bts_data_pop_point(max_size, &tdp) != BTS_DATA_STATUS_OK) break;
    size_t tdp_size = bts_data_point_size(tdp);
    memcpy(p, tdp, tdp_size);
    dp->num_points++;
    dp->size += tdp_size;
    max_size -= tdp_size;
    p += tdp_size;
    free(tdp);
  }

  if (dp->num_points > 0) {
    dp->seq = s_seq++;
  }

  res = true;
out:
  if (res) {
    if (dp->num_points > 0) {
      LOG(LL_DEBUG, ("pkt seq %d: %d pts (%d bytes)", (int) dp->seq,
                     (int) dp->num_points, (int) dp->size));
    }
    dp = (struct bts_data_packet_header *) realloc(*dpp, (*dpp)->size);
    if (dp != NULL) *dpp = dp;
  } else {
    free(*dpp);
    *dpp = NULL;
  }
  return res;
}

void bts_data_get_stats(struct bts_data_store_stats *ram_stats,
                        struct bts_data_store_stats *dev_stats,
                        struct bts_data_store_stats *file_stats,
                        size_t *num_dropped) {
  if (ram_stats != NULL) s_ram_ds->ops->get_stats(s_ram_ds, ram_stats);
  if (dev_stats != NULL) s_dev_ds->ops->get_stats(s_dev_ds, dev_stats);
  if (file_stats != NULL) s_file_ds->ops->get_stats(s_file_ds, file_stats);
  if (num_dropped != NULL) *num_dropped = s_num_dropped;
}

static void bts_data_ram_flush_timer_cb(void *arg);

void bts_data_flush(double max_time) {
  int num_flushed = 0, bytes_flushed = 0;
  double start = cs_time(), elapsed = 0;
  struct bts_data_store_stats ram_stats;
  while (true) {
    s_ram_ds->ops->get_stats(s_ram_ds, &ram_stats);
    if (ram_stats.num_records == 0) break;
    struct mg_str rdp = MG_NULL_STR;
    enum bts_data_store_status st =
        s_ram_ds->ops->pop_front(s_ram_ds, BTS_DATA_POINT_MAX_SIZE_ANY, &rdp);
    if (st != BTS_DATA_STATUS_OK) break;
    if (bts_data_push_to_dev(rdp) == BTS_DATA_STATUS_OK) {
      num_flushed++;
      bytes_flushed += rdp.len;
    } else {
      s_num_dropped++;
    }
    free((void *) rdp.p);
    elapsed = cs_time() - start;
    if (max_time >= 0 && elapsed > max_time) {
      mgos_set_timer(1000, 0, bts_data_ram_flush_timer_cb, NULL);
      break;
    }
  }

  if (ram_stats.num_records == 0) {
    s_dev_ds->ops->flush(s_dev_ds);
    s_file_ds->ops->flush(s_file_ds);
  }

  LOG((num_flushed > 0 ? LL_INFO : LL_DEBUG),
      ("Flushed %d pts (%d bytes), took %d ms", num_flushed, bytes_flushed,
       (int) (elapsed * 1000)));
}

static void bts_data_ram_flush_timer_cb(void *arg) {
  bts_data_flush(0.100);
}

static void stats_timer_cb(void *arg) {
  struct bts_data_store_stats ram_stats, dev_stats, file_stats;
  size_t num_dropped;
  bts_data_get_stats(&ram_stats, &dev_stats, &file_stats, &num_dropped);
  LOG(LL_INFO,
      ("RAM: %u pts, %u bytes free; dev: %u, %u; file: %u, %u; %u dropped; "
       "hf: %u",
       (unsigned) ram_stats.num_records, (unsigned) ram_stats.bytes_free,
       (unsigned) dev_stats.num_records, (unsigned) dev_stats.bytes_free,
       (unsigned) file_stats.num_records, (unsigned) file_stats.bytes_free,
       (unsigned) num_dropped, (unsigned) mgos_get_free_heap_size()));
}

bool mgos_bts_data_init(void) {
  bool res = false;

  s_file_ds = bts_data_store_file_create(mgos_sys_config_get_bts_data_file());
  if (s_file_ds == NULL) goto out;

  s_dev_ds = bts_data_store_dev_create(mgos_sys_config_get_bts_data_dev(),
                                       mg_mk_str(NULL), NULL);
  if (s_dev_ds == NULL) goto out;

  s_ram_ds = bts_data_store_ram_create(mgos_sys_config_get_bts_data_ram());
  if (s_ram_ds == NULL) goto out;

  int rfi = mgos_sys_config_get_bts_data_ram_flush_interval_ms();
  if (rfi > 0) {
    struct bts_data_store_stats ram_stats, dev_stats, file_stats;
    bts_data_get_stats(&ram_stats, &dev_stats, &file_stats, NULL);
    bool ram_enabled = (ram_stats.bytes_used + ram_stats.bytes_free > 0);
    bool dev_enabled = (dev_stats.bytes_used + dev_stats.bytes_free > 0);
    bool file_enabled = (file_stats.bytes_used + file_stats.bytes_free > 0);
    (void) file_enabled;
    if (ram_enabled && dev_enabled) {
      mgos_set_timer(rfi, MGOS_TIMER_REPEAT, bts_data_ram_flush_timer_cb, NULL);
    }
  }

  int data_stats_interval_ms = mgos_sys_config_get_bts_data_stats_interval_ms();
  if (data_stats_interval_ms > 0) {
    mgos_set_timer(data_stats_interval_ms, MGOS_TIMER_REPEAT, stats_timer_cb,
                   NULL);
  }

  res = true;

out:
  return res;
}
