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

#ifndef CS_MOS_LIBS_BTS_DATA_INCLUDE_BTS_DATA_STORE_RAM_H_
#define CS_MOS_LIBS_BTS_DATA_INCLUDE_BTS_DATA_STORE_RAM_H_

#include <stdbool.h>
#include <stdint.h>

#include "mgos_sys_config.h"

#include "bts_data_store.h"

#ifdef __cplusplus
extern "C" {
#endif

struct bts_data_store_ram_ctx {
  uint8_t *buf;
  uint8_t *head, *tail;
  uint32_t size;
  bool own_buf;
  struct bts_data_store_stats stats;
  struct mgos_rlock_type *lock;
};

struct bts_data_store *bts_data_store_ram_create(
    const struct mgos_config_bts_data_ram *cfg);

bool bts_data_store_ram_init_with_buffer(struct bts_data_store *ds,
                                         uint8_t *buf, size_t size);

void bts_data_store_ram_deinit(struct bts_data_store_ram_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* CS_MOS_LIBS_BTS_DATA_INCLUDE_BTS_DATA_STORE_RAM_H_ */
