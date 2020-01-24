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

#ifndef CS_MOS_LIBS_BTS_DATA_INCLUDE_BTS_DATA_STORE_H_
#define CS_MOS_LIBS_BTS_DATA_INCLUDE_BTS_DATA_STORE_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "common/mg_str.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BTS_DATA_POINT_MAX_SIZE_ANY ((size_t) -1)

struct bts_data_store;

enum bts_data_store_status {
  BTS_DATA_STATUS_OK = 0,
  BTS_DATA_STATUS_ERR = 1,
  BTS_DATA_STATUS_ERR_SIZE = 2,
  BTS_DATA_STATUS_ERR_EMPTY = 3,
  BTS_DATA_STATUS_ERR_CORRUPT = 4,
};

struct bts_data_store_stats {
  uint32_t num_records;
  uint32_t bytes_used;
  uint32_t bytes_free;
};

struct bts_data_store_ops {
  enum bts_data_store_status (*push_back)(struct bts_data_store *ds,
                                          const struct mg_str data);
  /* data->p must be free()d. */
  enum bts_data_store_status (*pop_front)(struct bts_data_store *ds,
                                          size_t max_size, struct mg_str *data);
  bool (*flush)(struct bts_data_store *ds);
  /* meta->p must be free()d. */
  bool (*get_meta)(struct bts_data_store *ds, struct mg_str *meta);
  void (*get_stats)(struct bts_data_store *ds,
                    struct bts_data_store_stats *stats);
  void (*destroy)(struct bts_data_store *ds);
};

struct bts_data_store {
  const struct bts_data_store_ops *ops;
  void *ctx;
};

#ifdef __cplusplus
}
#endif

#endif /* CS_MOS_LIBS_BTS_DATA_INCLUDE_BTS_DATA_STORE_H_ */
