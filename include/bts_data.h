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

#ifndef CS_MOS_LIBS_BTS_DATA_INCLUDE_BTS_DATA_H_
#define CS_MOS_LIBS_BTS_DATA_INCLUDE_BTS_DATA_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "common/mg_str.h"

#include "bts_data_point.h"
#include "bts_data_store.h"

#ifdef __cplusplus
extern "C" {
#endif

enum bts_data_store_status bts_data_push(const struct mg_str data);
enum bts_data_store_status bts_data_push_point(const struct bts_data_point *dp);

#define BTS_DATA_POINT_MAX_SIZE_ANY ((size_t) -1)
/* *dpp must be free()d. */
enum bts_data_store_status bts_data_pop(size_t max_size, struct mg_str *data);
enum bts_data_store_status bts_data_pop_point(size_t max_size,
                                              struct bts_data_point **dpp);

struct bts_data_packet_header {
  uint32_t sid;
  uint16_t seq;
  uint16_t size;
  uint16_t num_points;
} __attribute__((packed));

/* *dp must be free()d. */
bool bts_data_get_packet(size_t max_size, struct bts_data_packet_header **dp);

void bts_data_get_stats(struct bts_data_store_stats *ram_stats,
                        struct bts_data_store_stats *dev_stats,
                        struct bts_data_store_stats *file_stats,
                        size_t *num_dropped);

void bts_data_flush(double max_time);

#ifdef __cplusplus
}
#endif

#endif /* CS_MOS_LIBS_BTS_DATA_INCLUDE_BTS_DATA_H_ */
