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

#ifndef CS_MOS_LIBS_BTS_DATA_INCLUDE_BTS_DATA_POINT_H_
#define CS_MOS_LIBS_BTS_DATA_INCLUDE_BTS_DATA_POINT_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

enum bts_data_type {
  BTS_DATA_TYPE_NONE = 0,
  BTS_DATA_TYPE_ACCEL = 1,
  BTS_DATA_TYPE_ACCEL_TEMP = 2, /* Accelerometer temp sensor reading. */
  BTS_DATA_TYPE_TEMP = 3,
};

struct bts_accel_data_point {
  int16_t x, y, z;
};

struct bts_accel_data_point_f {
  float x, y, z;
};

struct bts_accel_temp_data_point {
  int16_t temp;
};

struct bts_temp_data_point {
  int16_t die_temp;
  int16_t obj_temp;
};

struct bts_data_point {
  uint8_t type;
  uint64_t timestamp_ms;
  union {
    struct bts_accel_data_point adp;
    struct bts_accel_temp_data_point atdp;
    struct bts_temp_data_point tdp;
  } data;
} __attribute__((packed));
#define BTS_DATA_HEADER_SIZE (1 + 8)
#define BTS_ACCEL_DATA_SIZE \
  (BTS_DATA_HEADER_SIZE + sizeof(struct bts_accel_data_point))
#define BTS_ACCEL_TEMP_DATA_SIZE \
  (BTS_DATA_HEADER_SIZE + sizeof(struct bts_accel_temp_data_point))
#define BTS_TEMP_DATA_SIZE \
  (BTS_DATA_HEADER_SIZE + sizeof(struct bts_temp_data_point))

size_t bts_data_point_size(const struct bts_data_point *dp);

void bts_data_dump_point(const struct bts_data_point *dp);

#ifdef __cplusplus
}
#endif

#endif /* CS_MOS_LIBS_BTS_DATA_INCLUDE_BTS_DATA_POINT_H_ */
