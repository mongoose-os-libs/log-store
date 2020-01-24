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

#include "bts_data_point.h"

/*
 * This file exists because simply marking functions with RTC_IRAM_ATTR
 * is not enough due to https://github.com/espressif/esp-idf/issues/1552.
 */
size_t bts_data_point_size(const struct bts_data_point *dp) {
  switch (dp->type) {
    case BTS_DATA_TYPE_ACCEL:
      return BTS_ACCEL_DATA_SIZE;
    case BTS_DATA_TYPE_ACCEL_TEMP:
      return BTS_ACCEL_TEMP_DATA_SIZE;
    case BTS_DATA_TYPE_TEMP:
      return BTS_TEMP_DATA_SIZE;
  }
  return 0;
}
