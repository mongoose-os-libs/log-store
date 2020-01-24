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

#include "common/cs_dbg.h"

void bts_data_dump_point(const struct bts_data_point *dp) {
  switch (dp->type) {
    case BTS_DATA_TYPE_ACCEL: {
      const struct bts_accel_data_point *adp = &dp->data.adp;
      LOG(LL_INFO,
          ("A  %llu %d %d %d", dp->timestamp_ms, adp->x, adp->y, adp->z));
      break;
    }
    case BTS_DATA_TYPE_ACCEL_TEMP: {
      const struct bts_accel_temp_data_point *atdp = &dp->data.atdp;
      LOG(LL_INFO, ("AT %llu %d", dp->timestamp_ms, atdp->temp));
      break;
    }
    case BTS_DATA_TYPE_TEMP: {
      const struct bts_temp_data_point *tdp = &dp->data.tdp;
      LOG(LL_INFO,
          ("T  %llu %d %d", dp->timestamp_ms, tdp->die_temp, tdp->obj_temp));
      break;
    }
  }
}
