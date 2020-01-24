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

#ifndef CS_MOS_LIBS_BTS_DATA_TEST_BTS_DATA_STORE_TEST_UTIL_H_
#define CS_MOS_LIBS_BTS_DATA_TEST_BTS_DATA_STORE_TEST_UTIL_H_

#include "bts_data.h"

#ifdef __cplusplus
extern "C" {
#endif

const char *push_back_str(struct bts_data_store *ds, int i, struct mg_str data,
                          enum bts_data_store_status exp_st);

const char *push_back(struct bts_data_store *ds, int i, const char *s,
                      enum bts_data_store_status exp_st);

const char *pop_front_str(struct bts_data_store *ds, int i, size_t max_size,
                          enum bts_data_store_status exp_st,
                          struct mg_str *data);

const char *pop_front(struct bts_data_store *ds, int i, const char *s,
                      enum bts_data_store_status exp_st);

typedef struct bts_data_store *(*ds_create_f)(const struct mg_str meta);
const char *random_test(ds_create_f cf, size_t max_len, int num_iterations,
                        bool test_reload);

#ifdef __cplusplus
}
#endif

#endif /* CS_MOS_LIBS_BTS_DATA_TEST_BTS_DATA_STORE_TEST_UTIL_H_ */
