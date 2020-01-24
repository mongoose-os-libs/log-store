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

#ifndef CS_MOS_LIBS_BTS_DATA_INCLUDE_CS_VARINT32_H_
#define CS_MOS_LIBS_BTS_DATA_INCLUDE_CS_VARINT32_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Returns number of bytes required to encode `num`. */
size_t cs_varint32_llen(uint32_t num);

/*
 * Encodes `num` into `buf`.
 * Returns number of bytes required to encode `num`.
 * Note: return value may be greater than `buf_size` but the function will only
 * write `buf_size` bytes.
 */
size_t cs_varint32_encode(uint32_t num, uint8_t *buf, size_t buf_size);

/*
 * Decodes varint stored in `buf`.
 * Stores the number of bytes consumed into `llen`.
 * If there aren't enough bytes in `buf` to decode a number, returns false.
 */
bool cs_varint32_decode(const uint8_t *buf, size_t buf_size, uint32_t *num,
                        size_t *llen);

uint32_t cs_varint32_decode_unsafe(const uint8_t *buf, int *llen);

#ifdef __cplusplus
}
#endif

#endif /* CS_MOS_LIBS_BTS_DATA_INCLUDE_CS_VARINT32_H_ */
