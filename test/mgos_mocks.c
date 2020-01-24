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

#include <assert.h>
#include <stdlib.h>

#include "mgos_system.h"

struct mgos_rlock_type {
  int lock;
};

struct mgos_rlock_type *mgos_rlock_create(void) {
  return (struct mgos_rlock_type *) calloc(1, sizeof(struct mgos_rlock_type));
}

void mgos_rlock(struct mgos_rlock_type *l) {
  l->lock++;
}

void mgos_runlock(struct mgos_rlock_type *l) {
  assert(l->lock > 0);
  l->lock--;
}

void mgos_rlock_destroy(struct mgos_rlock_type *l) {
  assert(l->lock == 0);
  free(l);
}

size_t mgos_get_free_heap_size(void) {
  return 0;
}
