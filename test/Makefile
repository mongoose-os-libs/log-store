.PHONY: clean test
.DEFAULT_GOAL := test

MGOS_PATH ?= ../../..
MGOS_LIBS_PATH ?= ../../../mos_libs
include $(MGOS_PATH)/fw/common.mk

VPATH = ../src $(MGOS_VPATH) \
        $(MGOS_LIBS_PATH)/vfs-common/src \
        $(MGOS_LIBS_PATH)/vfs-dev-ram/src

MGOS_IFLAGS += -I$(MGOS_LIBS_PATH)/vfs-common/include \
               -I$(MGOS_LIBS_PATH)/vfs-dev-ram/include

TEST_FILTER ?=

COMMON_SOURCES = bts_data_store_test_util.c \
                 cs_dbg.c cs_file.c cs_time.c \
                 frozen.c json_utils.c mbuf.c mg_str.c \
                 mgos_config.c mgos_config_util.c mgos_mocks.c \
                 rtc_wake_stub_cs_varint32.c \
                 str_util.c test_util.c test_main.c

CFLAGS = -O0 -ggdb -Wall -Wextra -Werror -fsanitize=address \
         -I. -I../include -I../src $(MGOS_IFLAGS) -DUNIT_TEST \
         -ffunction-sections -fdata-sections -Wl,--gc-sections
CC = $(wildcard /usr/bin/clang)
ifeq "$(CC)" ""
CC = clang-3.6
endif

bts_data_store_ram_test: $(COMMON_SOURCES) bts_data_store_ram.c rtc_wake_stub_bts_data_store_ram.c bts_data_store_ram_test.c
	$(CC) $(CFLAGS) $^ -o $@

run_bts_data_store_ram_test: bts_data_store_ram_test
	./bts_data_store_ram_test $(TEST_FILTER)

bts_data_store_dev_test: $(COMMON_SOURCES) bts_data_store_dev.c bts_data_store_dev_test.c frozen.c mgos_vfs_dev.c mgos_vfs_dev_ram.c
	$(CC) $(CFLAGS) $^ -o $@

run_bts_data_store_dev_test: bts_data_store_dev_test
	./bts_data_store_dev_test $(TEST_FILTER) 

test: clean run_bts_data_store_ram_test run_bts_data_store_dev_test

clean:
	rm -f bts_data_store_ram_test bts_data_store_dev_test
