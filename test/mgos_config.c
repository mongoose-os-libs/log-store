/* Generated file - do not edit. */

#include <stddef.h>
#include "mgos_config.h"

const struct mgos_conf_entry mgos_config_schema_[163] = {
    {.type = CONF_TYPE_OBJECT, .key = "", .num_desc = 162},
    {.type = CONF_TYPE_OBJECT, .key = "update", .num_desc = 8},
    {.type = CONF_TYPE_INT,
     .key = "timeout",
     .offset = offsetof(struct mgos_config, update.timeout)},
    {.type = CONF_TYPE_INT,
     .key = "commit_timeout",
     .offset = offsetof(struct mgos_config, update.commit_timeout)},
    {.type = CONF_TYPE_STRING,
     .key = "url",
     .offset = offsetof(struct mgos_config, update.url)},
    {.type = CONF_TYPE_INT,
     .key = "interval",
     .offset = offsetof(struct mgos_config, update.interval)},
    {.type = CONF_TYPE_STRING,
     .key = "ssl_ca_file",
     .offset = offsetof(struct mgos_config, update.ssl_ca_file)},
    {.type = CONF_TYPE_STRING,
     .key = "ssl_client_cert_file",
     .offset = offsetof(struct mgos_config, update.ssl_client_cert_file)},
    {.type = CONF_TYPE_STRING,
     .key = "ssl_server_name",
     .offset = offsetof(struct mgos_config, update.ssl_server_name)},
    {.type = CONF_TYPE_BOOL,
     .key = "enable_post",
     .offset = offsetof(struct mgos_config, update.enable_post)},
    {.type = CONF_TYPE_OBJECT, .key = "device", .num_desc = 2},
    {.type = CONF_TYPE_STRING,
     .key = "id",
     .offset = offsetof(struct mgos_config, device.id)},
    {.type = CONF_TYPE_STRING,
     .key = "password",
     .offset = offsetof(struct mgos_config, device.password)},
    {.type = CONF_TYPE_OBJECT, .key = "debug", .num_desc = 8},
    {.type = CONF_TYPE_STRING,
     .key = "udp_log_addr",
     .offset = offsetof(struct mgos_config, debug.udp_log_addr)},
    {.type = CONF_TYPE_INT,
     .key = "level",
     .offset = offsetof(struct mgos_config, debug.level)},
    {.type = CONF_TYPE_STRING,
     .key = "filter",
     .offset = offsetof(struct mgos_config, debug.filter)},
    {.type = CONF_TYPE_INT,
     .key = "stdout_uart",
     .offset = offsetof(struct mgos_config, debug.stdout_uart)},
    {.type = CONF_TYPE_INT,
     .key = "stderr_uart",
     .offset = offsetof(struct mgos_config, debug.stderr_uart)},
    {.type = CONF_TYPE_INT,
     .key = "factory_reset_gpio",
     .offset = offsetof(struct mgos_config, debug.factory_reset_gpio)},
    {.type = CONF_TYPE_STRING,
     .key = "mg_mgr_hexdump_file",
     .offset = offsetof(struct mgos_config, debug.mg_mgr_hexdump_file)},
    {.type = CONF_TYPE_INT,
     .key = "mbedtls_level",
     .offset = offsetof(struct mgos_config, debug.mbedtls_level)},
    {.type = CONF_TYPE_OBJECT, .key = "sys", .num_desc = 9},
    {.type = CONF_TYPE_OBJECT, .key = "mount", .num_desc = 5},
    {.type = CONF_TYPE_STRING,
     .key = "path",
     .offset = offsetof(struct mgos_config, sys.mount.path)},
    {.type = CONF_TYPE_STRING,
     .key = "dev_type",
     .offset = offsetof(struct mgos_config, sys.mount.dev_type)},
    {.type = CONF_TYPE_STRING,
     .key = "dev_opts",
     .offset = offsetof(struct mgos_config, sys.mount.dev_opts)},
    {.type = CONF_TYPE_STRING,
     .key = "fs_type",
     .offset = offsetof(struct mgos_config, sys.mount.fs_type)},
    {.type = CONF_TYPE_STRING,
     .key = "fs_opts",
     .offset = offsetof(struct mgos_config, sys.mount.fs_opts)},
    {.type = CONF_TYPE_STRING,
     .key = "tz_spec",
     .offset = offsetof(struct mgos_config, sys.tz_spec)},
    {.type = CONF_TYPE_INT,
     .key = "wdt_timeout",
     .offset = offsetof(struct mgos_config, sys.wdt_timeout)},
    {.type = CONF_TYPE_STRING,
     .key = "pref_ota_lib",
     .offset = offsetof(struct mgos_config, sys.pref_ota_lib)},
    {.type = CONF_TYPE_STRING,
     .key = "conf_acl",
     .offset = offsetof(struct mgos_config, conf_acl)},
    {.type = CONF_TYPE_OBJECT, .key = "bt", .num_desc = 13},
    {.type = CONF_TYPE_BOOL,
     .key = "enable",
     .offset = offsetof(struct mgos_config, bt.enable)},
    {.type = CONF_TYPE_STRING,
     .key = "dev_name",
     .offset = offsetof(struct mgos_config, bt.dev_name)},
    {.type = CONF_TYPE_BOOL,
     .key = "adv_enable",
     .offset = offsetof(struct mgos_config, bt.adv_enable)},
    {.type = CONF_TYPE_STRING,
     .key = "scan_rsp_data_hex",
     .offset = offsetof(struct mgos_config, bt.scan_rsp_data_hex)},
    {.type = CONF_TYPE_BOOL,
     .key = "keep_enabled",
     .offset = offsetof(struct mgos_config, bt.keep_enabled)},
    {.type = CONF_TYPE_BOOL,
     .key = "allow_pairing",
     .offset = offsetof(struct mgos_config, bt.allow_pairing)},
    {.type = CONF_TYPE_INT,
     .key = "max_paired_devices",
     .offset = offsetof(struct mgos_config, bt.max_paired_devices)},
    {.type = CONF_TYPE_BOOL,
     .key = "random_address",
     .offset = offsetof(struct mgos_config, bt.random_address)},
    {.type = CONF_TYPE_OBJECT, .key = "gatts", .num_desc = 2},
    {.type = CONF_TYPE_INT,
     .key = "min_sec_level",
     .offset = offsetof(struct mgos_config, bt.gatts.min_sec_level)},
    {.type = CONF_TYPE_BOOL,
     .key = "require_pairing",
     .offset = offsetof(struct mgos_config, bt.gatts.require_pairing)},
    {.type = CONF_TYPE_BOOL,
     .key = "config_svc_enable",
     .offset = offsetof(struct mgos_config, bt.config_svc_enable)},
    {.type = CONF_TYPE_BOOL,
     .key = "debug_svc_enable",
     .offset = offsetof(struct mgos_config, bt.debug_svc_enable)},
    {.type = CONF_TYPE_OBJECT, .key = "i2c", .num_desc = 6},
    {.type = CONF_TYPE_BOOL,
     .key = "enable",
     .offset = offsetof(struct mgos_config, i2c.enable)},
    {.type = CONF_TYPE_INT,
     .key = "freq",
     .offset = offsetof(struct mgos_config, i2c.freq)},
    {.type = CONF_TYPE_BOOL,
     .key = "debug",
     .offset = offsetof(struct mgos_config, i2c.debug)},
    {.type = CONF_TYPE_INT,
     .key = "unit_no",
     .offset = offsetof(struct mgos_config, i2c.unit_no)},
    {.type = CONF_TYPE_INT,
     .key = "sda_gpio",
     .offset = offsetof(struct mgos_config, i2c.sda_gpio)},
    {.type = CONF_TYPE_INT,
     .key = "scl_gpio",
     .offset = offsetof(struct mgos_config, i2c.scl_gpio)},
    {.type = CONF_TYPE_OBJECT, .key = "wifi", .num_desc = 30},
    {.type = CONF_TYPE_OBJECT, .key = "sta", .num_desc = 13},
    {.type = CONF_TYPE_BOOL,
     .key = "enable",
     .offset = offsetof(struct mgos_config, wifi.sta.enable)},
    {.type = CONF_TYPE_STRING,
     .key = "ssid",
     .offset = offsetof(struct mgos_config, wifi.sta.ssid)},
    {.type = CONF_TYPE_STRING,
     .key = "pass",
     .offset = offsetof(struct mgos_config, wifi.sta.pass)},
    {.type = CONF_TYPE_STRING,
     .key = "user",
     .offset = offsetof(struct mgos_config, wifi.sta.user)},
    {.type = CONF_TYPE_STRING,
     .key = "anon_identity",
     .offset = offsetof(struct mgos_config, wifi.sta.anon_identity)},
    {.type = CONF_TYPE_STRING,
     .key = "cert",
     .offset = offsetof(struct mgos_config, wifi.sta.cert)},
    {.type = CONF_TYPE_STRING,
     .key = "key",
     .offset = offsetof(struct mgos_config, wifi.sta.key)},
    {.type = CONF_TYPE_STRING,
     .key = "ca_cert",
     .offset = offsetof(struct mgos_config, wifi.sta.ca_cert)},
    {.type = CONF_TYPE_STRING,
     .key = "ip",
     .offset = offsetof(struct mgos_config, wifi.sta.ip)},
    {.type = CONF_TYPE_STRING,
     .key = "netmask",
     .offset = offsetof(struct mgos_config, wifi.sta.netmask)},
    {.type = CONF_TYPE_STRING,
     .key = "gw",
     .offset = offsetof(struct mgos_config, wifi.sta.gw)},
    {.type = CONF_TYPE_STRING,
     .key = "nameserver",
     .offset = offsetof(struct mgos_config, wifi.sta.nameserver)},
    {.type = CONF_TYPE_STRING,
     .key = "dhcp_hostname",
     .offset = offsetof(struct mgos_config, wifi.sta.dhcp_hostname)},
    {.type = CONF_TYPE_OBJECT, .key = "ap", .num_desc = 15},
    {.type = CONF_TYPE_BOOL,
     .key = "enable",
     .offset = offsetof(struct mgos_config, wifi.ap.enable)},
    {.type = CONF_TYPE_STRING,
     .key = "ssid",
     .offset = offsetof(struct mgos_config, wifi.ap.ssid)},
    {.type = CONF_TYPE_STRING,
     .key = "pass",
     .offset = offsetof(struct mgos_config, wifi.ap.pass)},
    {.type = CONF_TYPE_BOOL,
     .key = "hidden",
     .offset = offsetof(struct mgos_config, wifi.ap.hidden)},
    {.type = CONF_TYPE_INT,
     .key = "channel",
     .offset = offsetof(struct mgos_config, wifi.ap.channel)},
    {.type = CONF_TYPE_INT,
     .key = "max_connections",
     .offset = offsetof(struct mgos_config, wifi.ap.max_connections)},
    {.type = CONF_TYPE_STRING,
     .key = "ip",
     .offset = offsetof(struct mgos_config, wifi.ap.ip)},
    {.type = CONF_TYPE_STRING,
     .key = "netmask",
     .offset = offsetof(struct mgos_config, wifi.ap.netmask)},
    {.type = CONF_TYPE_STRING,
     .key = "gw",
     .offset = offsetof(struct mgos_config, wifi.ap.gw)},
    {.type = CONF_TYPE_STRING,
     .key = "dhcp_start",
     .offset = offsetof(struct mgos_config, wifi.ap.dhcp_start)},
    {.type = CONF_TYPE_STRING,
     .key = "dhcp_end",
     .offset = offsetof(struct mgos_config, wifi.ap.dhcp_end)},
    {.type = CONF_TYPE_INT,
     .key = "trigger_on_gpio",
     .offset = offsetof(struct mgos_config, wifi.ap.trigger_on_gpio)},
    {.type = CONF_TYPE_INT,
     .key = "disable_after",
     .offset = offsetof(struct mgos_config, wifi.ap.disable_after)},
    {.type = CONF_TYPE_STRING,
     .key = "hostname",
     .offset = offsetof(struct mgos_config, wifi.ap.hostname)},
    {.type = CONF_TYPE_BOOL,
     .key = "keep_enabled",
     .offset = offsetof(struct mgos_config, wifi.ap.keep_enabled)},
    {.type = CONF_TYPE_OBJECT, .key = "http", .num_desc = 10},
    {.type = CONF_TYPE_BOOL,
     .key = "enable",
     .offset = offsetof(struct mgos_config, http.enable)},
    {.type = CONF_TYPE_STRING,
     .key = "listen_addr",
     .offset = offsetof(struct mgos_config, http.listen_addr)},
    {.type = CONF_TYPE_STRING,
     .key = "document_root",
     .offset = offsetof(struct mgos_config, http.document_root)},
    {.type = CONF_TYPE_STRING,
     .key = "ssl_cert",
     .offset = offsetof(struct mgos_config, http.ssl_cert)},
    {.type = CONF_TYPE_STRING,
     .key = "ssl_key",
     .offset = offsetof(struct mgos_config, http.ssl_key)},
    {.type = CONF_TYPE_STRING,
     .key = "ssl_ca_cert",
     .offset = offsetof(struct mgos_config, http.ssl_ca_cert)},
    {.type = CONF_TYPE_STRING,
     .key = "upload_acl",
     .offset = offsetof(struct mgos_config, http.upload_acl)},
    {.type = CONF_TYPE_STRING,
     .key = "hidden_files",
     .offset = offsetof(struct mgos_config, http.hidden_files)},
    {.type = CONF_TYPE_STRING,
     .key = "auth_domain",
     .offset = offsetof(struct mgos_config, http.auth_domain)},
    {.type = CONF_TYPE_STRING,
     .key = "auth_file",
     .offset = offsetof(struct mgos_config, http.auth_file)},
    {.type = CONF_TYPE_OBJECT, .key = "rpc", .num_desc = 22},
    {.type = CONF_TYPE_BOOL,
     .key = "enable",
     .offset = offsetof(struct mgos_config, rpc.enable)},
    {.type = CONF_TYPE_INT,
     .key = "max_frame_size",
     .offset = offsetof(struct mgos_config, rpc.max_frame_size)},
    {.type = CONF_TYPE_INT,
     .key = "max_queue_length",
     .offset = offsetof(struct mgos_config, rpc.max_queue_length)},
    {.type = CONF_TYPE_INT,
     .key = "default_out_channel_idle_close_timeout",
     .offset = offsetof(struct mgos_config,
                        rpc.default_out_channel_idle_close_timeout)},
    {.type = CONF_TYPE_STRING,
     .key = "acl_file",
     .offset = offsetof(struct mgos_config, rpc.acl_file)},
    {.type = CONF_TYPE_STRING,
     .key = "auth_domain",
     .offset = offsetof(struct mgos_config, rpc.auth_domain)},
    {.type = CONF_TYPE_STRING,
     .key = "auth_file",
     .offset = offsetof(struct mgos_config, rpc.auth_file)},
    {.type = CONF_TYPE_OBJECT, .key = "ws", .num_desc = 7},
    {.type = CONF_TYPE_BOOL,
     .key = "enable",
     .offset = offsetof(struct mgos_config, rpc.ws.enable)},
    {.type = CONF_TYPE_STRING,
     .key = "server_address",
     .offset = offsetof(struct mgos_config, rpc.ws.server_address)},
    {.type = CONF_TYPE_INT,
     .key = "reconnect_interval_min",
     .offset = offsetof(struct mgos_config, rpc.ws.reconnect_interval_min)},
    {.type = CONF_TYPE_INT,
     .key = "reconnect_interval_max",
     .offset = offsetof(struct mgos_config, rpc.ws.reconnect_interval_max)},
    {.type = CONF_TYPE_STRING,
     .key = "ssl_server_name",
     .offset = offsetof(struct mgos_config, rpc.ws.ssl_server_name)},
    {.type = CONF_TYPE_STRING,
     .key = "ssl_ca_file",
     .offset = offsetof(struct mgos_config, rpc.ws.ssl_ca_file)},
    {.type = CONF_TYPE_STRING,
     .key = "ssl_client_cert_file",
     .offset = offsetof(struct mgos_config, rpc.ws.ssl_client_cert_file)},
    {.type = CONF_TYPE_OBJECT, .key = "gatts", .num_desc = 1},
    {.type = CONF_TYPE_BOOL,
     .key = "enable",
     .offset = offsetof(struct mgos_config, rpc.gatts.enable)},
    {.type = CONF_TYPE_OBJECT, .key = "uart", .num_desc = 4},
    {.type = CONF_TYPE_INT,
     .key = "uart_no",
     .offset = offsetof(struct mgos_config, rpc.uart.uart_no)},
    {.type = CONF_TYPE_INT,
     .key = "baud_rate",
     .offset = offsetof(struct mgos_config, rpc.uart.baud_rate)},
    {.type = CONF_TYPE_INT,
     .key = "fc_type",
     .offset = offsetof(struct mgos_config, rpc.uart.fc_type)},
    {.type = CONF_TYPE_BOOL,
     .key = "wait_for_start_frame",
     .offset = offsetof(struct mgos_config, rpc.uart.wait_for_start_frame)},
    {.type = CONF_TYPE_OBJECT, .key = "sntp", .num_desc = 5},
    {.type = CONF_TYPE_BOOL,
     .key = "enable",
     .offset = offsetof(struct mgos_config, sntp.enable)},
    {.type = CONF_TYPE_STRING,
     .key = "server",
     .offset = offsetof(struct mgos_config, sntp.server)},
    {.type = CONF_TYPE_INT,
     .key = "retry_min",
     .offset = offsetof(struct mgos_config, sntp.retry_min)},
    {.type = CONF_TYPE_INT,
     .key = "retry_max",
     .offset = offsetof(struct mgos_config, sntp.retry_max)},
    {.type = CONF_TYPE_INT,
     .key = "update_interval",
     .offset = offsetof(struct mgos_config, sntp.update_interval)},
    {.type = CONF_TYPE_OBJECT, .key = "bts", .num_desc = 37},
    {.type = CONF_TYPE_OBJECT, .key = "data", .num_desc = 25},
    {.type = CONF_TYPE_OBJECT, .key = "ram", .num_desc = 1},
    {.type = CONF_TYPE_INT,
     .key = "size",
     .offset = offsetof(struct mgos_config, bts.data.ram.size)},
    {.type = CONF_TYPE_INT,
     .key = "ram_flush_interval_ms",
     .offset = offsetof(struct mgos_config, bts.data.ram_flush_interval_ms)},
    {.type = CONF_TYPE_OBJECT, .key = "dev", .num_desc = 5},
    {.type = CONF_TYPE_STRING,
     .key = "type",
     .offset = offsetof(struct mgos_config, bts.data.dev.type)},
    {.type = CONF_TYPE_STRING,
     .key = "opts",
     .offset = offsetof(struct mgos_config, bts.data.dev.opts)},
    {.type = CONF_TYPE_INT,
     .key = "size",
     .offset = offsetof(struct mgos_config, bts.data.dev.size)},
    {.type = CONF_TYPE_INT,
     .key = "block_size",
     .offset = offsetof(struct mgos_config, bts.data.dev.block_size)},
    {.type = CONF_TYPE_INT,
     .key = "meta_blocks",
     .offset = offsetof(struct mgos_config, bts.data.dev.meta_blocks)},
    {.type = CONF_TYPE_OBJECT, .key = "file", .num_desc = 12},
    {.type = CONF_TYPE_BOOL,
     .key = "enable",
     .offset = offsetof(struct mgos_config, bts.data.file.enable)},
    {.type = CONF_TYPE_OBJECT, .key = "mount", .num_desc = 5},
    {.type = CONF_TYPE_BOOL,
     .key = "enable",
     .offset = offsetof(struct mgos_config, bts.data.file.mount.enable)},
    {.type = CONF_TYPE_STRING,
     .key = "dev_type",
     .offset = offsetof(struct mgos_config, bts.data.file.mount.dev_type)},
    {.type = CONF_TYPE_STRING,
     .key = "dev_opts",
     .offset = offsetof(struct mgos_config, bts.data.file.mount.dev_opts)},
    {.type = CONF_TYPE_STRING,
     .key = "fs_type",
     .offset = offsetof(struct mgos_config, bts.data.file.mount.fs_type)},
    {.type = CONF_TYPE_STRING,
     .key = "fs_opts",
     .offset = offsetof(struct mgos_config, bts.data.file.mount.fs_opts)},
    {.type = CONF_TYPE_STRING,
     .key = "state_file",
     .offset = offsetof(struct mgos_config, bts.data.file.state_file)},
    {.type = CONF_TYPE_STRING,
     .key = "data_prefix",
     .offset = offsetof(struct mgos_config, bts.data.file.data_prefix)},
    {.type = CONF_TYPE_INT,
     .key = "max_size",
     .offset = offsetof(struct mgos_config, bts.data.file.max_size)},
    {.type = CONF_TYPE_INT,
     .key = "max_num",
     .offset = offsetof(struct mgos_config, bts.data.file.max_num)},
    {.type = CONF_TYPE_INT,
     .key = "buf_size",
     .offset = offsetof(struct mgos_config, bts.data.file.buf_size)},
    {.type = CONF_TYPE_INT,
     .key = "stats_interval_ms",
     .offset = offsetof(struct mgos_config, bts.data.stats_interval_ms)},
    {.type = CONF_TYPE_OBJECT, .key = "gatts", .num_desc = 1},
    {.type = CONF_TYPE_BOOL,
     .key = "enable",
     .offset = offsetof(struct mgos_config, bts.data.gatts.enable)},
    {.type = CONF_TYPE_OBJECT, .key = "accel", .num_desc = 7},
    {.type = CONF_TYPE_INT,
     .key = "addr",
     .offset = offsetof(struct mgos_config, bts.accel.addr)},
    {.type = CONF_TYPE_INT,
     .key = "wu_thr_mg",
     .offset = offsetof(struct mgos_config, bts.accel.wu_thr_mg)},
    {.type = CONF_TYPE_INT,
     .key = "wu_dur_ms",
     .offset = offsetof(struct mgos_config, bts.accel.wu_dur_ms)},
    {.type = CONF_TYPE_INT,
     .key = "burst_size",
     .offset = offsetof(struct mgos_config, bts.accel.burst_size)},
    {.type = CONF_TYPE_INT,
     .key = "burst_sampling_interval_ms",
     .offset =
         offsetof(struct mgos_config, bts.accel.burst_sampling_interval_ms)},
    {.type = CONF_TYPE_INT,
     .key = "sampling_interval_ms",
     .offset = offsetof(struct mgos_config, bts.accel.sampling_interval_ms)},
    {.type = CONF_TYPE_INT,
     .key = "temp_sampling_interval_ms",
     .offset =
         offsetof(struct mgos_config, bts.accel.temp_sampling_interval_ms)},
    {.type = CONF_TYPE_OBJECT, .key = "temp", .num_desc = 2},
    {.type = CONF_TYPE_INT,
     .key = "addr",
     .offset = offsetof(struct mgos_config, bts.temp.addr)},
    {.type = CONF_TYPE_INT,
     .key = "sampling_interval_ms",
     .offset = offsetof(struct mgos_config, bts.temp.sampling_interval_ms)},
};

const struct mgos_conf_entry *mgos_config_schema() {
  return mgos_config_schema_;
}

/* Global instance */
struct mgos_config mgos_sys_config;

/* Getters {{{ */
const struct mgos_config_update *mgos_config_get_update(
    struct mgos_config *cfg) {
  return &cfg->update;
}
int mgos_config_get_update_timeout(struct mgos_config *cfg) {
  return cfg->update.timeout;
}
int mgos_config_get_update_commit_timeout(struct mgos_config *cfg) {
  return cfg->update.commit_timeout;
}
const char *mgos_config_get_update_url(struct mgos_config *cfg) {
  return cfg->update.url;
}
int mgos_config_get_update_interval(struct mgos_config *cfg) {
  return cfg->update.interval;
}
const char *mgos_config_get_update_ssl_ca_file(struct mgos_config *cfg) {
  return cfg->update.ssl_ca_file;
}
const char *mgos_config_get_update_ssl_client_cert_file(
    struct mgos_config *cfg) {
  return cfg->update.ssl_client_cert_file;
}
const char *mgos_config_get_update_ssl_server_name(struct mgos_config *cfg) {
  return cfg->update.ssl_server_name;
}
int mgos_config_get_update_enable_post(struct mgos_config *cfg) {
  return cfg->update.enable_post;
}
const struct mgos_config_device *mgos_config_get_device(
    struct mgos_config *cfg) {
  return &cfg->device;
}
const char *mgos_config_get_device_id(struct mgos_config *cfg) {
  return cfg->device.id;
}
const char *mgos_config_get_device_password(struct mgos_config *cfg) {
  return cfg->device.password;
}
const struct mgos_config_debug *mgos_config_get_debug(struct mgos_config *cfg) {
  return &cfg->debug;
}
const char *mgos_config_get_debug_udp_log_addr(struct mgos_config *cfg) {
  return cfg->debug.udp_log_addr;
}
int mgos_config_get_debug_level(struct mgos_config *cfg) {
  return cfg->debug.level;
}
const char *mgos_config_get_debug_filter(struct mgos_config *cfg) {
  return cfg->debug.filter;
}
int mgos_config_get_debug_stdout_uart(struct mgos_config *cfg) {
  return cfg->debug.stdout_uart;
}
int mgos_config_get_debug_stderr_uart(struct mgos_config *cfg) {
  return cfg->debug.stderr_uart;
}
int mgos_config_get_debug_factory_reset_gpio(struct mgos_config *cfg) {
  return cfg->debug.factory_reset_gpio;
}
const char *mgos_config_get_debug_mg_mgr_hexdump_file(struct mgos_config *cfg) {
  return cfg->debug.mg_mgr_hexdump_file;
}
int mgos_config_get_debug_mbedtls_level(struct mgos_config *cfg) {
  return cfg->debug.mbedtls_level;
}
const struct mgos_config_sys *mgos_config_get_sys(struct mgos_config *cfg) {
  return &cfg->sys;
}
const struct mgos_config_sys_mount *mgos_config_get_sys_mount(
    struct mgos_config *cfg) {
  return &cfg->sys.mount;
}
const char *mgos_config_get_sys_mount_path(struct mgos_config *cfg) {
  return cfg->sys.mount.path;
}
const char *mgos_config_get_sys_mount_dev_type(struct mgos_config *cfg) {
  return cfg->sys.mount.dev_type;
}
const char *mgos_config_get_sys_mount_dev_opts(struct mgos_config *cfg) {
  return cfg->sys.mount.dev_opts;
}
const char *mgos_config_get_sys_mount_fs_type(struct mgos_config *cfg) {
  return cfg->sys.mount.fs_type;
}
const char *mgos_config_get_sys_mount_fs_opts(struct mgos_config *cfg) {
  return cfg->sys.mount.fs_opts;
}
const char *mgos_config_get_sys_tz_spec(struct mgos_config *cfg) {
  return cfg->sys.tz_spec;
}
int mgos_config_get_sys_wdt_timeout(struct mgos_config *cfg) {
  return cfg->sys.wdt_timeout;
}
const char *mgos_config_get_sys_pref_ota_lib(struct mgos_config *cfg) {
  return cfg->sys.pref_ota_lib;
}
const char *mgos_config_get_conf_acl(struct mgos_config *cfg) {
  return cfg->conf_acl;
}
const struct mgos_config_bt *mgos_config_get_bt(struct mgos_config *cfg) {
  return &cfg->bt;
}
int mgos_config_get_bt_enable(struct mgos_config *cfg) {
  return cfg->bt.enable;
}
const char *mgos_config_get_bt_dev_name(struct mgos_config *cfg) {
  return cfg->bt.dev_name;
}
int mgos_config_get_bt_adv_enable(struct mgos_config *cfg) {
  return cfg->bt.adv_enable;
}
const char *mgos_config_get_bt_scan_rsp_data_hex(struct mgos_config *cfg) {
  return cfg->bt.scan_rsp_data_hex;
}
int mgos_config_get_bt_keep_enabled(struct mgos_config *cfg) {
  return cfg->bt.keep_enabled;
}
int mgos_config_get_bt_allow_pairing(struct mgos_config *cfg) {
  return cfg->bt.allow_pairing;
}
int mgos_config_get_bt_max_paired_devices(struct mgos_config *cfg) {
  return cfg->bt.max_paired_devices;
}
int mgos_config_get_bt_random_address(struct mgos_config *cfg) {
  return cfg->bt.random_address;
}
const struct mgos_config_bt_gatts *mgos_config_get_bt_gatts(
    struct mgos_config *cfg) {
  return &cfg->bt.gatts;
}
int mgos_config_get_bt_gatts_min_sec_level(struct mgos_config *cfg) {
  return cfg->bt.gatts.min_sec_level;
}
int mgos_config_get_bt_gatts_require_pairing(struct mgos_config *cfg) {
  return cfg->bt.gatts.require_pairing;
}
int mgos_config_get_bt_config_svc_enable(struct mgos_config *cfg) {
  return cfg->bt.config_svc_enable;
}
int mgos_config_get_bt_debug_svc_enable(struct mgos_config *cfg) {
  return cfg->bt.debug_svc_enable;
}
const struct mgos_config_i2c *mgos_config_get_i2c(struct mgos_config *cfg) {
  return &cfg->i2c;
}
int mgos_config_get_i2c_enable(struct mgos_config *cfg) {
  return cfg->i2c.enable;
}
int mgos_config_get_i2c_freq(struct mgos_config *cfg) {
  return cfg->i2c.freq;
}
int mgos_config_get_i2c_debug(struct mgos_config *cfg) {
  return cfg->i2c.debug;
}
int mgos_config_get_i2c_unit_no(struct mgos_config *cfg) {
  return cfg->i2c.unit_no;
}
int mgos_config_get_i2c_sda_gpio(struct mgos_config *cfg) {
  return cfg->i2c.sda_gpio;
}
int mgos_config_get_i2c_scl_gpio(struct mgos_config *cfg) {
  return cfg->i2c.scl_gpio;
}
const struct mgos_config_wifi *mgos_config_get_wifi(struct mgos_config *cfg) {
  return &cfg->wifi;
}
const struct mgos_config_wifi_sta *mgos_config_get_wifi_sta(
    struct mgos_config *cfg) {
  return &cfg->wifi.sta;
}
int mgos_config_get_wifi_sta_enable(struct mgos_config *cfg) {
  return cfg->wifi.sta.enable;
}
const char *mgos_config_get_wifi_sta_ssid(struct mgos_config *cfg) {
  return cfg->wifi.sta.ssid;
}
const char *mgos_config_get_wifi_sta_pass(struct mgos_config *cfg) {
  return cfg->wifi.sta.pass;
}
const char *mgos_config_get_wifi_sta_user(struct mgos_config *cfg) {
  return cfg->wifi.sta.user;
}
const char *mgos_config_get_wifi_sta_anon_identity(struct mgos_config *cfg) {
  return cfg->wifi.sta.anon_identity;
}
const char *mgos_config_get_wifi_sta_cert(struct mgos_config *cfg) {
  return cfg->wifi.sta.cert;
}
const char *mgos_config_get_wifi_sta_key(struct mgos_config *cfg) {
  return cfg->wifi.sta.key;
}
const char *mgos_config_get_wifi_sta_ca_cert(struct mgos_config *cfg) {
  return cfg->wifi.sta.ca_cert;
}
const char *mgos_config_get_wifi_sta_ip(struct mgos_config *cfg) {
  return cfg->wifi.sta.ip;
}
const char *mgos_config_get_wifi_sta_netmask(struct mgos_config *cfg) {
  return cfg->wifi.sta.netmask;
}
const char *mgos_config_get_wifi_sta_gw(struct mgos_config *cfg) {
  return cfg->wifi.sta.gw;
}
const char *mgos_config_get_wifi_sta_nameserver(struct mgos_config *cfg) {
  return cfg->wifi.sta.nameserver;
}
const char *mgos_config_get_wifi_sta_dhcp_hostname(struct mgos_config *cfg) {
  return cfg->wifi.sta.dhcp_hostname;
}
const struct mgos_config_wifi_ap *mgos_config_get_wifi_ap(
    struct mgos_config *cfg) {
  return &cfg->wifi.ap;
}
int mgos_config_get_wifi_ap_enable(struct mgos_config *cfg) {
  return cfg->wifi.ap.enable;
}
const char *mgos_config_get_wifi_ap_ssid(struct mgos_config *cfg) {
  return cfg->wifi.ap.ssid;
}
const char *mgos_config_get_wifi_ap_pass(struct mgos_config *cfg) {
  return cfg->wifi.ap.pass;
}
int mgos_config_get_wifi_ap_hidden(struct mgos_config *cfg) {
  return cfg->wifi.ap.hidden;
}
int mgos_config_get_wifi_ap_channel(struct mgos_config *cfg) {
  return cfg->wifi.ap.channel;
}
int mgos_config_get_wifi_ap_max_connections(struct mgos_config *cfg) {
  return cfg->wifi.ap.max_connections;
}
const char *mgos_config_get_wifi_ap_ip(struct mgos_config *cfg) {
  return cfg->wifi.ap.ip;
}
const char *mgos_config_get_wifi_ap_netmask(struct mgos_config *cfg) {
  return cfg->wifi.ap.netmask;
}
const char *mgos_config_get_wifi_ap_gw(struct mgos_config *cfg) {
  return cfg->wifi.ap.gw;
}
const char *mgos_config_get_wifi_ap_dhcp_start(struct mgos_config *cfg) {
  return cfg->wifi.ap.dhcp_start;
}
const char *mgos_config_get_wifi_ap_dhcp_end(struct mgos_config *cfg) {
  return cfg->wifi.ap.dhcp_end;
}
int mgos_config_get_wifi_ap_trigger_on_gpio(struct mgos_config *cfg) {
  return cfg->wifi.ap.trigger_on_gpio;
}
int mgos_config_get_wifi_ap_disable_after(struct mgos_config *cfg) {
  return cfg->wifi.ap.disable_after;
}
const char *mgos_config_get_wifi_ap_hostname(struct mgos_config *cfg) {
  return cfg->wifi.ap.hostname;
}
int mgos_config_get_wifi_ap_keep_enabled(struct mgos_config *cfg) {
  return cfg->wifi.ap.keep_enabled;
}
const struct mgos_config_http *mgos_config_get_http(struct mgos_config *cfg) {
  return &cfg->http;
}
int mgos_config_get_http_enable(struct mgos_config *cfg) {
  return cfg->http.enable;
}
const char *mgos_config_get_http_listen_addr(struct mgos_config *cfg) {
  return cfg->http.listen_addr;
}
const char *mgos_config_get_http_document_root(struct mgos_config *cfg) {
  return cfg->http.document_root;
}
const char *mgos_config_get_http_ssl_cert(struct mgos_config *cfg) {
  return cfg->http.ssl_cert;
}
const char *mgos_config_get_http_ssl_key(struct mgos_config *cfg) {
  return cfg->http.ssl_key;
}
const char *mgos_config_get_http_ssl_ca_cert(struct mgos_config *cfg) {
  return cfg->http.ssl_ca_cert;
}
const char *mgos_config_get_http_upload_acl(struct mgos_config *cfg) {
  return cfg->http.upload_acl;
}
const char *mgos_config_get_http_hidden_files(struct mgos_config *cfg) {
  return cfg->http.hidden_files;
}
const char *mgos_config_get_http_auth_domain(struct mgos_config *cfg) {
  return cfg->http.auth_domain;
}
const char *mgos_config_get_http_auth_file(struct mgos_config *cfg) {
  return cfg->http.auth_file;
}
const struct mgos_config_rpc *mgos_config_get_rpc(struct mgos_config *cfg) {
  return &cfg->rpc;
}
int mgos_config_get_rpc_enable(struct mgos_config *cfg) {
  return cfg->rpc.enable;
}
int mgos_config_get_rpc_max_frame_size(struct mgos_config *cfg) {
  return cfg->rpc.max_frame_size;
}
int mgos_config_get_rpc_max_queue_length(struct mgos_config *cfg) {
  return cfg->rpc.max_queue_length;
}
int mgos_config_get_rpc_default_out_channel_idle_close_timeout(
    struct mgos_config *cfg) {
  return cfg->rpc.default_out_channel_idle_close_timeout;
}
const char *mgos_config_get_rpc_acl_file(struct mgos_config *cfg) {
  return cfg->rpc.acl_file;
}
const char *mgos_config_get_rpc_auth_domain(struct mgos_config *cfg) {
  return cfg->rpc.auth_domain;
}
const char *mgos_config_get_rpc_auth_file(struct mgos_config *cfg) {
  return cfg->rpc.auth_file;
}
const struct mgos_config_rpc_ws *mgos_config_get_rpc_ws(
    struct mgos_config *cfg) {
  return &cfg->rpc.ws;
}
int mgos_config_get_rpc_ws_enable(struct mgos_config *cfg) {
  return cfg->rpc.ws.enable;
}
const char *mgos_config_get_rpc_ws_server_address(struct mgos_config *cfg) {
  return cfg->rpc.ws.server_address;
}
int mgos_config_get_rpc_ws_reconnect_interval_min(struct mgos_config *cfg) {
  return cfg->rpc.ws.reconnect_interval_min;
}
int mgos_config_get_rpc_ws_reconnect_interval_max(struct mgos_config *cfg) {
  return cfg->rpc.ws.reconnect_interval_max;
}
const char *mgos_config_get_rpc_ws_ssl_server_name(struct mgos_config *cfg) {
  return cfg->rpc.ws.ssl_server_name;
}
const char *mgos_config_get_rpc_ws_ssl_ca_file(struct mgos_config *cfg) {
  return cfg->rpc.ws.ssl_ca_file;
}
const char *mgos_config_get_rpc_ws_ssl_client_cert_file(
    struct mgos_config *cfg) {
  return cfg->rpc.ws.ssl_client_cert_file;
}
const struct mgos_config_rpc_gatts *mgos_config_get_rpc_gatts(
    struct mgos_config *cfg) {
  return &cfg->rpc.gatts;
}
int mgos_config_get_rpc_gatts_enable(struct mgos_config *cfg) {
  return cfg->rpc.gatts.enable;
}
const struct mgos_config_rpc_uart *mgos_config_get_rpc_uart(
    struct mgos_config *cfg) {
  return &cfg->rpc.uart;
}
int mgos_config_get_rpc_uart_uart_no(struct mgos_config *cfg) {
  return cfg->rpc.uart.uart_no;
}
int mgos_config_get_rpc_uart_baud_rate(struct mgos_config *cfg) {
  return cfg->rpc.uart.baud_rate;
}
int mgos_config_get_rpc_uart_fc_type(struct mgos_config *cfg) {
  return cfg->rpc.uart.fc_type;
}
int mgos_config_get_rpc_uart_wait_for_start_frame(struct mgos_config *cfg) {
  return cfg->rpc.uart.wait_for_start_frame;
}
const struct mgos_config_sntp *mgos_config_get_sntp(struct mgos_config *cfg) {
  return &cfg->sntp;
}
int mgos_config_get_sntp_enable(struct mgos_config *cfg) {
  return cfg->sntp.enable;
}
const char *mgos_config_get_sntp_server(struct mgos_config *cfg) {
  return cfg->sntp.server;
}
int mgos_config_get_sntp_retry_min(struct mgos_config *cfg) {
  return cfg->sntp.retry_min;
}
int mgos_config_get_sntp_retry_max(struct mgos_config *cfg) {
  return cfg->sntp.retry_max;
}
int mgos_config_get_sntp_update_interval(struct mgos_config *cfg) {
  return cfg->sntp.update_interval;
}
const struct mgos_config_bts *mgos_config_get_bts(struct mgos_config *cfg) {
  return &cfg->bts;
}
const struct mgos_config_bts_data *mgos_config_get_bts_data(
    struct mgos_config *cfg) {
  return &cfg->bts.data;
}
const struct mgos_config_bts_data_ram *mgos_config_get_bts_data_store_ram(
    struct mgos_config *cfg) {
  return &cfg->bts.data.ram;
}
int mgos_config_get_bts_data_store_ram_size(struct mgos_config *cfg) {
  return cfg->bts.data.ram.size;
}
int mgos_config_get_bts_data_store_ram_flush_interval_ms(
    struct mgos_config *cfg) {
  return cfg->bts.data.ram_flush_interval_ms;
}
const struct mgos_config_bts_data_dev *mgos_config_get_bts_data_store_dev(
    struct mgos_config *cfg) {
  return &cfg->bts.data.dev;
}
const char *mgos_config_get_bts_data_store_dev_type(struct mgos_config *cfg) {
  return cfg->bts.data.dev.type;
}
const char *mgos_config_get_bts_data_store_dev_opts(struct mgos_config *cfg) {
  return cfg->bts.data.dev.opts;
}
int mgos_config_get_bts_data_store_dev_size(struct mgos_config *cfg) {
  return cfg->bts.data.dev.size;
}
int mgos_config_get_bts_data_store_dev_block_size(struct mgos_config *cfg) {
  return cfg->bts.data.dev.block_size;
}
int mgos_config_get_bts_data_store_dev_meta_blocks(struct mgos_config *cfg) {
  return cfg->bts.data.dev.meta_blocks;
}
const struct mgos_config_bts_data_file *mgos_config_get_bts_data_store_file(
    struct mgos_config *cfg) {
  return &cfg->bts.data.file;
}
int mgos_config_get_bts_data_store_file_enable(struct mgos_config *cfg) {
  return cfg->bts.data.file.enable;
}
const struct mgos_config_bts_data_file_mount *
mgos_config_get_bts_data_store_file_mount(struct mgos_config *cfg) {
  return &cfg->bts.data.file.mount;
}
int mgos_config_get_bts_data_store_file_mount_enable(struct mgos_config *cfg) {
  return cfg->bts.data.file.mount.enable;
}
const char *mgos_config_get_bts_data_store_file_mount_dev_type(
    struct mgos_config *cfg) {
  return cfg->bts.data.file.mount.dev_type;
}
const char *mgos_config_get_bts_data_store_file_mount_dev_opts(
    struct mgos_config *cfg) {
  return cfg->bts.data.file.mount.dev_opts;
}
const char *mgos_config_get_bts_data_store_file_mount_fs_type(
    struct mgos_config *cfg) {
  return cfg->bts.data.file.mount.fs_type;
}
const char *mgos_config_get_bts_data_store_file_mount_fs_opts(
    struct mgos_config *cfg) {
  return cfg->bts.data.file.mount.fs_opts;
}
const char *mgos_config_get_bts_data_store_file_state_file(
    struct mgos_config *cfg) {
  return cfg->bts.data.file.state_file;
}
const char *mgos_config_get_bts_data_store_file_data_prefix(
    struct mgos_config *cfg) {
  return cfg->bts.data.file.data_prefix;
}
int mgos_config_get_bts_data_store_file_max_size(struct mgos_config *cfg) {
  return cfg->bts.data.file.max_size;
}
int mgos_config_get_bts_data_store_file_max_num(struct mgos_config *cfg) {
  return cfg->bts.data.file.max_num;
}
int mgos_config_get_bts_data_store_file_buf_size(struct mgos_config *cfg) {
  return cfg->bts.data.file.buf_size;
}
int mgos_config_get_bts_data_store_stats_interval_ms(struct mgos_config *cfg) {
  return cfg->bts.data.stats_interval_ms;
}
const struct mgos_config_bts_data_gatts *mgos_config_get_bts_data_gatts(
    struct mgos_config *cfg) {
  return &cfg->bts.data.gatts;
}
int mgos_config_get_bts_data_gatts_enable(struct mgos_config *cfg) {
  return cfg->bts.data.gatts.enable;
}
const struct mgos_config_bts_accel *mgos_config_get_bts_accel(
    struct mgos_config *cfg) {
  return &cfg->bts.accel;
}
int mgos_config_get_bts_accel_addr(struct mgos_config *cfg) {
  return cfg->bts.accel.addr;
}
int mgos_config_get_bts_accel_wu_thr_mg(struct mgos_config *cfg) {
  return cfg->bts.accel.wu_thr_mg;
}
int mgos_config_get_bts_accel_wu_dur_ms(struct mgos_config *cfg) {
  return cfg->bts.accel.wu_dur_ms;
}
int mgos_config_get_bts_accel_burst_size(struct mgos_config *cfg) {
  return cfg->bts.accel.burst_size;
}
int mgos_config_get_bts_accel_burst_sampling_interval_ms(
    struct mgos_config *cfg) {
  return cfg->bts.accel.burst_sampling_interval_ms;
}
int mgos_config_get_bts_accel_sampling_interval_ms(struct mgos_config *cfg) {
  return cfg->bts.accel.sampling_interval_ms;
}
int mgos_config_get_bts_accel_temp_sampling_interval_ms(
    struct mgos_config *cfg) {
  return cfg->bts.accel.temp_sampling_interval_ms;
}
const struct mgos_config_bts_temp *mgos_config_get_bts_temp(
    struct mgos_config *cfg) {
  return &cfg->bts.temp;
}
int mgos_config_get_bts_temp_addr(struct mgos_config *cfg) {
  return cfg->bts.temp.addr;
}
int mgos_config_get_bts_temp_sampling_interval_ms(struct mgos_config *cfg) {
  return cfg->bts.temp.sampling_interval_ms;
}
/* }}} */

/* Setters {{{ */
void mgos_config_set_update_timeout(struct mgos_config *cfg, int val) {
  cfg->update.timeout = val;
}
void mgos_config_set_update_commit_timeout(struct mgos_config *cfg, int val) {
  cfg->update.commit_timeout = val;
}
void mgos_config_set_update_url(struct mgos_config *cfg, const char *val) {
  mgos_conf_set_str(&cfg->update.url, val);
}
void mgos_config_set_update_interval(struct mgos_config *cfg, int val) {
  cfg->update.interval = val;
}
void mgos_config_set_update_ssl_ca_file(struct mgos_config *cfg,
                                        const char *val) {
  mgos_conf_set_str(&cfg->update.ssl_ca_file, val);
}
void mgos_config_set_update_ssl_client_cert_file(struct mgos_config *cfg,
                                                 const char *val) {
  mgos_conf_set_str(&cfg->update.ssl_client_cert_file, val);
}
void mgos_config_set_update_ssl_server_name(struct mgos_config *cfg,
                                            const char *val) {
  mgos_conf_set_str(&cfg->update.ssl_server_name, val);
}
void mgos_config_set_update_enable_post(struct mgos_config *cfg, int val) {
  cfg->update.enable_post = val;
}
void mgos_config_set_device_id(struct mgos_config *cfg, const char *val) {
  mgos_conf_set_str(&cfg->device.id, val);
}
void mgos_config_set_device_password(struct mgos_config *cfg, const char *val) {
  mgos_conf_set_str(&cfg->device.password, val);
}
void mgos_config_set_debug_udp_log_addr(struct mgos_config *cfg,
                                        const char *val) {
  mgos_conf_set_str(&cfg->debug.udp_log_addr, val);
}
void mgos_config_set_debug_level(struct mgos_config *cfg, int val) {
  cfg->debug.level = val;
}
void mgos_config_set_debug_filter(struct mgos_config *cfg, const char *val) {
  mgos_conf_set_str(&cfg->debug.filter, val);
}
void mgos_config_set_debug_stdout_uart(struct mgos_config *cfg, int val) {
  cfg->debug.stdout_uart = val;
}
void mgos_config_set_debug_stderr_uart(struct mgos_config *cfg, int val) {
  cfg->debug.stderr_uart = val;
}
void mgos_config_set_debug_factory_reset_gpio(struct mgos_config *cfg,
                                              int val) {
  cfg->debug.factory_reset_gpio = val;
}
void mgos_config_set_debug_mg_mgr_hexdump_file(struct mgos_config *cfg,
                                               const char *val) {
  mgos_conf_set_str(&cfg->debug.mg_mgr_hexdump_file, val);
}
void mgos_config_set_debug_mbedtls_level(struct mgos_config *cfg, int val) {
  cfg->debug.mbedtls_level = val;
}
void mgos_config_set_sys_mount_path(struct mgos_config *cfg, const char *val) {
  mgos_conf_set_str(&cfg->sys.mount.path, val);
}
void mgos_config_set_sys_mount_dev_type(struct mgos_config *cfg,
                                        const char *val) {
  mgos_conf_set_str(&cfg->sys.mount.dev_type, val);
}
void mgos_config_set_sys_mount_dev_opts(struct mgos_config *cfg,
                                        const char *val) {
  mgos_conf_set_str(&cfg->sys.mount.dev_opts, val);
}
void mgos_config_set_sys_mount_fs_type(struct mgos_config *cfg,
                                       const char *val) {
  mgos_conf_set_str(&cfg->sys.mount.fs_type, val);
}
void mgos_config_set_sys_mount_fs_opts(struct mgos_config *cfg,
                                       const char *val) {
  mgos_conf_set_str(&cfg->sys.mount.fs_opts, val);
}
void mgos_config_set_sys_tz_spec(struct mgos_config *cfg, const char *val) {
  mgos_conf_set_str(&cfg->sys.tz_spec, val);
}
void mgos_config_set_sys_wdt_timeout(struct mgos_config *cfg, int val) {
  cfg->sys.wdt_timeout = val;
}
void mgos_config_set_sys_pref_ota_lib(struct mgos_config *cfg,
                                      const char *val) {
  mgos_conf_set_str(&cfg->sys.pref_ota_lib, val);
}
void mgos_config_set_conf_acl(struct mgos_config *cfg, const char *val) {
  mgos_conf_set_str(&cfg->conf_acl, val);
}
void mgos_config_set_bt_enable(struct mgos_config *cfg, int val) {
  cfg->bt.enable = val;
}
void mgos_config_set_bt_dev_name(struct mgos_config *cfg, const char *val) {
  mgos_conf_set_str(&cfg->bt.dev_name, val);
}
void mgos_config_set_bt_adv_enable(struct mgos_config *cfg, int val) {
  cfg->bt.adv_enable = val;
}
void mgos_config_set_bt_scan_rsp_data_hex(struct mgos_config *cfg,
                                          const char *val) {
  mgos_conf_set_str(&cfg->bt.scan_rsp_data_hex, val);
}
void mgos_config_set_bt_keep_enabled(struct mgos_config *cfg, int val) {
  cfg->bt.keep_enabled = val;
}
void mgos_config_set_bt_allow_pairing(struct mgos_config *cfg, int val) {
  cfg->bt.allow_pairing = val;
}
void mgos_config_set_bt_max_paired_devices(struct mgos_config *cfg, int val) {
  cfg->bt.max_paired_devices = val;
}
void mgos_config_set_bt_random_address(struct mgos_config *cfg, int val) {
  cfg->bt.random_address = val;
}
void mgos_config_set_bt_gatts_min_sec_level(struct mgos_config *cfg, int val) {
  cfg->bt.gatts.min_sec_level = val;
}
void mgos_config_set_bt_gatts_require_pairing(struct mgos_config *cfg,
                                              int val) {
  cfg->bt.gatts.require_pairing = val;
}
void mgos_config_set_bt_config_svc_enable(struct mgos_config *cfg, int val) {
  cfg->bt.config_svc_enable = val;
}
void mgos_config_set_bt_debug_svc_enable(struct mgos_config *cfg, int val) {
  cfg->bt.debug_svc_enable = val;
}
void mgos_config_set_i2c_enable(struct mgos_config *cfg, int val) {
  cfg->i2c.enable = val;
}
void mgos_config_set_i2c_freq(struct mgos_config *cfg, int val) {
  cfg->i2c.freq = val;
}
void mgos_config_set_i2c_debug(struct mgos_config *cfg, int val) {
  cfg->i2c.debug = val;
}
void mgos_config_set_i2c_unit_no(struct mgos_config *cfg, int val) {
  cfg->i2c.unit_no = val;
}
void mgos_config_set_i2c_sda_gpio(struct mgos_config *cfg, int val) {
  cfg->i2c.sda_gpio = val;
}
void mgos_config_set_i2c_scl_gpio(struct mgos_config *cfg, int val) {
  cfg->i2c.scl_gpio = val;
}
void mgos_config_set_wifi_sta_enable(struct mgos_config *cfg, int val) {
  cfg->wifi.sta.enable = val;
}
void mgos_config_set_wifi_sta_ssid(struct mgos_config *cfg, const char *val) {
  mgos_conf_set_str(&cfg->wifi.sta.ssid, val);
}
void mgos_config_set_wifi_sta_pass(struct mgos_config *cfg, const char *val) {
  mgos_conf_set_str(&cfg->wifi.sta.pass, val);
}
void mgos_config_set_wifi_sta_user(struct mgos_config *cfg, const char *val) {
  mgos_conf_set_str(&cfg->wifi.sta.user, val);
}
void mgos_config_set_wifi_sta_anon_identity(struct mgos_config *cfg,
                                            const char *val) {
  mgos_conf_set_str(&cfg->wifi.sta.anon_identity, val);
}
void mgos_config_set_wifi_sta_cert(struct mgos_config *cfg, const char *val) {
  mgos_conf_set_str(&cfg->wifi.sta.cert, val);
}
void mgos_config_set_wifi_sta_key(struct mgos_config *cfg, const char *val) {
  mgos_conf_set_str(&cfg->wifi.sta.key, val);
}
void mgos_config_set_wifi_sta_ca_cert(struct mgos_config *cfg,
                                      const char *val) {
  mgos_conf_set_str(&cfg->wifi.sta.ca_cert, val);
}
void mgos_config_set_wifi_sta_ip(struct mgos_config *cfg, const char *val) {
  mgos_conf_set_str(&cfg->wifi.sta.ip, val);
}
void mgos_config_set_wifi_sta_netmask(struct mgos_config *cfg,
                                      const char *val) {
  mgos_conf_set_str(&cfg->wifi.sta.netmask, val);
}
void mgos_config_set_wifi_sta_gw(struct mgos_config *cfg, const char *val) {
  mgos_conf_set_str(&cfg->wifi.sta.gw, val);
}
void mgos_config_set_wifi_sta_nameserver(struct mgos_config *cfg,
                                         const char *val) {
  mgos_conf_set_str(&cfg->wifi.sta.nameserver, val);
}
void mgos_config_set_wifi_sta_dhcp_hostname(struct mgos_config *cfg,
                                            const char *val) {
  mgos_conf_set_str(&cfg->wifi.sta.dhcp_hostname, val);
}
void mgos_config_set_wifi_ap_enable(struct mgos_config *cfg, int val) {
  cfg->wifi.ap.enable = val;
}
void mgos_config_set_wifi_ap_ssid(struct mgos_config *cfg, const char *val) {
  mgos_conf_set_str(&cfg->wifi.ap.ssid, val);
}
void mgos_config_set_wifi_ap_pass(struct mgos_config *cfg, const char *val) {
  mgos_conf_set_str(&cfg->wifi.ap.pass, val);
}
void mgos_config_set_wifi_ap_hidden(struct mgos_config *cfg, int val) {
  cfg->wifi.ap.hidden = val;
}
void mgos_config_set_wifi_ap_channel(struct mgos_config *cfg, int val) {
  cfg->wifi.ap.channel = val;
}
void mgos_config_set_wifi_ap_max_connections(struct mgos_config *cfg, int val) {
  cfg->wifi.ap.max_connections = val;
}
void mgos_config_set_wifi_ap_ip(struct mgos_config *cfg, const char *val) {
  mgos_conf_set_str(&cfg->wifi.ap.ip, val);
}
void mgos_config_set_wifi_ap_netmask(struct mgos_config *cfg, const char *val) {
  mgos_conf_set_str(&cfg->wifi.ap.netmask, val);
}
void mgos_config_set_wifi_ap_gw(struct mgos_config *cfg, const char *val) {
  mgos_conf_set_str(&cfg->wifi.ap.gw, val);
}
void mgos_config_set_wifi_ap_dhcp_start(struct mgos_config *cfg,
                                        const char *val) {
  mgos_conf_set_str(&cfg->wifi.ap.dhcp_start, val);
}
void mgos_config_set_wifi_ap_dhcp_end(struct mgos_config *cfg,
                                      const char *val) {
  mgos_conf_set_str(&cfg->wifi.ap.dhcp_end, val);
}
void mgos_config_set_wifi_ap_trigger_on_gpio(struct mgos_config *cfg, int val) {
  cfg->wifi.ap.trigger_on_gpio = val;
}
void mgos_config_set_wifi_ap_disable_after(struct mgos_config *cfg, int val) {
  cfg->wifi.ap.disable_after = val;
}
void mgos_config_set_wifi_ap_hostname(struct mgos_config *cfg,
                                      const char *val) {
  mgos_conf_set_str(&cfg->wifi.ap.hostname, val);
}
void mgos_config_set_wifi_ap_keep_enabled(struct mgos_config *cfg, int val) {
  cfg->wifi.ap.keep_enabled = val;
}
void mgos_config_set_http_enable(struct mgos_config *cfg, int val) {
  cfg->http.enable = val;
}
void mgos_config_set_http_listen_addr(struct mgos_config *cfg,
                                      const char *val) {
  mgos_conf_set_str(&cfg->http.listen_addr, val);
}
void mgos_config_set_http_document_root(struct mgos_config *cfg,
                                        const char *val) {
  mgos_conf_set_str(&cfg->http.document_root, val);
}
void mgos_config_set_http_ssl_cert(struct mgos_config *cfg, const char *val) {
  mgos_conf_set_str(&cfg->http.ssl_cert, val);
}
void mgos_config_set_http_ssl_key(struct mgos_config *cfg, const char *val) {
  mgos_conf_set_str(&cfg->http.ssl_key, val);
}
void mgos_config_set_http_ssl_ca_cert(struct mgos_config *cfg,
                                      const char *val) {
  mgos_conf_set_str(&cfg->http.ssl_ca_cert, val);
}
void mgos_config_set_http_upload_acl(struct mgos_config *cfg, const char *val) {
  mgos_conf_set_str(&cfg->http.upload_acl, val);
}
void mgos_config_set_http_hidden_files(struct mgos_config *cfg,
                                       const char *val) {
  mgos_conf_set_str(&cfg->http.hidden_files, val);
}
void mgos_config_set_http_auth_domain(struct mgos_config *cfg,
                                      const char *val) {
  mgos_conf_set_str(&cfg->http.auth_domain, val);
}
void mgos_config_set_http_auth_file(struct mgos_config *cfg, const char *val) {
  mgos_conf_set_str(&cfg->http.auth_file, val);
}
void mgos_config_set_rpc_enable(struct mgos_config *cfg, int val) {
  cfg->rpc.enable = val;
}
void mgos_config_set_rpc_max_frame_size(struct mgos_config *cfg, int val) {
  cfg->rpc.max_frame_size = val;
}
void mgos_config_set_rpc_max_queue_length(struct mgos_config *cfg, int val) {
  cfg->rpc.max_queue_length = val;
}
void mgos_config_set_rpc_default_out_channel_idle_close_timeout(
    struct mgos_config *cfg, int val) {
  cfg->rpc.default_out_channel_idle_close_timeout = val;
}
void mgos_config_set_rpc_acl_file(struct mgos_config *cfg, const char *val) {
  mgos_conf_set_str(&cfg->rpc.acl_file, val);
}
void mgos_config_set_rpc_auth_domain(struct mgos_config *cfg, const char *val) {
  mgos_conf_set_str(&cfg->rpc.auth_domain, val);
}
void mgos_config_set_rpc_auth_file(struct mgos_config *cfg, const char *val) {
  mgos_conf_set_str(&cfg->rpc.auth_file, val);
}
void mgos_config_set_rpc_ws_enable(struct mgos_config *cfg, int val) {
  cfg->rpc.ws.enable = val;
}
void mgos_config_set_rpc_ws_server_address(struct mgos_config *cfg,
                                           const char *val) {
  mgos_conf_set_str(&cfg->rpc.ws.server_address, val);
}
void mgos_config_set_rpc_ws_reconnect_interval_min(struct mgos_config *cfg,
                                                   int val) {
  cfg->rpc.ws.reconnect_interval_min = val;
}
void mgos_config_set_rpc_ws_reconnect_interval_max(struct mgos_config *cfg,
                                                   int val) {
  cfg->rpc.ws.reconnect_interval_max = val;
}
void mgos_config_set_rpc_ws_ssl_server_name(struct mgos_config *cfg,
                                            const char *val) {
  mgos_conf_set_str(&cfg->rpc.ws.ssl_server_name, val);
}
void mgos_config_set_rpc_ws_ssl_ca_file(struct mgos_config *cfg,
                                        const char *val) {
  mgos_conf_set_str(&cfg->rpc.ws.ssl_ca_file, val);
}
void mgos_config_set_rpc_ws_ssl_client_cert_file(struct mgos_config *cfg,
                                                 const char *val) {
  mgos_conf_set_str(&cfg->rpc.ws.ssl_client_cert_file, val);
}
void mgos_config_set_rpc_gatts_enable(struct mgos_config *cfg, int val) {
  cfg->rpc.gatts.enable = val;
}
void mgos_config_set_rpc_uart_uart_no(struct mgos_config *cfg, int val) {
  cfg->rpc.uart.uart_no = val;
}
void mgos_config_set_rpc_uart_baud_rate(struct mgos_config *cfg, int val) {
  cfg->rpc.uart.baud_rate = val;
}
void mgos_config_set_rpc_uart_fc_type(struct mgos_config *cfg, int val) {
  cfg->rpc.uart.fc_type = val;
}
void mgos_config_set_rpc_uart_wait_for_start_frame(struct mgos_config *cfg,
                                                   int val) {
  cfg->rpc.uart.wait_for_start_frame = val;
}
void mgos_config_set_sntp_enable(struct mgos_config *cfg, int val) {
  cfg->sntp.enable = val;
}
void mgos_config_set_sntp_server(struct mgos_config *cfg, const char *val) {
  mgos_conf_set_str(&cfg->sntp.server, val);
}
void mgos_config_set_sntp_retry_min(struct mgos_config *cfg, int val) {
  cfg->sntp.retry_min = val;
}
void mgos_config_set_sntp_retry_max(struct mgos_config *cfg, int val) {
  cfg->sntp.retry_max = val;
}
void mgos_config_set_sntp_update_interval(struct mgos_config *cfg, int val) {
  cfg->sntp.update_interval = val;
}
void mgos_config_set_bts_data_store_ram_size(struct mgos_config *cfg, int val) {
  cfg->bts.data.ram.size = val;
}
void mgos_config_set_bts_data_store_ram_flush_interval_ms(
    struct mgos_config *cfg, int val) {
  cfg->bts.data.ram_flush_interval_ms = val;
}
void mgos_config_set_bts_data_store_dev_type(struct mgos_config *cfg,
                                             const char *val) {
  mgos_conf_set_str(&cfg->bts.data.dev.type, val);
}
void mgos_config_set_bts_data_store_dev_opts(struct mgos_config *cfg,
                                             const char *val) {
  mgos_conf_set_str(&cfg->bts.data.dev.opts, val);
}
void mgos_config_set_bts_data_store_dev_size(struct mgos_config *cfg, int val) {
  cfg->bts.data.dev.size = val;
}
void mgos_config_set_bts_data_store_dev_block_size(struct mgos_config *cfg,
                                                   int val) {
  cfg->bts.data.dev.block_size = val;
}
void mgos_config_set_bts_data_store_dev_meta_blocks(struct mgos_config *cfg,
                                                    int val) {
  cfg->bts.data.dev.meta_blocks = val;
}
void mgos_config_set_bts_data_store_file_enable(struct mgos_config *cfg,
                                                int val) {
  cfg->bts.data.file.enable = val;
}
void mgos_config_set_bts_data_store_file_mount_enable(struct mgos_config *cfg,
                                                      int val) {
  cfg->bts.data.file.mount.enable = val;
}
void mgos_config_set_bts_data_store_file_mount_dev_type(struct mgos_config *cfg,
                                                        const char *val) {
  mgos_conf_set_str(&cfg->bts.data.file.mount.dev_type, val);
}
void mgos_config_set_bts_data_store_file_mount_dev_opts(struct mgos_config *cfg,
                                                        const char *val) {
  mgos_conf_set_str(&cfg->bts.data.file.mount.dev_opts, val);
}
void mgos_config_set_bts_data_store_file_mount_fs_type(struct mgos_config *cfg,
                                                       const char *val) {
  mgos_conf_set_str(&cfg->bts.data.file.mount.fs_type, val);
}
void mgos_config_set_bts_data_store_file_mount_fs_opts(struct mgos_config *cfg,
                                                       const char *val) {
  mgos_conf_set_str(&cfg->bts.data.file.mount.fs_opts, val);
}
void mgos_config_set_bts_data_store_file_state_file(struct mgos_config *cfg,
                                                    const char *val) {
  mgos_conf_set_str(&cfg->bts.data.file.state_file, val);
}
void mgos_config_set_bts_data_store_file_data_prefix(struct mgos_config *cfg,
                                                     const char *val) {
  mgos_conf_set_str(&cfg->bts.data.file.data_prefix, val);
}
void mgos_config_set_bts_data_store_file_max_size(struct mgos_config *cfg,
                                                  int val) {
  cfg->bts.data.file.max_size = val;
}
void mgos_config_set_bts_data_store_file_max_num(struct mgos_config *cfg,
                                                 int val) {
  cfg->bts.data.file.max_num = val;
}
void mgos_config_set_bts_data_store_file_buf_size(struct mgos_config *cfg,
                                                  int val) {
  cfg->bts.data.file.buf_size = val;
}
void mgos_config_set_bts_data_store_stats_interval_ms(struct mgos_config *cfg,
                                                      int val) {
  cfg->bts.data.stats_interval_ms = val;
}
void mgos_config_set_bts_data_gatts_enable(struct mgos_config *cfg, int val) {
  cfg->bts.data.gatts.enable = val;
}
void mgos_config_set_bts_accel_addr(struct mgos_config *cfg, int val) {
  cfg->bts.accel.addr = val;
}
void mgos_config_set_bts_accel_wu_thr_mg(struct mgos_config *cfg, int val) {
  cfg->bts.accel.wu_thr_mg = val;
}
void mgos_config_set_bts_accel_wu_dur_ms(struct mgos_config *cfg, int val) {
  cfg->bts.accel.wu_dur_ms = val;
}
void mgos_config_set_bts_accel_burst_size(struct mgos_config *cfg, int val) {
  cfg->bts.accel.burst_size = val;
}
void mgos_config_set_bts_accel_burst_sampling_interval_ms(
    struct mgos_config *cfg, int val) {
  cfg->bts.accel.burst_sampling_interval_ms = val;
}
void mgos_config_set_bts_accel_sampling_interval_ms(struct mgos_config *cfg,
                                                    int val) {
  cfg->bts.accel.sampling_interval_ms = val;
}
void mgos_config_set_bts_accel_temp_sampling_interval_ms(
    struct mgos_config *cfg, int val) {
  cfg->bts.accel.temp_sampling_interval_ms = val;
}
void mgos_config_set_bts_temp_addr(struct mgos_config *cfg, int val) {
  cfg->bts.temp.addr = val;
}
void mgos_config_set_bts_temp_sampling_interval_ms(struct mgos_config *cfg,
                                                   int val) {
  cfg->bts.temp.sampling_interval_ms = val;
}
/* }}} */
