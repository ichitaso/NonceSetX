//
// NonceSetX: persistent boot-nonce write (V3 handler entries, CHRP handler dict, or the iOS 15.0 - 15.3 dict).
//
// com.apple.System.boot-nonce is KernelOnly, so the registry write fails and the os-dict fallback only changes
// IODTNVRAM::_varDict, which syncBlock never reads. This edits the handler's entry the same way
// IONVRAMV3Handler::setVariableInternal does for an existing entry of equal size (data, crc32, new_state),
// then forces a sync. Layout from xnu-8796.121.2, checked on iPhone15,2 iOS 16.5; any mismatch aborts.
//

/* Include headers */
#include <ctype.h>
#include <zlib.h>
#include <libkrw.h>
#include <x8A4/Registry/registry.h>
#include <x8A4/Services/services.h>
#include <x8A4/Kernel/kernel.h>
#include <x8A4/Kernel/nvram_v3.h>
#include <x8A4/Logger/logger.h>
#include <x8A4/x8A4.h>

/* Defines */
#define IODTNVRAM_FORMAT          0x98
#define IODTNVRAM_VARDICT         0xC0
#define V3_PROVIDER               0x20
#define V3_NEWDATA                0x28
#define V3_RAWCONTROLLER          0x2B
#define V3_VARDICT_REF            0x38
#define V3_VARENTRIES             0x58
#define OSARRAY_COUNT             0x14
#define OSARRAY_ARRAY             0x20
#define OSDATA_LENGTH             0xC
#define OSDATA_BYTES              0x18
#define ENTRY_NEW_STATE           0x0
#define ENTRY_NAME_SIZE           0x18
#define ENTRY_DATA_SIZE           0x1C
#define ENTRY_CRC                 0x30
#define ENTRY_NAME                0x34
#define ENTRY_CONTAINER_BASE      0x38
#define VAR_NEW_STATE_APPEND      3

static const char *kBootNonceName = "com.apple.System.boot-nonce";
#define BOOT_NONCE_NAME_SIZE      28
#define BOOT_NONCE_DATA_SIZE      18

/* Functions */
static uint64_t v3_read_ptr(uint64_t addr) {
  uint64_t value = 0;
  if(kread(addr, &value, 8)) {
    return 0;
  }
  return unsign_ptr(&value);
}

static uint32_t v3_read32(uint64_t addr) {
  uint32_t value = 0;
  kread(addr, &value, 4);
  return value;
}

/**
 * @brief           Finds the V3 handler and the boot-nonce entry, validating every step
 * @param[out]      handler_out
 * @param[out]      entry_out     Address of the entry bytes (nvram_v3_var_entry)
 * @return          NULL on success, otherwise the reason it is unsupported
 */
static const char *v3_find_boot_nonce(uint64_t *handler_out, uint64_t *entry_out) {
  io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IODTNVRAM"));
  if(!service) {
    return "IODTNVRAM service not found";
  }
  uint64_t nvram = get_ipc_kobject(service);
  IOObjectRelease(service);
  if(!nvram) {
    return "IODTNVRAM kobject not found";
  }
  uint64_t handler = v3_read_ptr(nvram + IODTNVRAM_FORMAT);
  if(!handler || v3_read_ptr(handler + V3_PROVIDER) != nvram ||
     v3_read_ptr(handler + V3_VARDICT_REF) != nvram + IODTNVRAM_VARDICT) {
    return "NVRAM handler layout does not match (not a V3 handler, or a different iOS)";
  }
  uint8_t raw_controller = 1;
  kread(handler + V3_RAWCONTROLLER, &raw_controller, 1);
  if(raw_controller) {
    return "raw NVRAM controller is not supported";
  }
  uint64_t entries = v3_read_ptr(handler + V3_VARENTRIES);
  uint32_t count = entries ? v3_read32(entries + OSARRAY_COUNT) : 0;
  uint64_t array = entries ? v3_read_ptr(entries + OSARRAY_ARRAY) : 0;
  if(!array || count == 0 || count > 512) {
    return "NVRAM entry list not found";
  }
  for(uint32_t i = 0; i < count; i++) {
    uint64_t data = v3_read_ptr(array + i * 8);
    if(!data || v3_read32(data + OSDATA_LENGTH) != ENTRY_CONTAINER_BASE + BOOT_NONCE_NAME_SIZE + BOOT_NONCE_DATA_SIZE) {
      continue;
    }
    uint64_t bytes = v3_read_ptr(data + OSDATA_BYTES);
    char name[BOOT_NONCE_NAME_SIZE + 1] = {0};
    if(!bytes || kread(bytes + ENTRY_NAME, name, BOOT_NONCE_NAME_SIZE) || strcmp(name, kBootNonceName) != 0) {
      continue;
    }
    if(v3_read32(bytes + ENTRY_NAME_SIZE) != BOOT_NONCE_NAME_SIZE || v3_read32(bytes + ENTRY_DATA_SIZE) != BOOT_NONCE_DATA_SIZE) {
      return "boot-nonce entry has unexpected sizes";
    }
    char current[BOOT_NONCE_DATA_SIZE + 1] = {0};
    kread(bytes + ENTRY_NAME + BOOT_NONCE_NAME_SIZE, current, BOOT_NONCE_DATA_SIZE);
    if((uint32_t)crc32(0, (const Bytef *)current, BOOT_NONCE_DATA_SIZE) != v3_read32(bytes + ENTRY_CRC)) {
      return "boot-nonce CRC does not match (layout differs)";
    }
    *handler_out = handler;
    *entry_out = bytes;
    return NULL;
  }
  return "boot-nonce entry not found in NVRAM";
}

/**
 * @brief           iOS 15.0 - 15.3 (xnu-8019) has no format handler: variables live in IODTNVRAM::_commonDict and every
 *                  userland variable write re-serializes the whole dict into the image, which x8A4_sync_nvram then writes.
 *                  So editing the existing entry in the dict is enough there. iOS 15.4 (xnu-8020) added format handlers.
 * @return          True on iOS 15.0 - 15.3
 */
static bool dict_mode(void) {
  return gXPF.darwinVersion && strcmp(gXPF.darwinVersion, "21.0.0") >= 0 && strcmp(gXPF.darwinVersion, "21.4.0") < 0;
}

/**
 * @brief           Finds an IONVRAMCHRPHandler (iOS 15.4 - 17). CHRP serializes the dict it shares with IODTNVRAM on
 *                  every sync, so editing the dict entry and setting _newData is enough. Two layouts, both checked on
 *                  devices: xnu-8020 (iPhone13,1 15.4.1): _provider +0x18, &_commonDict +0x48, _newData +0x08;
 *                  xnu-8796 / 10063 (iPad7,5 17.5.1): _provider +0x20, &_varDict +0x48, _newData +0x14.
 * @param[out]      newdata_out   Address of the handler's _newData
 * @return          NULL when a CHRP handler was found, otherwise the reason
 */
static const char *chrp_find_handler(uint64_t *newdata_out) {
  if(!gXPF.darwinVersion || strcmp(gXPF.darwinVersion, "21.4.0") < 0 || strcmp(gXPF.darwinVersion, "24.0.0") >= 0) {
    return "CHRP mode is only checked on iOS 15.4 - 17";
  }
  io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IODTNVRAM"));
  if(!service) {
    return "IODTNVRAM service not found";
  }
  uint64_t nvram = get_ipc_kobject(service);
  IOObjectRelease(service);
  if(!nvram) {
    return "IODTNVRAM kobject not found";
  }
  uint64_t dict = nvram + koffsets_cached->io_dt_nvram;
  for(int off = 0x80; off <= 0xA0; off += 8) {
    uint64_t handler = v3_read_ptr(nvram + off);
    if(!handler || v3_read_ptr(handler + 0x48) != dict) {
      continue;
    }
    if(v3_read_ptr(handler + 0x20) == nvram) {
      *newdata_out = handler + 0x14;
      return NULL;
    }
    if(v3_read_ptr(handler + 0x18) == nvram) {
      *newdata_out = handler + 0x08;
      return NULL;
    }
  }
  return "not a CHRP handler";
}

/**
 * @brief           Reads the boot-nonce from the os-dict and checks it looks like a generator
 * @param[out]      current       BOOT_NONCE_DATA_SIZE + 1 bytes
 * @return          NULL on success, otherwise the reason it is unsupported
 */
static const char *dict_read_boot_nonce(char *current) {
  uint32_t size = 0;
  uint8_t *value = x8A4_get_boot_nonce_os_dict(&size);
  if(!value || size != BOOT_NONCE_DATA_SIZE + 1) {
    return "boot-nonce not found in the NVRAM dict (no generator set, or a different iOS)";
  }
  memcpy(current, value, BOOT_NONCE_DATA_SIZE);
  current[BOOT_NONCE_DATA_SIZE] = '\0';
  if(current[0] != '0' || current[1] != 'x') {
    return "boot-nonce in the NVRAM dict has an unexpected format";
  }
  for(int i = 2; i < BOOT_NONCE_DATA_SIZE; i++) {
    if(!isxdigit((unsigned char)current[i])) {
      return "boot-nonce in the NVRAM dict has an unexpected format";
    }
  }
  return NULL;
}

/**
 * @brief           Whether the CHRP dict has a boot-nonce entry at all
 * @return          True if present
 */
static bool chrp_has_boot_nonce(void) {
  uint32_t size = 0;
  return x8A4_get_boot_nonce_os_dict(&size) && size;
}

/**
 * @brief           Checks whether the persistent write is supported and prints the stored generator
 * @return          Zero if supported
 */
int x8A4_v3_check(void) {
  if(dict_mode()) {
    char current[BOOT_NONCE_DATA_SIZE + 1] = {0};
    const char *reason = dict_read_boot_nonce(current);
    if(reason) {
      x8A4_log("NSX_V3: UNSUPPORTED (%s)\n", reason);
      return -1;
    }
    x8A4_log("NSX_V3: SUPPORTED stored(%s) mode(dict)\n", current);
    return 0;
  }
  uint64_t newdata = 0;
  if(!chrp_find_handler(&newdata)) {
    char current[BOOT_NONCE_DATA_SIZE + 1] = {0};
    if(!chrp_has_boot_nonce()) {
      x8A4_log("NSX_V3: SUPPORTED stored(none) mode(chrp)\n", "");
      return 0;
    }
    const char *reason = dict_read_boot_nonce(current);
    if(reason) {
      x8A4_log("NSX_V3: UNSUPPORTED (%s)\n", reason);
      return -1;
    }
    x8A4_log("NSX_V3: SUPPORTED stored(%s) mode(chrp)\n", current);
    return 0;
  }
  uint64_t handler = 0, entry = 0;
  const char *reason = v3_find_boot_nonce(&handler, &entry);
  if(reason) {
    x8A4_log("NSX_V3: UNSUPPORTED (%s)\n", reason);
    return -1;
  }
  char current[BOOT_NONCE_DATA_SIZE + 1] = {0};
  kread(entry + ENTRY_NAME + BOOT_NONCE_NAME_SIZE, current, BOOT_NONCE_DATA_SIZE);
  x8A4_log("NSX_V3: SUPPORTED stored(%s) mode(v3)\n", current);
  return 0;
}

/**
 * @brief           Writes the generator into the V3 entry and syncs NVRAM
 * @param[in]       generator     "0x" + 16 lowercase hex digits
 * @return          Zero on success
 */
int x8A4_v3_set_apnonce_generator(const char *generator) {
  if(!generator || strlen(generator) != BOOT_NONCE_DATA_SIZE || generator[0] != '0' || generator[1] != 'x') {
    x8A4_log("NSX_V3: FAILED (invalid generator)\n", "");
    return -1;
  }
  char gen[BOOT_NONCE_DATA_SIZE + 1] = {0};
  for(int i = 0; i < BOOT_NONCE_DATA_SIZE; i++) {
    gen[i] = (char)tolower((unsigned char)generator[i]);
    if(i >= 2 && !isxdigit((unsigned char)gen[i])) {
      x8A4_log("NSX_V3: FAILED (invalid generator)\n", "");
      return -1;
    }
  }
  if(dict_mode()) {
    char current[BOOT_NONCE_DATA_SIZE + 1] = {0};
    const char *reason = dict_read_boot_nonce(current);
    if(reason) {
      x8A4_log("NSX_V3: UNSUPPORTED (%s)\n", reason);
      return -1;
    }
    char back[BOOT_NONCE_DATA_SIZE + 1] = {0};
    if(x8A4_set_boot_nonce_os_dict((uint8_t *)gen, BOOT_NONCE_DATA_SIZE + 1) ||
       dict_read_boot_nonce(back) || strcmp(back, gen) != 0) {
      x8A4_log("NSX_V3: FAILED (dict write)\n", "");
      return -1;
    }
    if(x8A4_sync_nvram()) {
      x8A4_log("NSX_V3: FAILED (sync)\n", "");
      return -1;
    }
    x8A4_log("NSX_V3: OK generator(%s) synced(yes) mode(dict)\n", gen);
    return 0;
  }
  uint64_t newdata = 0;
  if(!chrp_find_handler(&newdata)) {
    char current[BOOT_NONCE_DATA_SIZE + 1] = {0};
    // No generator stored yet (iBoot picks a random one every boot): let the kernel create the entry
    if(!chrp_has_boot_nonce() && io_generate_apnonce()) {
      x8A4_log("NSX_V3: FAILED (generateNonce)\n", "");
      return -1;
    }
    const char *reason = dict_read_boot_nonce(current);
    if(reason) {
      x8A4_log("NSX_V3: UNSUPPORTED (%s)\n", reason);
      return -1;
    }
    char back[BOOT_NONCE_DATA_SIZE + 1] = {0};
    uint8_t new_data = 1;
    if(x8A4_set_boot_nonce_os_dict((uint8_t *)gen, BOOT_NONCE_DATA_SIZE + 1) ||
       dict_read_boot_nonce(back) || strcmp(back, gen) != 0) {
      x8A4_log("NSX_V3: FAILED (dict write)\n", "");
      return -1;
    }
    // serializeVariables returns early unless _newData is set
    if(kwrite(&new_data, newdata, 1) || x8A4_sync_nvram()) {
      x8A4_log("NSX_V3: FAILED (sync)\n", "");
      return -1;
    }
    x8A4_log("NSX_V3: OK generator(%s) synced(yes) mode(chrp)\n", gen);
    return 0;
  }
  uint64_t handler = 0, entry = 0;
  const char *reason = v3_find_boot_nonce(&handler, &entry);
  if(reason) {
    x8A4_log("NSX_V3: UNSUPPORTED (%s)\n", reason);
    return -1;
  }
  uint32_t crc = (uint32_t)crc32(0, (const Bytef *)gen, BOOT_NONCE_DATA_SIZE);
  uint8_t append = VAR_NEW_STATE_APPEND;
  uint8_t new_data = 1;
  if(kwrite(gen, entry + ENTRY_NAME + BOOT_NONCE_NAME_SIZE, BOOT_NONCE_DATA_SIZE) ||
     kwrite(&crc, entry + ENTRY_CRC, 4) ||
     kwrite(&append, entry + ENTRY_NEW_STATE, 1) ||
     kwrite(&new_data, handler + V3_NEWDATA, 1)) {
    x8A4_log("NSX_V3: FAILED (kernel write)\n", "");
    return -1;
  }
  char back[BOOT_NONCE_DATA_SIZE + 1] = {0};
  kread(entry + ENTRY_NAME + BOOT_NONCE_NAME_SIZE, back, BOOT_NONCE_DATA_SIZE);
  if(strcmp(back, gen) != 0 || v3_read32(entry + ENTRY_CRC) != crc) {
    x8A4_log("NSX_V3: FAILED (read-back mismatch)\n", "");
    return -1;
  }
  // Keep _varDict (what readers see) in sync with the entry
  x8A4_set_boot_nonce_os_dict((uint8_t *)gen, BOOT_NONCE_DATA_SIZE + 1);
  if(x8A4_sync_nvram()) {
    x8A4_log("NSX_V3: FAILED (sync)\n", "");
    return -1;
  }
  uint8_t pending = 1;
  kread(handler + V3_NEWDATA, &pending, 1);
  x8A4_log("NSX_V3: OK generator(%s) synced(%s) mode(v3)\n", gen, pending ? "pending" : "yes");
  return 0;
}
