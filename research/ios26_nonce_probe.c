// Read-only: iOS 26 APNonce + Cryptex1 seed/nonce. Usage: n26probe [seedhex32]  (override skips NVRAM)
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <IOKit/IOKitLib.h>
#include <CommonCrypto/CommonCrypto.h>

int jbclient_initialize_primitives(void);
int kreadbuf(uint64_t kaddr, void *output, size_t size);
uint64_t kread64(uint64_t va);
uint32_t kread32(uint64_t va);
uint64_t task_self(void);
uint64_t task_get_ipc_port_kobject(uint64_t task, mach_port_t port);

struct akey {
	uint32_t generated, key_id, key_sz;
	uint8_t key[16], iv[16];
	uint32_t zero, pad;
} __attribute__((packed));

#define STRIP(p) ((p) | 0xFFFFFF8000000000ULL)

static uint64_t service_object(const char *name) {
	io_service_t s = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching(name));
	if (!s) return 0;
	uint64_t ko = task_get_ipc_port_kobject(task_self(), s);
	IOObjectRelease(s);
	return ko ? STRIP(kread64(ko + 0x20)) : 0;
}

static int get_key(uint32_t id, struct akey *out) {
	io_service_t s = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOAESAccelerator"));
	uint64_t ko = s ? task_get_ipc_port_kobject(task_self(), s) : 0;
	if (!ko) return -1;
	// IOMachPort object at +0x20 (iOS 26) / +0x30 (iOS 17); the service itself on iOS 16
	uint64_t cand[3] = { STRIP(kread64(ko + 0x20)), STRIP(kread64(ko + 0x30)), ko }, aes = 0, keys = 0;
	uint32_t n = 0;
	for (int c = 0; c < 3 && !aes; c++) {
		n = kread32(cand[c] + 0xD8);
		if (!n || n > 64) continue;
		keys = STRIP(kread64(cand[c] + 0xD0));
		if (kreadbuf(keys, out, sizeof(*out)) == 0 && out->key_id >= 0x800 && out->key_id <= 0x8FF) aes = cand[c];
	}
	if (!aes) return -1;
	for (uint32_t i = 0; i < n; i++) {
		if (kreadbuf(keys + i * sizeof(*out), out, sizeof(*out))) return -1;
		if (out->key_id == id) return 0;
	}
	return -1;
}

static void hash_aes(uint32_t id, const void *in, uint8_t out32[32]) {
	struct akey k;
	uint8_t enc[16], h[CC_SHA384_DIGEST_LENGTH];
	size_t olen = 0;
	memset(out32, 0, 32);
	if (get_key(id, &k)) { printf("key 0x%X not found\n", id); return; }
	CCCrypt(kCCEncrypt, kCCAlgorithmAES128, 0, k.key, 16, k.iv, in, 16, enc, 16, &olen);
	memset(&k, 0, sizeof(k));
	CC_SHA384(enc, 16, h);
	memcpy(out32, h, 32);
}

static int nvram_c1bt(uint8_t seed[16]) {
	uint64_t nv = service_object("IODTNVRAM");
	uint64_t dict = STRIP(kread64(STRIP(kread64(nv + 0x98)) + 0x48));
	uint32_t cnt = kread32(dict + 0x14);
	uint64_t arr = STRIP(kread64(dict + 0x20));
	if (cnt > 512) return -1;
	for (uint32_t i = 0; i < cnt; i++) {
		uint64_t k = STRIP(kread64(arr + i * 16)), v = STRIP(kread64(arr + i * 16 + 8));
		uint32_t klen = kread32(k + 0xC) >> 14;
		char name[128] = {0};
		if (klen >= sizeof(name)) continue;
		kreadbuf(STRIP(kread64(k + 0x10)), name, klen);
		size_t l = strlen(name);
		if (l < 9 || strcmp(name + l - 9, ":krn.c1bt")) continue;
		uint8_t d[37];
		if (kread32(v + 0xC) != sizeof(d) || kreadbuf(STRIP(kread64(v + 0x18)), d, sizeof(d))) return -1;
		printf("c1bt flags 0x%02x\n", d[4]);
		memcpy(seed, d + 5, 16);
		return 0;
	}
	return -1;
}

static void pr(const char *t, const uint8_t *b, int n) {
	printf("%s ", t);
	for (int i = 0; i < n; i++) printf("%02x", b[i]);
	printf("\n");
}

int main(int argc, char **argv) {
	if (jbclient_initialize_primitives()) return 1;
	uint8_t seed[16], out[32];
	if (argc > 1 && strlen(argv[1]) == 32) {
		for (int i = 0; i < 16; i++) sscanf(argv[1] + i * 2, "%2hhx", &seed[i]);
	} else {
		io_registry_entry_t ch = IORegistryEntryFromPath(kIOMainPortDefault, "IODeviceTree:/chosen");
		CFDataRef bn = IORegistryEntryCreateCFProperty(ch, CFSTR("boot-nonce"), kCFAllocatorDefault, 0);
		uint64_t gen[2] = { 0, 0 };
		if (bn && CFDataGetLength(bn) == 8) CFDataGetBytes(bn, CFRangeMake(0, 8), (UInt8 *)&gen[1]);
		printf("generator 0x%016llx\n", gen[1]);
		hash_aes(0x8A3, gen, out);
		pr("APNonce", out, 32);
		if (nvram_c1bt(seed)) { printf("c1bt not found\n"); return 1; }
	}
	pr("Cryptex1 seed 0x", seed, 16);
	hash_aes(0x8A4, seed, out);
	pr("Cryptex1 nonce", out, 32);
	return 0;
}
