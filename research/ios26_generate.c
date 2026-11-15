// iOS 26: gen26 show | generate | clear | check | set 0x<16 hex>  (AppleMobileApNonce 0xC8/0xC9, then verify against kernel NVRAM)
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
int kwritebuf(uint64_t kaddr, const void *input, size_t size);
int kwrite8(uint64_t kaddr, uint8_t val);
uint64_t task_self(void);
uint64_t task_get_ipc_port_kobject(uint64_t task, mach_port_t port);

struct akey {
	uint32_t generated, key_id, key_sz;
	uint8_t key[16], iv[16];
	uint32_t zero, pad;
} __attribute__((packed));

kern_return_t IORegistryEntrySetCFProperty_(io_registry_entry_t, CFStringRef, CFTypeRef) __asm__("_IORegistryEntrySetCFProperty");

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

static void pr(const char *t, const uint8_t *b, int n) {
	printf("%s ", t);
	for (int i = 0; i < n; i++) printf("%02x", b[i]);
	printf("\n");
}

static int nvram_find(const char *suffix, char *out, size_t outsz) {
	uint64_t nv = service_object("IODTNVRAM");
	uint64_t dict = STRIP(kread64(STRIP(kread64(nv + 0x98)) + 0x48));
	uint32_t cnt = kread32(dict + 0x14);
	uint64_t arr = STRIP(kread64(dict + 0x20));
	if (cnt > 512) return -1;
	size_t sl = strlen(suffix);
	for (uint32_t i = 0; i < cnt; i++) {
		uint64_t k = STRIP(kread64(arr + i * 16)), v = STRIP(kread64(arr + i * 16 + 8));
		uint32_t klen = kread32(k + 0xC) >> 14;
		char name[128] = {0};
		if (klen >= sizeof(name)) continue;
		kreadbuf(STRIP(kread64(k + 0x10)), name, klen);
		size_t l = strlen(name);
		if (l < sl || strcmp(name + l - sl, suffix)) continue;
		uint32_t vl = kread32(v + 0xC);
		printf("nvram %s raw len field 0x%x\n", name, vl);
		// OSString: len>>14 @+0xC, ptr @+0x10; OSData: len @+0xC, ptr @+0x18
		uint32_t sl2 = vl >> 14;
		memset(out, 0, outsz);
		if (sl2 && sl2 < outsz) { kreadbuf(STRIP(kread64(v + 0x10)), out, sl2); return 1; }
		if (vl && vl < outsz) { kreadbuf(STRIP(kread64(v + 0x18)), out, vl); return 2; }
		return -1;
	}
	return 0;
}

static int set_prop(io_registry_entry_t e, const char *k, const char *v) {
	CFStringRef ck = CFStringCreateWithCString(NULL, k, kCFStringEncodingASCII), cv = CFStringCreateWithCString(NULL, v, kCFStringEncodingASCII);
	kern_return_t kr = IORegistryEntrySetCFProperty_(e, ck, cv);
	CFRelease(ck); CFRelease(cv);
	if (kr) printf("set %s failed 0x%x\n", k, kr);
	return kr;
}

static int valid_gen(const char *g) {
	if (strlen(g) != 18 || g[0] != '0' || g[1] != 'x') return 0;
	for (int i = 2; i < 18; i++) if (!strchr("0123456789abcdef", g[i])) return 0;
	return 1;
}

// CHRP (xnu-12377): handler = nv+0x98, _newData +0x14, _provider +0x20, _varDict +0x48
static int chrp_set(const char *gen, int dry) {
	uint64_t nv = service_object("IODTNVRAM");
	uint64_t h = STRIP(kread64(nv + 0x98));
	uint64_t dict = STRIP(kread64(h + 0x48));
	printf("handler 0x%llx provider-ok %d newData %u\n", h, STRIP(kread64(h + 0x20)) == nv, kread32(h + 0x14) & 0xFF);
	if (STRIP(kread64(h + 0x20)) != nv) { printf("UNSUPPORTED (not a CHRP handler)\n"); return -1; }
	uint32_t cnt = kread32(dict + 0x14);
	uint64_t arr = STRIP(kread64(dict + 0x20));
	for (uint32_t i = 0; i < cnt && cnt < 512; i++) {
		uint64_t k = STRIP(kread64(arr + i * 16)), v = STRIP(kread64(arr + i * 16 + 8));
		uint32_t klen = kread32(k + 0xC) >> 14;
		char name[128] = {0};
		if (klen >= sizeof(name)) continue;
		kreadbuf(STRIP(kread64(k + 0x10)), name, klen);
		size_t l = strlen(name);
		if (l < 28 || strcmp(name + l - 28, ":com.apple.System.boot-nonce")) continue;
		uint32_t vlen = kread32(v + 0xC) >> 14;
		uint64_t sp = STRIP(kread64(v + 0x10));
		char cur[32] = {0};
		if (vlen != 19 || kreadbuf(sp, cur, 18) || !valid_gen(cur)) { printf("UNSUPPORTED (unexpected boot-nonce, len %u)\n", vlen); return -1; }
		printf("current %s\n", cur);
		if (dry) return 0;
		char back[32] = {0};
		if (kwritebuf(sp, gen, 18) || kreadbuf(sp, back, 18) || strcmp(back, gen)) { printf("FAILED (write)\n"); return -1; }
		if (kwrite8(h + 0x14, 1)) { printf("FAILED (newData)\n"); return -1; }
		io_registry_entry_t o = IORegistryEntryFromPath(kIOMainPortDefault, "IODeviceTree:/options");
		if (set_prop(o, "delete_me_key", "delete_me_val") || set_prop(o, "IONVRAM-DELETE-PROPERTY", "delete_me_key") ||
		    set_prop(o, "IONVRAM-FORCESYNCNOW-PROPERTY", "com.apple.System.boot-nonce")) { printf("FAILED (sync)\n"); return -1; }
		printf("OK %s newData-after %u\n", gen, kread32(h + 0x14) & 0xFF);
		return 0;
	}
	printf("UNSUPPORTED (no boot-nonce in NVRAM)\n");
	return -1;
}

static void show(void) {
	io_registry_entry_t ch = IORegistryEntryFromPath(kIOMainPortDefault, "IODeviceTree:/chosen");
	CFDataRef bn = IORegistryEntryCreateCFProperty(ch, CFSTR("boot-nonce"), kCFAllocatorDefault, 0);
	uint64_t gen[2] = { 0, 0 };
	uint8_t out[32];
	if (bn && CFDataGetLength(bn) == 8) CFDataGetBytes(bn, CFRangeMake(0, 8), (UInt8 *)&gen[1]);
	printf("chosen generator 0x%016llx\n", gen[1]);
	char v[64];
	int t = nvram_find(":com.apple.System.boot-nonce", v, sizeof(v));
	if (t <= 0) { printf("nvram boot-nonce: none (%d)\n", t); return; }
	if (t == 1) printf("nvram generator string \"%s\"\n", v);
	else { printf("nvram data: "); for (int i = 0; i < 16; i++) printf("%02x", (uint8_t)v[i]); printf("\n"); }
	if (t == 1) {
		gen[1] = strtoull(v, NULL, 0);
		hash_aes(0x8A3, gen, out);
		pr("APNonce(nvram gen)", out, 32);
	}
}

int main(int argc, char **argv) {
	if (jbclient_initialize_primitives()) return 1;
	const char *cmd = argc > 1 ? argv[1] : "show";
	if (!strcmp(cmd, "generate") || !strcmp(cmd, "clear")) {
		io_service_t s = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("AppleMobileApNonce"));
		io_connect_t c = 0;
		kern_return_t kr = IOServiceOpen(s, mach_task_self(), 0, &c);
		printf("open 0x%x\n", kr);
		if (kr) return 1;
		if (!strcmp(cmd, "generate")) {
			uint8_t nonce[CC_SHA384_DIGEST_LENGTH] = {0};
			size_t n = sizeof(nonce);
			kr = IOConnectCallStructMethod(c, 0xC8, NULL, 0, nonce, &n);
			printf("generate 0x%x (%s) size %zu\n", kr, mach_error_string(kr), n);
			if (!kr) pr("returned nonce", nonce, (int)n);
		} else {
			kr = IOConnectCallStructMethod(c, 0xC9, NULL, 0, NULL, NULL);
			printf("clear 0x%x (%s)\n", kr, mach_error_string(kr));
		}
		IOServiceClose(c);
	}
	if (!strcmp(cmd, "check")) chrp_set(NULL, 1);
	if (!strcmp(cmd, "set")) {
		if (argc < 3 || !valid_gen(argv[2])) { printf("usage: set 0x<16 lowercase hex>\n"); return 1; }
		if (chrp_set(argv[2], 0)) return 1;
	}
	show();
	return 0;
}
