// nsx26: x8A4-compatible CLI for iOS 18.5+ / 26 on Dopamine (x8A4/XPF does not support them).
// Kernel r/w comes from libjailbreak. Checked on iPhone12,3 (A13) 26.0.1 and iPad7,11 (A10) 18.6.
#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <mach-o/dyld.h>
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
// Marked unavailable in the iOS SDK headers, but exported by IOKit
kern_return_t NSXSetCFProperty(io_registry_entry_t, CFStringRef, CFTypeRef) __asm__("_IORegistryEntrySetCFProperty");

#define STRIP(p) ((p) | 0xFFFFFF8000000000ULL)
#define GEN_LEN 18

struct accel_key {
	uint32_t generated, key_id, key_sz;
	uint8_t key[16], iv[16];
	uint32_t zero, pad;
} __attribute__((packed));

#define OBJ_CANDIDATES 2

// IOMachPort -> object at +0x20 (xnu-12377) or +0x30 (xnu-11417); callers check which one fits
static int service_objects(const char *name, uint64_t out[OBJ_CANDIDATES]) {
	static const int offs[OBJ_CANDIDATES] = { 0x20, 0x30 };
	memset(out, 0, sizeof(uint64_t) * OBJ_CANDIDATES);
	io_service_t s = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching(name));
	if (!s) return -1;
	// Read before releasing: dropping the last send right frees the IOMachPort
	uint64_t port = task_get_ipc_port_kobject(task_self(), s);
	for (int i = 0; port && i < OBJ_CANDIDATES; i++) {
		uint64_t raw = kread64(port + offs[i]);
		if (raw) out[i] = STRIP(raw);
	}
	IOObjectRelease(s);
	return 0;
}

// IOAESAccelerator special keys: array +0xD0, count +0xD8
static int get_key(uint32_t id, struct accel_key *out) {
	uint64_t objs[OBJ_CANDIDATES];
	if (service_objects("IOAESAccelerator", objs)) return -1;
	for (int c = 0; c < OBJ_CANDIDATES; c++) {
		uint32_t n = objs[c] ? kread32(objs[c] + 0xD8) : 0;
		if (!n || n > 64) continue;
		uint64_t keys = STRIP(kread64(objs[c] + 0xD0));
		if (kreadbuf(keys, out, sizeof(*out)) || out->key_id < 0x800 || out->key_id > 0x8FF) continue;
		for (uint32_t i = 0; i < n; i++) {
			if (kreadbuf(keys + i * sizeof(*out), out, sizeof(*out))) return -1;
			if (out->key_id == id) return 0;
		}
		return -1;
	}
	return -1;
}

// sha384(AES128-CBC(key id, 16 bytes))[:32]
static int entangle(uint32_t id, const void *in, uint8_t out[32]) {
	struct accel_key k;
	uint8_t enc[16], h[CC_SHA384_DIGEST_LENGTH];
	size_t len = 0;
	if (get_key(id, &k)) return -1;
	CCCryptorStatus st = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, 0, k.key, 16, k.iv, in, 16, enc, 16, &len);
	memset(&k, 0, sizeof(k));
	if (st != kCCSuccess || len != 16) return -1;
	CC_SHA384(enc, 16, h);
	memcpy(out, h, 32);
	return 0;
}

struct chrp {
	uint64_t handler;
	uint64_t dict;
};

// CHRP handler (xnu-11417 / 12377): nv+0x98, _newData +0x14, _provider +0x20, _varDict +0x48
static const char *chrp_find(struct chrp *c) {
	uint64_t objs[OBJ_CANDIDATES];
	if (service_objects("IODTNVRAM", objs)) return "IODTNVRAM not found";
	for (int i = 0; i < OBJ_CANDIDATES; i++) {
		uint64_t nv = objs[i];
		if (!nv) continue;
		c->handler = STRIP(kread64(nv + 0x98));
		if (STRIP(kread64(c->handler + 0x20)) != nv) continue;
		c->dict = STRIP(kread64(c->handler + 0x48));
		uint32_t cnt = kread32(c->dict + 0x14);
		if (!cnt || cnt > 512) return "unexpected NVRAM dictionary";
		return NULL;
	}
	return "not a CHRP NVRAM handler";
}

// Value object of the first "<guid>:<name>" key in _varDict
static uint64_t chrp_lookup(struct chrp *c, const char *name) {
	uint32_t cnt = kread32(c->dict + 0x14);
	uint64_t arr = STRIP(kread64(c->dict + 0x20));
	size_t nl = strlen(name);
	for (uint32_t i = 0; i < cnt; i++) {
		uint64_t key = STRIP(kread64(arr + i * 16));
		uint32_t klen = kread32(key + 0xC) >> 14;
		char buf[128] = {0};
		if (klen >= sizeof(buf) || kreadbuf(STRIP(kread64(key + 0x10)), buf, klen)) continue;
		size_t l = strlen(buf);
		if (l > nl && buf[l - nl - 1] == ':' && !strcmp(buf + l - nl, name)) return STRIP(kread64(arr + i * 16 + 8));
	}
	return 0;
}

static int valid_gen(const char *g) {
	if (strlen(g) != GEN_LEN || g[0] != '0' || g[1] != 'x') return 0;
	for (int i = 2; i < GEN_LEN; i++)
		if (!strchr("0123456789abcdef", g[i])) return 0;
	return 1;
}

// boot-nonce is an OSString "0x" + 16 hex (length +0xC >> 14 includes the NUL, chars at +0x10)
static uint64_t boot_nonce_chars(struct chrp *c, char out[GEN_LEN + 1]) {
	uint64_t v = chrp_lookup(c, "com.apple.System.boot-nonce");
	if (!v || (kread32(v + 0xC) >> 14) != GEN_LEN + 1) return 0;
	uint64_t chars = STRIP(kread64(v + 0x10));
	memset(out, 0, GEN_LEN + 1);
	if (kreadbuf(chars, out, GEN_LEN) || !valid_gen(out)) return 0;
	return chars;
}

static uint64_t chosen_generator(void) {
	uint64_t gen = 0;
	io_registry_entry_t ch = IORegistryEntryFromPath(kIOMainPortDefault, "IODeviceTree:/chosen");
	if (!ch) return 0;
	CFDataRef d = IORegistryEntryCreateCFProperty(ch, CFSTR("boot-nonce"), kCFAllocatorDefault, 0);
	if (d && CFGetTypeID(d) == CFDataGetTypeID() && CFDataGetLength(d) == 8) CFDataGetBytes(d, CFRangeMake(0, 8), (UInt8 *)&gen);
	if (d) CFRelease(d);
	IOObjectRelease(ch);
	return gen;
}

// Same as x8A4 -g: the stored generator, else the one iBoot booted with
static uint64_t current_generator(void) {
	struct chrp c;
	char g[GEN_LEN + 1];
	if (!chrp_find(&c) && boot_nonce_chars(&c, g)) return strtoull(g, NULL, 16);
	return chosen_generator();
}

static void print_hex(const char *prefix, const uint8_t *b, int n) {
	printf("%s0x", prefix);
	for (int i = 0; i < n; i++) printf("%02X", b[i]);
	printf(")\n");
}

static int set_option(io_registry_entry_t e, const char *k, const char *v) {
	CFStringRef ck = CFStringCreateWithCString(NULL, k, kCFStringEncodingASCII);
	CFStringRef cv = CFStringCreateWithCString(NULL, v, kCFStringEncodingASCII);
	kern_return_t kr = NSXSetCFProperty(e, ck, cv);
	CFRelease(ck);
	CFRelease(cv);
	return kr;
}

// Same trick as x8A4_sync_nvram. Returns the failing step (1-3) or 0
static int sync_nvram(kern_return_t *kr) {
	io_registry_entry_t o = IORegistryEntryFromPath(kIOMainPortDefault, "IODeviceTree:/options");
	if (!o) return 4;
	int step = 0;
	if ((*kr = set_option(o, "delete_me_key", "delete_me_val"))) step = 1;
	else if ((*kr = set_option(o, "IONVRAM-DELETE-PROPERTY", "delete_me_key"))) step = 2;
	else if ((*kr = set_option(o, "IONVRAM-FORCESYNCNOW-PROPERTY", "com.apple.System.boot-nonce"))) step = 3;
	IOObjectRelease(o);
	return step;
}

// AppleMobileApNonce generateNonce: stores a new random generator in NVRAM. Returns a step (1 open, 2 call) or 0
static int generate_nonce(kern_return_t *kr) {
	io_service_t s = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("AppleMobileApNonce"));
	io_connect_t c = 0;
	*kr = KERN_FAILURE;
	if (!s) return 1;
	*kr = IOServiceOpen(s, mach_task_self(), 0, &c);
	IOObjectRelease(s);
	if (*kr) return 1;
	uint8_t nonce[CC_SHA384_DIGEST_LENGTH];
	size_t n = sizeof(nonce);
	*kr = IOConnectCallStructMethod(c, 0xC8, NULL, 0, nonce, &n);
	IOServiceClose(c);
	return *kr ? 2 : 0;
}

static void cmd_generator(void) {
	uint64_t g = current_generator();
	if (g) printf("APNonce generator(0x%016llx)\n", g);
	else printf("[-]: Failed to get apnonce generator!\n");
}

// A12+ entangle the generator with key 0x8A3; older SoCs hash it directly (same as x8A4)
static int is_arm64e(void) {
	cpu_subtype_t sub = 0;
	size_t len = sizeof(sub);
	return sysctlbyname("hw.cpusubtype", &sub, &len, NULL, 0) == 0 && (sub & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E;
}

static void cmd_apnonce(void) {
	uint64_t in[2] = { 0, current_generator() };
	uint8_t out[32], h[CC_SHA384_DIGEST_LENGTH];
	if (in[1] && !is_arm64e()) {
		CC_SHA384(&in[1], 8, h);
		print_hex("Got APNonce (", h, 32);
		return;
	}
	if (!in[1] || entangle(0x8A3, in, out)) {
		printf("[-]: Failed to get apnonce!\n");
		return;
	}
	print_hex("Got APNonce (", out, 32);
}

// krn.c1bt (cryptex1 boot slot): 4 zero bytes, flags, 16-byte seed, 16 zero bytes
static int cryptex_seed(uint8_t seed[16]) {
	struct chrp c;
	if (chrp_find(&c)) return -1;
	uint64_t v = chrp_lookup(&c, "krn.c1bt");
	uint8_t d[37];
	if (!v || kread32(v + 0xC) != sizeof(d) || kreadbuf(STRIP(kread64(v + 0x18)), d, sizeof(d))) return -1;
	memcpy(seed, d + 5, 16);
	return 0;
}

static void cmd_cryptex_seed(void) {
	uint8_t seed[16];
	if (cryptex_seed(seed)) printf("[-]: Failed to get cryptex seed!\n");
	else print_hex("Got cryptex seed (", seed, 16);
}

static void cmd_cryptex_nonce(void) {
	uint8_t seed[16], out[32];
	if (cryptex_seed(seed) || entangle(0x8A4, seed, out)) printf("[-]: Failed to get cryptex nonce!\n");
	else print_hex("Got cryptex nonce (", out, 32);
}

static int cmd_check(void) {
	struct chrp c;
	char g[GEN_LEN + 1];
	const char *reason = chrp_find(&c);
	if (reason) {
		printf("NSX_V3: UNSUPPORTED (%s)\n", reason);
		return -1;
	}
	if (!chrp_lookup(&c, "com.apple.System.boot-nonce")) {
		printf("NSX_V3: SUPPORTED stored(none) mode(chrp26)\n");
		return 0;
	}
	if (!boot_nonce_chars(&c, g)) {
		printf("NSX_V3: UNSUPPORTED (boot-nonce in the NVRAM dict has an unexpected format)\n");
		return -1;
	}
	printf("NSX_V3: SUPPORTED stored(%s) mode(chrp26)\n", g);
	return 0;
}

static int cmd_set(const char *arg) {
	char gen[GEN_LEN + 1] = {0}, back[GEN_LEN + 1] = {0}, cur[GEN_LEN + 1];
	struct chrp c;
	if (!arg || strlen(arg) != GEN_LEN) goto invalid;
	for (int i = 0; i < GEN_LEN; i++) gen[i] = (char)tolower((unsigned char)arg[i]);
	if (!valid_gen(gen)) goto invalid;
	const char *reason = chrp_find(&c);
	if (reason) {
		printf("NSX_V3: UNSUPPORTED (%s)\n", reason);
		return -1;
	}
	// No generator stored yet (iBoot picks a random one every boot): let the kernel create the entry
	if (!chrp_lookup(&c, "com.apple.System.boot-nonce")) {
		kern_return_t kr;
		int step = generate_nonce(&kr);
		if (step) {
			printf("NSX_V3: FAILED (generateNonce %s: 0x%x)\n", step == 1 ? "open" : "call", kr);
			return -1;
		}
	}
	uint64_t chars = boot_nonce_chars(&c, cur);
	if (!chars) {
		printf("NSX_V3: UNSUPPORTED (boot-nonce in the NVRAM dict has an unexpected format)\n");
		return -1;
	}
	int r = kwritebuf(chars, gen, GEN_LEN);
	if (r || kreadbuf(chars, back, GEN_LEN) || strcmp(back, gen)) {
		printf("NSX_V3: FAILED (kernel write %d)\n", r);
		return -1;
	}
	// serializeVariables returns early unless _newData is set
	if ((r = kwrite8(c.handler + 0x14, 1))) {
		printf("NSX_V3: FAILED (newData write %d)\n", r);
		return -1;
	}
	kern_return_t kr = 0;
	int step = sync_nvram(&kr);
	if (step) {
		printf("NSX_V3: FAILED (sync step %d: 0x%x)\n", step, kr);
		return -1;
	}
	printf("NSX_V3: OK generator(%s) synced(%s) mode(chrp26)\n", gen, (kread32(c.handler + 0x14) & 0xFF) ? "pending" : "yes");
	return 0;
invalid:
	printf("NSX_V3: FAILED (invalid generator)\n");
	return -1;
}

int main(int argc, char **argv) {
	if (getuid() != 0) {
		printf("[-]: nsx26 requires root!\n");
		return 1;
	}
	// Spawned by the app with a root persona, the audit token still says mobile, so IOKit "root" checks
	// (AppleMobileApNonce, NVRAM) fail. Exec again as root once to get a root token.
	if (!getenv("NSX26_REEXEC")) {
		char path[1024];
		uint32_t size = sizeof(path);
		if (_NSGetExecutablePath(path, &size) == 0 && setgid(0) == 0 && setuid(0) == 0) {
			setenv("NSX26_REEXEC", "1", 1);
			execv(path, argv);
		}
	}
	if (jbclient_initialize_primitives()) {
		printf("[-]: Failed to get kernel r/w from libjailbreak!\n");
		return 1;
	}
	int ret = 0;
	for (int i = 1; i < argc; i++) {
		const char *a = argv[i];
		if (!strcmp(a, "-g")) cmd_generator();
		else if (!strcmp(a, "-n")) cmd_apnonce();
		else if (!strcmp(a, "-x")) cmd_cryptex_seed();
		else if (!strcmp(a, "-t")) cmd_cryptex_nonce();
		else if (!strcmp(a, "-V")) ret |= cmd_check();
		else if (!strcmp(a, "-S")) ret |= cmd_set(i + 1 < argc ? argv[++i] : NULL);
		else {
			printf("usage: nsx26 [-g] [-n] [-x] [-t] [-V] [-S 0x<16 hex>]\n");
			return 1;
		}
		fflush(stdout);
	}
	return ret ? 1 : 0;
}
