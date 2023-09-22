/* main.c -- Professor Layton: Curious Village HD .so loader
 *
 * Copyright (C) 2021 Andy Nguyen
 * Copyright (C) 2023 Rinnegatamante
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.	See the LICENSE file for details.
 */

#include <vitasdk.h>
#include <kubridge.h>
#include <vitashark.h>
#include <vitaGL.h>
#include <zlib.h>

#define AL_ALEXT_PROTOTYPES
#include <AL/alext.h>
#include <AL/efx.h>

#include <malloc.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <wchar.h>
#include <wctype.h>

#include <math.h>
#include <math_neon.h>
#include <SLES/OpenSLES.h>

#include <errno.h>
#include <ctype.h>
#include <setjmp.h>
#include <sys/time.h>
#include <sys/stat.h>

#include "main.h"
#include "config.h"
#include "dialog.h"
#include "so_util.h"
#include "sha1.h"
#include "player.h"

#define STB_IMAGE_IMPLEMENTATION
#define STBI_ONLY_PNG
#include "stb_image.h"

//#define ENABLE_DEBUG

typedef struct {
	unsigned char *elements;
	int size;
} jni_bytearray;

static char fake_vm[0x1000];
static char fake_env[0x1000];

int _newlib_heap_size_user = MEMORY_NEWLIB_MB * 1024 * 1024;

unsigned int _pthread_stack_default_user = 1 * 1024 * 1024;

so_module layton_mod;

void *__wrap_memcpy(void *dest, const void *src, size_t n) {
	return sceClibMemcpy(dest, src, n);
}

void *__wrap_memmove(void *dest, const void *src, size_t n) {
	return sceClibMemmove(dest, src, n);
}

void *__wrap_memset(void *s, int c, size_t n) {
	return sceClibMemset(s, c, n);
}

int debugPrintf(char *fmt, ...) {
#ifdef ENABLE_DEBUG
	va_list list;
	static char string[0x8000];

	va_start(list, fmt);
	vsprintf(string, fmt, list);
	va_end(list);

	printf("[DBG] %s\n", string);
#endif
	return 0;
}

int __android_log_print(int prio, const char *tag, const char *fmt, ...) {
#ifdef ENABLE_DEBUG
	va_list list;
	static char string[0x8000];

	va_start(list, fmt);
	vsprintf(string, fmt, list);
	va_end(list);

	printf("[LOG] %s: %s\n", tag, string);
#endif
	return 0;
}

int __android_log_vprint(int prio, const char *tag, const char *fmt, va_list list) {
#ifdef ENABLE_DEBUG
	static char string[0x8000];

	vsprintf(string, fmt, list);
	va_end(list);

	printf("[LOGV] %s: %s\n", tag, string);
#endif
	return 0;
}

int ret0(void) {
	return 0;
}

int ret1(void) {
	return 1;
}

int clock_gettime(int clk_ik, struct timespec *t) {
	struct timeval now;
	int rv = gettimeofday(&now, NULL);
	if (rv)
		return rv;
	t->tv_sec = now.tv_sec;
	t->tv_nsec = now.tv_usec * 1000;
	return 0;
}

int pthread_mutex_init_fake(pthread_mutex_t **uid,
														const pthread_mutexattr_t *mutexattr) {
	pthread_mutex_t *m = calloc(1, sizeof(pthread_mutex_t));
	if (!m)
		return -1;

	const int recursive = (mutexattr && *(const int *)mutexattr == 1);
	*m = recursive ? PTHREAD_RECURSIVE_MUTEX_INITIALIZER
								 : PTHREAD_MUTEX_INITIALIZER;

	int ret = pthread_mutex_init(m, mutexattr);
	if (ret < 0) {
		free(m);
		return -1;
	}

	*uid = m;

	return 0;
}

int pthread_mutex_destroy_fake(pthread_mutex_t **uid) {
	if (uid && *uid && (uintptr_t)*uid > 0x8000) {
		pthread_mutex_destroy(*uid);
		free(*uid);
		*uid = NULL;
	}
	return 0;
}

int pthread_mutex_lock_fake(pthread_mutex_t **uid) {
	int ret = 0;
	if (!*uid) {
		ret = pthread_mutex_init_fake(uid, NULL);
	} else if ((uintptr_t)*uid == 0x4000) {
		pthread_mutexattr_t attr;
		pthread_mutexattr_init(&attr);
		pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
		ret = pthread_mutex_init_fake(uid, &attr);
		pthread_mutexattr_destroy(&attr);
	} else if ((uintptr_t)*uid == 0x8000) {
		pthread_mutexattr_t attr;
		pthread_mutexattr_init(&attr);
		pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
		ret = pthread_mutex_init_fake(uid, &attr);
		pthread_mutexattr_destroy(&attr);
	}
	if (ret < 0)
		return ret;
	return pthread_mutex_lock(*uid);
}

int pthread_mutex_unlock_fake(pthread_mutex_t **uid) {
	int ret = 0;
	if (!*uid) {
		ret = pthread_mutex_init_fake(uid, NULL);
	} else if ((uintptr_t)*uid == 0x4000) {
		pthread_mutexattr_t attr;
		pthread_mutexattr_init(&attr);
		pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
		ret = pthread_mutex_init_fake(uid, &attr);
		pthread_mutexattr_destroy(&attr);
	} else if ((uintptr_t)*uid == 0x8000) {
		pthread_mutexattr_t attr;
		pthread_mutexattr_init(&attr);
		pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
		ret = pthread_mutex_init_fake(uid, &attr);
		pthread_mutexattr_destroy(&attr);
	}
	if (ret < 0)
		return ret;
	return pthread_mutex_unlock(*uid);
}

int pthread_cond_init_fake(pthread_cond_t **cnd, const int *condattr) {
	pthread_cond_t *c = calloc(1, sizeof(pthread_cond_t));
	if (!c)
		return -1;

	*c = PTHREAD_COND_INITIALIZER;

	int ret = pthread_cond_init(c, NULL);
	if (ret < 0) {
		free(c);
		return -1;
	}

	*cnd = c;

	return 0;
}

int pthread_cond_broadcast_fake(pthread_cond_t **cnd) {
	if (!*cnd) {
		if (pthread_cond_init_fake(cnd, NULL) < 0)
			return -1;
	}
	return pthread_cond_broadcast(*cnd);
}

int pthread_cond_signal_fake(pthread_cond_t **cnd) {
	if (!*cnd) {
		if (pthread_cond_init_fake(cnd, NULL) < 0)
			return -1;
	}
	return pthread_cond_signal(*cnd);
}

int pthread_cond_destroy_fake(pthread_cond_t **cnd) {
	if (cnd && *cnd) {
		pthread_cond_destroy(*cnd);
		free(*cnd);
		*cnd = NULL;
	}
	return 0;
}

int pthread_cond_wait_fake(pthread_cond_t **cnd, pthread_mutex_t **mtx) {
	if (!*cnd) {
		if (pthread_cond_init_fake(cnd, NULL) < 0)
			return -1;
	}
	return pthread_cond_wait(*cnd, *mtx);
}

int pthread_cond_timedwait_fake(pthread_cond_t **cnd, pthread_mutex_t **mtx,
																const struct timespec *t) {
	if (!*cnd) {
		if (pthread_cond_init_fake(cnd, NULL) < 0)
			return -1;
	}
	return pthread_cond_timedwait(*cnd, *mtx, t);
}

int pthread_create_fake(pthread_t *thread, const void *unused, void *entry,
												void *arg) {
	return pthread_create(thread, NULL, entry, arg);
}

int pthread_once_fake(volatile int *once_control, void (*init_routine)(void)) {
	if (!once_control || !init_routine)
		return -1;
	if (__sync_lock_test_and_set(once_control, 1) == 0)
		(*init_routine)();
	return 0;
}

int GetCurrentThreadId(void) {
	return sceKernelGetThreadId();
}

extern void *__aeabi_ldiv0;

int GetEnv(void *vm, void **env, int r2) {
	*env = fake_env;
	return 0;
}

void *GetJNIEnv(void *this) {
	return fake_env;
}

uint8_t FS_LoadFile(char *buf, const char *fname, int pos, int size) {
	char full_fname[256];
	sprintf(full_fname, "ux0:data/layton_curious/assets/%s", fname);
	//printf("FS_LoadFile %s\n", full_fname);
	FILE *f = fopen(full_fname, "rb");
	if (f) {
		fseek(f, pos, SEEK_SET);
		fread(buf, 1, size, f);
		fclose(f);
		return 1;
	}
	return 0;
}

int FS_GetLength(const char *fname) {
	char full_fname[256];
	sprintf(full_fname, "ux0:data/layton_curious/assets/%s", fname);
	SceIoStat st;
	if (sceIoGetstat(full_fname, &st) >= 0) {
		return st.st_size;
	}
	return 0;
}

void criErr_Notify(int unk, char *error) {
	printf("Error: %s\n", error);
}

void patch_game(void) {
	hook_addr(so_symbol(&layton_mod, "_Z11FS_LoadFilePcPKcii"), FS_LoadFile);
	hook_addr(so_symbol(&layton_mod, "_Z12FS_GetLengthPKc"), FS_GetLength);
	hook_addr(so_symbol(&layton_mod, "_Z9MO_Renderv"), ret0);
	
	
	hook_addr(so_symbol(&layton_mod, "criErr_Notify"), criErr_Notify);
	//hook_addr(so_symbol(&layton_mod, "_Z9OS_PrintfPKcz"), printf);
}

extern void *__aeabi_atexit;
extern void *__aeabi_idiv;
extern void *__aeabi_idivmod;
extern void *__aeabi_ldivmod;
extern void *__aeabi_uidiv;
extern void *__aeabi_uidivmod;
extern void *__aeabi_uldivmod;
extern void *__cxa_atexit;
extern void *__cxa_finalize;
extern void *__gnu_unwind_frame;
extern void *__stack_chk_fail;
int open(const char *pathname, int flags);

static int __stack_chk_guard_fake = 0x42424242;

static char *__ctype_ = (char *)&_ctype_;

static FILE __sF_fake[0x100][3];

int stat_hook(const char *pathname, void *statbuf) {
	char real_fname[128];
	sprintf(real_fname, "%s.mp3", pathname);
	
	struct stat st;
	int res = stat(real_fname, &st);
	if (res == 0)
		*(uint64_t *)(statbuf + 0x30) = st.st_size;
	return res;
}

void *mmap(void *addr, size_t length, int prot, int flags, int fd,
					 off_t offset) {
	return malloc(length);
}

int munmap(void *addr, size_t length) {
	free(addr);
	return 0;
}

FILE *fopen_hook(char *fname, char *mode) {
	if (strstr(fname, "main.obb") && mode[0] == 'w')
		return NULL;
	//printf("opening %s %s\n", fname, mode);
	return fopen(fname, mode);
}

int open_hook(const char *fname, int flags) {
	return open(fname, flags);
}

int fstat_hook(int fd, void *statbuf) {
	struct stat st;
	int res = fstat(fd, &st);
	if (res == 0)
		*(uint64_t *)(statbuf + 0x30) = st.st_size;
	return res;
}

void *sceClibMemclr(void *dst, SceSize len) {
  return sceClibMemset(dst, 0, len);
}

void *sceClibMemset2(void *dst, SceSize len, int ch) {
  return sceClibMemset(dst, ch, len);
}

char *patched_frag = {
	"uniform sampler2D texture;uniform vec4 color;varying vec2 vary_uv;void main(){ gl_FragColor = texture2D(texture, vary_uv) * color; }"
};

void glShaderSource_hook(GLuint shader, GLsizei count, const GLchar* const* string, const GLint* length) {
	if (strstr(*string, "samplerExternalOES")) {
		glShaderSource(shader, count, &patched_frag, NULL);
	} else {
		glShaderSource(shader, count, string, length);
	}
}

pid_t gettid() {
	return sceKernelGetThreadId();
}

int nanosleep_hook(const struct timespec *req, struct timespec *rem) {
	const uint32_t usec = req->tv_sec * 1000 * 1000 + req->tv_nsec / 1000;
	return sceKernelDelayThreadCB(usec);
}

FILE *AAssetManager_open(void *mgr, const char *fname, int mode) {
	char full_fname[256];
	sprintf(full_fname, "ux0:data/layton_curious/assets/%s", fname);
	//printf("AAssetManager_open %s\n", full_fname);
	return fopen(full_fname, "rb");
}

FILE *saved_fp = NULL;
int AAsset_openFileDescriptor64(FILE *f, int64_t *start, int64_t *len) {
	fseek(f, *start, SEEK_SET);
	saved_fp = f;
	return 1;
}

FILE *fdopen_hook(int fd, const char *mode) {
	if (fd == 1) {
		FILE *r = saved_fp;
		saved_fp = NULL;
		return r;
	}
	return fdopen(fd, mode);
}

int AAsset_close(FILE *f) {
	if (saved_fp) {
		return 0;
	}
	return fclose(f);
}

size_t AAsset_getLength(FILE *f) {
	size_t p = ftell(f);
	fseek(f, 0, SEEK_END);
	size_t res = ftell(f);
	fseek(f, p, SEEK_SET);
	return res;
}

uint64_t AAsset_getLength64(FILE *f) {
	size_t p = ftell(f);
	fseek(f, 0, SEEK_END);
	uint64_t res = ftell(f);
	fseek(f, p, SEEK_SET);
	return res;
}

size_t AAsset_read(FILE *f, void *buf, size_t count) {
	return fread(buf, 1, count, f);
}

size_t AAsset_seek(FILE *f, size_t offs, int whence) {
	fseek(f, offs, whence);
	return ftell(f);
}

size_t __strlen_chk(const char *s, size_t s_len) {
	return strlen(s);
}

int __vsprintf_chk(char* dest, int flags, size_t dest_len_from_compiler, const char *format, va_list va) {
	return vsprintf(dest, format, va);
}

void *__memmove_chk(void *dest, const void *src, size_t len, size_t dstlen) {
	return memmove(dest, src, len);
}

void *__memset_chk(void *dest, int val, size_t len, size_t dstlen) {
	return memset(dest, val, len);
}

size_t __strlcat_chk (char *dest, char *src, size_t len, size_t dstlen) {
	return strlcat(dest, src, len);
}

size_t __strlcpy_chk (char *dest, char *src, size_t len, size_t dstlen) {
	return strlcpy(dest, src, len);
}

char* __strchr_chk(const char* p, int ch, size_t s_len) {
	return strchr(p, ch);
}

char *__strcat_chk(char *dest, const char *src, size_t destlen) {
	return strcat(dest, src);
}

char *__strrchr_chk(const char *p, int ch, size_t s_len) {
	return strrchr(p, ch);
}

char *__strcpy_chk(char *dest, const char *src, size_t destlen) {
	return strcpy(dest, src);
}

char *__strncat_chk(char *s1, const char *s2, size_t n, size_t s1len) {
	return strncat(s1, s2, n);
}

void *__memcpy_chk(void *dest, const void *src, size_t len, size_t destlen) {
	return memcpy(dest, src, len);
}

int __vsnprintf_chk(char *s, size_t maxlen, int flag, size_t slen, const char *format, va_list args) {
	return vsnprintf(s, maxlen, format, args);
}

void glViewport_hook(GLint x, GLint y, GLsizei width, GLsizei height) {
	glScissor(x, y, width, height);
	glViewport(x, y, width, height);
}

static so_default_dynlib default_dynlib[] = {
	{ "__strcat_chk", (uintptr_t)&__strcat_chk },
	{ "__strchr_chk", (uintptr_t)&__strchr_chk },
	{ "__strcpy_chk", (uintptr_t)&__strcpy_chk },
	{ "__strlcat_chk", (uintptr_t)&__strlcat_chk },
	{ "__strlcpy_chk", (uintptr_t)&__strlcpy_chk },
	{ "__strlen_chk", (uintptr_t)&__strlen_chk },
	{ "__strncat_chk", (uintptr_t)&__strncat_chk },
	{ "__strrchr_chk", (uintptr_t)&__strrchr_chk },
	{ "__vsprintf_chk", (uintptr_t)&__vsprintf_chk },
	{ "__vsnprintf_chk", (uintptr_t)&__vsnprintf_chk },
	{ "__memcpy_chk", (uintptr_t)&__memcpy_chk },
	{ "setpriority", (uintptr_t)&ret0 },
	{ "nanosleep", (uintptr_t)&nanosleep_hook },
	{ "SL_IID_BUFFERQUEUE", (uintptr_t)&SL_IID_BUFFERQUEUE },
	{ "SL_IID_ENGINE", (uintptr_t)&SL_IID_ENGINE },
	{ "SL_IID_ENVIRONMENTALREVERB", (uintptr_t)&SL_IID_ENVIRONMENTALREVERB },
	{ "SL_IID_PLAY", (uintptr_t)&SL_IID_PLAY },
	{ "SL_IID_VOLUME", (uintptr_t)&SL_IID_VOLUME },
	{ "slCreateEngine", (uintptr_t)&slCreateEngine },
	{ "AAssetManager_fromJava", (uintptr_t)&ret1 },
	{ "AAssetManager_open", (uintptr_t)&AAssetManager_open },
	{ "AAsset_close", (uintptr_t)&AAsset_close },
	{ "AAsset_read", (uintptr_t)&AAsset_read },
	{ "AAsset_getLength", (uintptr_t)&AAsset_getLength },
	{ "AAsset_getLength64", (uintptr_t)&AAsset_getLength64 },
	{ "AAsset_seek", (uintptr_t)&AAsset_seek },
	{ "AAsset_openFileDescriptor64", (uintptr_t)&AAsset_openFileDescriptor64 },
	{ "__aeabi_memclr", (uintptr_t)&sceClibMemclr },
	{ "__aeabi_memclr4", (uintptr_t)&sceClibMemclr },
	{ "__aeabi_memclr8", (uintptr_t)&sceClibMemclr },
	{ "__aeabi_memcpy", (uintptr_t)&sceClibMemcpy },
	{ "__aeabi_memcpy4", (uintptr_t)&sceClibMemcpy },
	{ "__aeabi_memcpy8", (uintptr_t)&sceClibMemcpy },
	{ "__aeabi_memmove", (uintptr_t)&sceClibMemmove },
	{ "__aeabi_memmove4", (uintptr_t)&sceClibMemmove },
	{ "__aeabi_memmove8", (uintptr_t)&sceClibMemmove },
	{ "__aeabi_memset", (uintptr_t)&sceClibMemset2 },
	{ "__aeabi_memset4", (uintptr_t)&sceClibMemset2 },
	{ "__aeabi_memset8", (uintptr_t)&sceClibMemset2 },
	{ "__aeabi_atexit", (uintptr_t)&__aeabi_atexit },
	{ "__aeabi_uidiv", (uintptr_t)&__aeabi_uidiv },
	{ "__aeabi_uidivmod", (uintptr_t)&__aeabi_uidivmod },
	{ "__aeabi_idiv", (uintptr_t)&__aeabi_idiv },
	{ "__aeabi_idivmod", (uintptr_t)&__aeabi_idivmod },
	{ "__android_log_print", (uintptr_t)&__android_log_print },
	{ "__android_log_vprint", (uintptr_t)&__android_log_vprint },
	{ "__cxa_atexit", (uintptr_t)&__cxa_atexit },
	{ "__cxa_finalize", (uintptr_t)&__cxa_finalize },
	{ "__errno", (uintptr_t)&__errno },
	{ "__gnu_unwind_frame", (uintptr_t)&__gnu_unwind_frame },
	// { "__google_potentially_blocking_region_begin", (uintptr_t)&__google_potentially_blocking_region_begin },
	// { "__google_potentially_blocking_region_end", (uintptr_t)&__google_potentially_blocking_region_end },
	{ "__sF", (uintptr_t)&__sF_fake },
	{ "__stack_chk_fail", (uintptr_t)&__stack_chk_fail },
	{ "__stack_chk_guard", (uintptr_t)&__stack_chk_guard_fake },
	{ "_ctype_", (uintptr_t)&__ctype_ },
	{ "abort", (uintptr_t)&abort },
	// { "accept", (uintptr_t)&accept },
	{ "acos", (uintptr_t)&acos },
	{ "acosf", (uintptr_t)&acosf },
	{ "asin", (uintptr_t)&asin },
	{ "asinf", (uintptr_t)&asinf },
	{ "atan", (uintptr_t)&atan },
	{ "atan2", (uintptr_t)&atan2 },
	{ "atan2f", (uintptr_t)&atan2f },
	{ "atanf", (uintptr_t)&atanf },
	{ "atoi", (uintptr_t)&atoi },
	{ "atoll", (uintptr_t)&atoll },
	// { "bind", (uintptr_t)&bind },
	{ "bsearch", (uintptr_t)&bsearch },
	{ "btowc", (uintptr_t)&btowc },
	{ "calloc", (uintptr_t)&calloc },
	{ "ceil", (uintptr_t)&ceil },
	{ "ceilf", (uintptr_t)&ceilf },
	{ "clearerr", (uintptr_t)&clearerr },
	{ "clock", (uintptr_t)&clock },
	{ "clock_gettime", (uintptr_t)&clock_gettime },
	{ "close", (uintptr_t)&close },
	{ "cos", (uintptr_t)&cos },
	{ "cosf", (uintptr_t)&cosf },
	{ "cosh", (uintptr_t)&cosh },
	{ "crc32", (uintptr_t)&crc32 },
	{ "difftime", (uintptr_t)&difftime },
	{ "div", (uintptr_t)&div },
	{ "dlopen", (uintptr_t)&ret0 },
	{ "exit", (uintptr_t)&exit },
	{ "exp", (uintptr_t)&exp },
	{ "exp2f", (uintptr_t)&exp2f },
	{ "expf", (uintptr_t)&expf },
	{ "fclose", (uintptr_t)&fclose },
	{ "fcntl", (uintptr_t)&ret0 },
	{ "fdopen", (uintptr_t)&fdopen_hook },
	{ "ferror", (uintptr_t)&ferror },
	{ "fflush", (uintptr_t)&fflush },
	{ "fgets", (uintptr_t)&fgets },
	{ "floor", (uintptr_t)&floor },
	{ "floorf", (uintptr_t)&floorf },
	{ "fmod", (uintptr_t)&fmod },
	{ "fmodf", (uintptr_t)&fmodf },
	{ "fopen", (uintptr_t)&fopen_hook },
	{ "fprintf", (uintptr_t)&fprintf },
	{ "fputc", (uintptr_t)&fputc },
	{ "fputs", (uintptr_t)&fputs },
	{ "fread", (uintptr_t)&fread },
	{ "free", (uintptr_t)&free },
	{ "frexp", (uintptr_t)&frexp },
	{ "frexpf", (uintptr_t)&frexpf },
	{ "fscanf", (uintptr_t)&fscanf },
	{ "fseek", (uintptr_t)&fseek },
	{ "fstat", (uintptr_t)&fstat_hook },
	{ "ftell", (uintptr_t)&ftell },
	{ "fwrite", (uintptr_t)&fwrite },
	{ "getc", (uintptr_t)&getc },
	{ "gettid", (uintptr_t)&gettid },
	{ "getenv", (uintptr_t)&ret0 },
	{ "getwc", (uintptr_t)&getwc },
	{ "gettimeofday", (uintptr_t)&gettimeofday },
	{ "glVertexAttribPointer", (uintptr_t)&glVertexAttribPointer },
	{ "glEnableVertexAttribArray", (uintptr_t)&glEnableVertexAttribArray },
	{ "glAlphaFunc", (uintptr_t)&glAlphaFunc },
	{ "glBindBuffer", (uintptr_t)&glBindBuffer },
	{ "glBindTexture", (uintptr_t)&glBindTexture },
	{ "glBlendFunc", (uintptr_t)&glBlendFunc },
	{ "glBufferData", (uintptr_t)&glBufferData },
	{ "glClear", (uintptr_t)&ret0 },
	{ "glClearColor", (uintptr_t)&ret0 },
	{ "glClearDepthf", (uintptr_t)&glClearDepthf },
	{ "glColorPointer", (uintptr_t)&glColorPointer },
	{ "glCompressedTexImage2D", (uintptr_t)&glCompressedTexImage2D },
	{ "glDeleteBuffers", (uintptr_t)&glDeleteBuffers },
	{ "glDeleteTextures", (uintptr_t)&glDeleteTextures },
	{ "glDepthFunc", (uintptr_t)&glDepthFunc },
	{ "glDepthMask", (uintptr_t)&glDepthMask },
	{ "glDisable", (uintptr_t)&glDisable },
	{ "glDrawElements", (uintptr_t)&glDrawElements },
	{ "glEnable", (uintptr_t)&glEnable },
	{ "glEnableClientState", (uintptr_t)&glEnableClientState },
	{ "glGenBuffers", (uintptr_t)&glGenBuffers },
	{ "glGenTextures", (uintptr_t)&glGenTextures },
	{ "glGetError", (uintptr_t)&ret0 },
	{ "glLoadIdentity", (uintptr_t)&glLoadIdentity },
	{ "glMatrixMode", (uintptr_t)&glMatrixMode },
	{ "glMultMatrixx", (uintptr_t)&glMultMatrixx },
	{ "glOrthof", (uintptr_t)&glOrthof },
	{ "glPixelStorei", (uintptr_t)&ret0 },
	{ "glPopMatrix", (uintptr_t)&glPopMatrix },
	{ "glPushMatrix", (uintptr_t)&glPushMatrix },
	{ "glTexCoordPointer", (uintptr_t)&glTexCoordPointer },
	{ "glTexImage2D", (uintptr_t)&glTexImage2D },
	{ "glTexParameteri", (uintptr_t)&glTexParameteri },
	{ "glTexSubImage2D", (uintptr_t)&glTexSubImage2D },
	{ "glTranslatex", (uintptr_t)&glTranslatex },
	{ "glVertexPointer", (uintptr_t)&glVertexPointer },
	{ "glShaderSource", (uintptr_t)&glShaderSource_hook },
	{ "glViewport", (uintptr_t)&glViewport_hook },
	{ "gmtime", (uintptr_t)&gmtime },
	{ "gzopen", (uintptr_t)&ret0 },
	{ "inflate", (uintptr_t)&inflate },
	{ "inflateEnd", (uintptr_t)&inflateEnd },
	{ "inflateInit_", (uintptr_t)&inflateInit_ },
	{ "inflateReset", (uintptr_t)&inflateReset },
	{ "isalnum", (uintptr_t)&isalnum },
	{ "isalpha", (uintptr_t)&isalpha },
	{ "iscntrl", (uintptr_t)&iscntrl },
	{ "islower", (uintptr_t)&islower },
	{ "ispunct", (uintptr_t)&ispunct },
	{ "isprint", (uintptr_t)&isprint },
	{ "isspace", (uintptr_t)&isspace },
	{ "isupper", (uintptr_t)&isupper },
	{ "iswalpha", (uintptr_t)&iswalpha },
	{ "iswcntrl", (uintptr_t)&iswcntrl },
	{ "iswctype", (uintptr_t)&iswctype },
	{ "iswdigit", (uintptr_t)&iswdigit },
	{ "iswdigit", (uintptr_t)&iswdigit },
	{ "iswlower", (uintptr_t)&iswlower },
	{ "iswprint", (uintptr_t)&iswprint },
	{ "iswpunct", (uintptr_t)&iswpunct },
	{ "iswspace", (uintptr_t)&iswspace },
	{ "iswupper", (uintptr_t)&iswupper },
	{ "iswxdigit", (uintptr_t)&iswxdigit },
	{ "isxdigit", (uintptr_t)&isxdigit },
	{ "ldexp", (uintptr_t)&ldexp },
	// { "listen", (uintptr_t)&listen },
	{ "localtime", (uintptr_t)&localtime },
	{ "localtime_r", (uintptr_t)&localtime_r },
	{ "log", (uintptr_t)&log },
	{ "log10", (uintptr_t)&log10 },
	{ "longjmp", (uintptr_t)&longjmp },
	{ "lrand48", (uintptr_t)&lrand48 },
	{ "lrint", (uintptr_t)&lrint },
	{ "lrintf", (uintptr_t)&lrintf },
	{ "lseek", (uintptr_t)&lseek },
	{ "malloc", (uintptr_t)&malloc },
	{ "mbrtowc", (uintptr_t)&mbrtowc },
	{ "memchr", (uintptr_t)&sceClibMemchr },
	{ "memcmp", (uintptr_t)&memcmp },
	{ "memcpy", (uintptr_t)&sceClibMemcpy },
	{ "memmove", (uintptr_t)&sceClibMemmove },
	{ "memset", (uintptr_t)&sceClibMemset },
	{ "mkdir", (uintptr_t)&mkdir },
	{ "mktime", (uintptr_t)&mktime },
	{ "mmap", (uintptr_t)&mmap},
	{ "munmap", (uintptr_t)&munmap},
	{ "modf", (uintptr_t)&modf },
	// { "poll", (uintptr_t)&poll },
	{ "open", (uintptr_t)&open_hook },
	{ "pow", (uintptr_t)&pow },
	{ "powf", (uintptr_t)&powf },
	{ "printf", (uintptr_t)&printf },
	{ "puts", (uintptr_t)&puts },
	{ "pthread_attr_destroy", (uintptr_t)&ret0 },
	{ "pthread_attr_init", (uintptr_t)&ret0 },
	{ "pthread_attr_setdetachstate", (uintptr_t)&ret0 },
	{ "pthread_attr_setschedpolicy", (uintptr_t)&ret0 },
	{ "pthread_attr_setschedparam", (uintptr_t)&ret0 },
	{ "pthread_cond_init", (uintptr_t)&pthread_cond_init_fake},
	{ "pthread_cond_signal", (uintptr_t)&pthread_cond_signal_fake},
	{ "pthread_cond_broadcast", (uintptr_t)&pthread_cond_broadcast_fake},
	{ "pthread_cond_wait", (uintptr_t)&pthread_cond_wait_fake},
	{ "pthread_create", (uintptr_t)&pthread_create_fake },
	{ "pthread_getschedparam", (uintptr_t)&pthread_getschedparam },
	{ "pthread_getspecific", (uintptr_t)&pthread_getspecific },
	{ "pthread_key_create", (uintptr_t)&pthread_key_create },
	{ "pthread_key_delete", (uintptr_t)&pthread_key_delete },
	{ "pthread_mutex_destroy", (uintptr_t)&pthread_mutex_destroy_fake },
	{ "pthread_mutex_init", (uintptr_t)&pthread_mutex_init_fake },
	{ "pthread_mutex_lock", (uintptr_t)&pthread_mutex_lock_fake },
	{ "pthread_mutex_unlock", (uintptr_t)&pthread_mutex_unlock_fake },
	{ "pthread_once", (uintptr_t)&pthread_once_fake },
	{ "pthread_self", (uintptr_t)&pthread_self },
	{ "pthread_setschedparam", (uintptr_t)&pthread_setschedparam },
	{ "pthread_setspecific", (uintptr_t)&pthread_setspecific },
	{ "pthread_setname_np", (uintptr_t)&ret0 },
	{ "putc", (uintptr_t)&putc },
	{ "putwc", (uintptr_t)&putwc },
	{ "qsort", (uintptr_t)&qsort },
	{ "read", (uintptr_t)&read },
	{ "realloc", (uintptr_t)&realloc },
	{ "remove", (uintptr_t)&remove },
	// { "recv", (uintptr_t)&recv },
	{ "rint", (uintptr_t)&rint },
	// { "send", (uintptr_t)&send },
	// { "sendto", (uintptr_t)&sendto },
	{ "setenv", (uintptr_t)&ret0 },
	{ "setjmp", (uintptr_t)&setjmp },
	// { "setlocale", (uintptr_t)&setlocale },
	// { "setsockopt", (uintptr_t)&setsockopt },
	{ "setvbuf", (uintptr_t)&setvbuf },
	{ "sin", (uintptr_t)&sin },
	{ "sincosf", (uintptr_t)&sincosf },
	{ "sinf", (uintptr_t)&sinf },
	{ "sinh", (uintptr_t)&sinh },
	{ "snprintf", (uintptr_t)&snprintf },
	// { "socket", (uintptr_t)&socket },
	{ "sprintf", (uintptr_t)&sprintf },
	{ "sqrt", (uintptr_t)&sqrt },
	{ "sqrtf", (uintptr_t)&sqrtf },
	{ "srand48", (uintptr_t)&srand48 },
	{ "sscanf", (uintptr_t)&sscanf },
	{ "stat", (uintptr_t)&stat_hook },
	{ "strcasecmp", (uintptr_t)&strcasecmp },
	{ "strcat", (uintptr_t)&strcat },
	{ "strchr", (uintptr_t)&strchr },
	{ "strcmp", (uintptr_t)&sceClibStrcmp },
	{ "strcoll", (uintptr_t)&strcoll },
	{ "strcpy", (uintptr_t)&strcpy },
	{ "strcspn", (uintptr_t)&strcspn },
	{ "strerror", (uintptr_t)&strerror },
	{ "strftime", (uintptr_t)&strftime },
	{ "strlen", (uintptr_t)&strlen },
	{ "strncasecmp", (uintptr_t)&sceClibStrncasecmp },
	{ "strncat", (uintptr_t)&sceClibStrncat },
	{ "strncmp", (uintptr_t)&sceClibStrncmp },
	{ "strncpy", (uintptr_t)&sceClibStrncpy },
	{ "strpbrk", (uintptr_t)&strpbrk },
	{ "strrchr", (uintptr_t)&sceClibStrrchr },
	{ "strdup", (uintptr_t)&strdup },
	{ "strstr", (uintptr_t)&sceClibStrstr },
	{ "strtod", (uintptr_t)&strtod },
	{ "strtol", (uintptr_t)&strtol },
	{ "strtok", (uintptr_t)&strtok },
	{ "strtoul", (uintptr_t)&strtoul },
	{ "strxfrm", (uintptr_t)&strxfrm },
	{ "sysconf", (uintptr_t)&ret0 },
	{ "tan", (uintptr_t)&tan },
	{ "tanf", (uintptr_t)&tanf },
	{ "tanh", (uintptr_t)&tanh },
	{ "time", (uintptr_t)&time },
	{ "tolower", (uintptr_t)&tolower },
	{ "toupper", (uintptr_t)&toupper },
	{ "towlower", (uintptr_t)&towlower },
	{ "towupper", (uintptr_t)&towupper },
	{ "ungetc", (uintptr_t)&ungetc },
	{ "ungetwc", (uintptr_t)&ungetwc },
	{ "usleep", (uintptr_t)&usleep },
	{ "vfprintf", (uintptr_t)&vfprintf },
	{ "vprintf", (uintptr_t)&vprintf },
	{ "vsnprintf", (uintptr_t)&vsnprintf },
	{ "vsprintf", (uintptr_t)&vsprintf },
	{ "vswprintf", (uintptr_t)&vswprintf },
	{ "wcrtomb", (uintptr_t)&wcrtomb },
	{ "wcscoll", (uintptr_t)&wcscoll },
	{ "wcscmp", (uintptr_t)&wcscmp },
	{ "wcsncpy", (uintptr_t)&wcsncpy },
	{ "wcsftime", (uintptr_t)&wcsftime },
	{ "wcslen", (uintptr_t)&wcslen },
	{ "wcsxfrm", (uintptr_t)&wcsxfrm },
	{ "wctob", (uintptr_t)&wctob },
	{ "wctype", (uintptr_t)&wctype },
	{ "wmemchr", (uintptr_t)&wmemchr },
	{ "wmemcmp", (uintptr_t)&wmemcmp },
	{ "wmemcpy", (uintptr_t)&wmemcpy },
	{ "wmemmove", (uintptr_t)&wmemmove },
	{ "wmemset", (uintptr_t)&wmemset },
	{ "write", (uintptr_t)&write },
	// { "writev", (uintptr_t)&writev },
};

int check_kubridge(void) {
	int search_unk[2];
	return _vshKernelSearchModuleByName("kubridge", search_unk);
}

int file_exists(const char *path) {
	SceIoStat stat;
	return sceIoGetstat(path, &stat) >= 0;
}

enum MethodIDs {
	UNKNOWN = 0,
	INIT,
	CARD_GetFilesDirName,
	GL_LoadPNG,
	LVL_GetState,
	LSH_GetState,
	SBS_GetState,
	L5iD_IsEndRequest,
	UI_StartEditText,
	UI_GetEditText,
	UI_GetEditState,
	MO_PlayMovie,
	MO_GetState,
	MO_ReleaseMovie,
	MO_GetPosition,
	MO_PauseMovie,
	MO_SetVolume,
	DL_GetFileName,
} MethodIDs;

typedef struct {
	char *name;
	enum MethodIDs id;
} NameToMethodID;

static NameToMethodID name_to_method_ids[] = {
	{ "<init>", INIT },
	{ "CARD_GetFilesDirName", CARD_GetFilesDirName },
	{ "GL_LoadPNG", GL_LoadPNG },
	{ "LVL_GetState", LVL_GetState },
	{ "LSH_GetState", LSH_GetState },
	{ "SBS_GetState", SBS_GetState },
	{ "L5iD_IsEndRequest", L5iD_IsEndRequest },
	{ "UI_StartEditText", UI_StartEditText },
	{ "UI_GetEditText", UI_GetEditText },
	{ "UI_GetEditState", UI_GetEditState },
	{ "MO_PlayMovie", MO_PlayMovie },
	{ "MO_GetState", MO_GetState },
	{ "MO_ReleaseMovie", MO_ReleaseMovie },
	{ "DL_GetFileName", DL_GetFileName },
	{ "MO_GetPosition", MO_GetPosition },
	{ "MO_PauseMovie", MO_PauseMovie },
	{ "MO_SetVolume", MO_SetVolume },
};

int GetMethodID(void *env, void *class, const char *name, const char *sig) {
	for (int i = 0; i < sizeof(name_to_method_ids) / sizeof(NameToMethodID); i++) {
		if (strcmp(name, name_to_method_ids[i].name) == 0) {
			return name_to_method_ids[i].id;
		}
	}

	printf("%s\n", name);
	return UNKNOWN;
}

int GetStaticMethodID(void *env, void *class, const char *name, const char *sig) {
	for (int i = 0; i < sizeof(name_to_method_ids) / sizeof(NameToMethodID); i++) {
		if (strcmp(name, name_to_method_ids[i].name) == 0)
			return name_to_method_ids[i].id;
	}
	
	printf("Static: %s\n", name);
	return UNKNOWN;
}

void CallStaticVoidMethodV(void *env, void *obj, int methodID, uintptr_t *args) {
	switch (methodID) {
	default:
		break;
	}
}

int CallStaticBooleanMethodV(void *env, void *obj, int methodID, uintptr_t *args) {
	return 0;
}

int CallStaticIntMethodV(void *env, void *obj, int methodID, uintptr_t *args) {
	int ret;
	switch (methodID) {
	default:
		break;
	}
	return 0;
}

size_t array_size = 0;
int delete_next = 0;
void *CallStaticObjectMethodV(void *env, void *obj, int methodID, uintptr_t *args) {
	int w, h;
	void *buf;
	uint8_t *src;
	int *res;
	switch (methodID) {
	case GL_LoadPNG:
		delete_next = 1;
		buf = stbi_load_from_memory(args[0], array_size, &w, &h, NULL, 4);
		src = buf;
		for (int i = 0; i < w * h; i++) {
			uint8_t tmp = src[0];
			src[0] = src[2];
			src[2] = tmp;
			src += 4;
		}
		res = (int *)malloc(w * h * 4 + 8);
		res[0] = w;
		res[1] = h;
		sceClibMemcpy(&res[2], buf, w * h * 4);
		free(buf);
		return res;
	default:
		break;
	}
	return NULL;
}

uint64_t CallLongMethodV(void *env, void *obj, int methodID, uintptr_t *args) {
	return -1;
}

int32_t CallIntMethodV(void *env, void *obj, int methodID, uintptr_t *args) {
	switch (methodID) {
	case LVL_GetState:
	case LSH_GetState:
	case SBS_GetState:
		return 2;
	case MO_GetPosition:
		return video_get_current_time();
	default:
		break;
	}
	return 0;
}

void *FindClass(void) {
	return (void *)0x41414141;
}

void *NewGlobalRef(void *env, char *str) {
	return (void *)0x42424242;
}

void DeleteGlobalRef(void *env, char *str) {
}

void *NewObjectV(void *env, void *clazz, int methodID, uintptr_t args) {
	return (void *)0x43434343;
}

void *GetObjectClass(void *env, void *obj) {
	return (void *)0x44444444;
}

char *NewStringUTF(void *env, char *bytes) {
	return bytes;
}

char *GetStringUTFChars(void *env, char *string, int *isCopy) {
	return string;
}

int GetJavaVM(void *env, void **vm) {
	*vm = fake_vm;
	return 0;
}

int GetFieldID(void *env, void *clazz, const char *name, const char *sig) {
	return 0;
}

int GetBooleanField(void *env, void *obj, int fieldID) {
	return 0;
}

void *CallObjectMethodV(void *env, void *obj, int methodID, uintptr_t *args) {
	switch (methodID) {
	case CARD_GetFilesDirName:
		return "ux0:data/layton_curious";
	case UI_GetEditText:
		return get_ime_dialog_result();
	case DL_GetFileName:
		return "ux0:data/layton_curious/data/main.obb";
	}
	return NULL;
}

uint8_t has_edit_text = 0;
uint8_t has_movie = 0;
int CallBooleanMethodV(void *env, void *obj, int methodID, va_list args) {
	char fname[256];
	char *file;
	off_t offs;
	size_t size;
	switch (methodID) {
	case MO_PlayMovie:
		file = va_arg(args, char *);
		offs = va_arg(args, off_t);
		size = va_arg(args, size_t);
		sprintf(fname, "ux0:data/layton_curious/assets/%s", file);
		video_open(fname, offs, size);
		has_movie = 1;
		return 1;
	case MO_GetState:
		return has_movie;
	case L5iD_IsEndRequest:
		return 1;
	case UI_GetEditState:
		return has_edit_text;
	default:
		return 0;
	}
}

uint8_t close_movie = 0;
void CallVoidMethodV(void *env, void *obj, int methodID, uintptr_t *args) {
	switch (methodID) {
	case UI_StartEditText:
		init_ime_dialog("", args[0]);
		has_edit_text = 1;
		break;
	case MO_PauseMovie:
		args[0] ? video_pause() : video_resume();
		break;
	case MO_ReleaseMovie:
		if (has_movie)
			close_movie = 1;
		break;
	case MO_SetVolume:
		video_set_volume(args[0]);
		break;
	default:
		break;
	}
}

uint8_t *NewByteArray(void *env, size_t size) {
	uint8_t *res = (uint8_t *)malloc(size);
	array_size = size;
	return res;
}

uint8_t *SetByteArrayRegion(void *env, uint8_t *array, size_t start, size_t len, uint8_t *buf) {
	sceClibMemcpy(&array[start], buf, len);
	return array;
}

void ReleaseByteArrayElements(void *env, uint8_t *array, void *elems, int mode) {
	free(array);
}

int GetIntField(void *env, void *obj, int fieldID) { return 0; }

int *GetIntArrayElements(void *env, int *array, int *isCopy) {
	if (isCopy) {
		*isCopy = 0;
	}
	return array;
}

void DeleteLocalRef(void *env, void *ref) {
	if (delete_next) {
		free(ref);
		delete_next = 0;
	}
}

void setup_2d_draw_rotated(float *bg_attributes, float x, float y, float x2, float y2) {
	glUseProgram(0);
	glDisable(GL_DEPTH_TEST);
	glDepthMask(GL_FALSE);
	glDisable(GL_CULL_FACE);
	glEnable(GL_BLEND);
	glDisable(GL_ALPHA_TEST);
	glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
	glEnable(GL_TEXTURE_2D);
	glEnableClientState(GL_VERTEX_ARRAY);
	glEnableClientState(GL_TEXTURE_COORD_ARRAY);
	glDisableClientState(GL_COLOR_ARRAY);
	glMatrixMode(GL_PROJECTION);
	glLoadIdentity();
	glOrthof(0, 960, 544, 0, -1, 1);
	glMatrixMode(GL_MODELVIEW);
	glLoadIdentity();
				
	bg_attributes[0] = x;
	bg_attributes[1] = y2;
	bg_attributes[2] = 0.0f;
	bg_attributes[3] = x2;
	bg_attributes[4] = y2;
	bg_attributes[5] = 0.0f;
	bg_attributes[6] = x;
	bg_attributes[7] = y;
	bg_attributes[8] = 0.0f;
	bg_attributes[9] = x2;
	bg_attributes[10] = y;
	bg_attributes[11] = 0.0f;
	vglVertexPointerMapped(3, bg_attributes);
	
	bg_attributes[12] = 0.0f;
	bg_attributes[13] = 0.0f;
	bg_attributes[14] = 0.0f;
	bg_attributes[15] = 1.0f;
	bg_attributes[16] = 1.0f;
	bg_attributes[17] = 0.0f;
	bg_attributes[18] = 1.0f;
	bg_attributes[19] = 1.0f;
	vglTexCoordPointerMapped(&bg_attributes[12]);
	
	uint16_t *bg_indices = (uint16_t*)&bg_attributes[20];
	bg_indices[0] = 0;
	bg_indices[1] = 1;
	bg_indices[2] = 2;
	bg_indices[3] = 3;
	vglIndexPointerMapped(bg_indices);
}

void setup_2d_draw(float *bg_attributes, float x, float y, float x2, float y2) {
	glUseProgram(0);
	glDisable(GL_DEPTH_TEST);
	glDepthMask(GL_FALSE);
	glDisable(GL_CULL_FACE);
	glEnable(GL_BLEND);
	glDisable(GL_ALPHA_TEST);
	glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
	glEnable(GL_TEXTURE_2D);
	glEnableClientState(GL_VERTEX_ARRAY);
	glEnableClientState(GL_TEXTURE_COORD_ARRAY);
	glDisableClientState(GL_COLOR_ARRAY);
	glMatrixMode(GL_PROJECTION);
	glLoadIdentity();
	glOrthof(0, 960, 544, 0, -1, 1);
	glMatrixMode(GL_MODELVIEW);
	glLoadIdentity();
				
	bg_attributes[0] = x;
	bg_attributes[1] = y;
	bg_attributes[2] = 0.0f;
	bg_attributes[3] = x2;
	bg_attributes[4] = y;
	bg_attributes[5] = 0.0f;
	bg_attributes[6] = x;
	bg_attributes[7] = y2;
	bg_attributes[8] = 0.0f;
	bg_attributes[9] = x2;
	bg_attributes[10] = y2;
	bg_attributes[11] = 0.0f;
	vglVertexPointerMapped(3, bg_attributes);
	
	bg_attributes[12] = 0.0f;
	bg_attributes[13] = 0.0f;
	bg_attributes[14] = 1.0f;
	bg_attributes[15] = 0.0f;
	bg_attributes[16] = 0.0f;
	bg_attributes[17] = 1.0f;
	bg_attributes[18] = 1.0f;
	bg_attributes[19] = 1.0f;
	vglTexCoordPointerMapped(&bg_attributes[12]);
	
	uint16_t *bg_indices = (uint16_t*)&bg_attributes[20];
	bg_indices[0] = 0;
	bg_indices[1] = 1;
	bg_indices[2] = 2;
	bg_indices[3] = 3;
	vglIndexPointerMapped(bg_indices);
}

void *real_main(void *argv) {
	//sceSysmoduleLoadModule(SCE_SYSMODULE_RAZOR_CAPTURE);
	SceAppUtilInitParam init_param;
	SceAppUtilBootParam boot_param;
	memset(&init_param, 0, sizeof(SceAppUtilInitParam));
	memset(&boot_param, 0, sizeof(SceAppUtilBootParam));
	sceAppUtilInit(&init_param, &boot_param);
	
	sceTouchSetSamplingState(SCE_TOUCH_PORT_FRONT, SCE_TOUCH_SAMPLING_STATE_START);

	scePowerSetArmClockFrequency(444);
	scePowerSetBusClockFrequency(222);
	scePowerSetGpuClockFrequency(222);
	scePowerSetGpuXbarClockFrequency(166);
	
	uint32_t platform =  sceKernelGetModelForCDialog();
	printf("Platform: %x\n", platform);
	uint32_t force_landscape = platform == 0x20000 ? 1 : 0;
	if (!force_landscape) {
		SceAppUtilAppEventParam eventParam;
		sceClibMemset(&eventParam, 0, sizeof(SceAppUtilAppEventParam));
		sceAppUtilReceiveAppEvent(&eventParam);
		if (eventParam.type == 0x05) {
			char buffer[2048];
			sceAppUtilAppEventParseLiveArea(&eventParam, buffer);
			if (strstr(buffer, "landscape"))
				force_landscape = 1;
		}
	}

	if (check_kubridge() < 0)
		fatal_error("Error kubridge.skprx is not installed.");

	if (!file_exists("ur0:/data/libshacccg.suprx") && !file_exists("ur0:/data/external/libshacccg.suprx"))
		fatal_error("Error libshacccg.suprx is not installed.");

	if (so_file_load(&layton_mod, SO_PATH, LOAD_ADDRESS) < 0)
		fatal_error("Error could not load %s.", SO_PATH);

	so_relocate(&layton_mod);
	so_resolve(&layton_mod, default_dynlib, sizeof(default_dynlib), 0);

	patch_game();
	so_flush_caches(&layton_mod);

	so_initialize(&layton_mod);
	
	vglSetSemanticBindingMode(VGL_MODE_SHADER_PAIR);
	vglSetupGarbageCollector(127, 0x20000);
	vglInitWithCustomThreshold(0, SCREEN_W, SCREEN_H, MEMORY_VITAGL_THRESHOLD_MB * 1024 * 1024, 0, 20 * 1024 * 1024, 12 * 1024 * 1024, SCE_GXM_MULTISAMPLE_NONE);
	sceSysmoduleLoadModule(SCE_SYSMODULE_AVPLAYER);
	
	memset(fake_vm, 'A', sizeof(fake_vm));
	*(uintptr_t *)(fake_vm + 0x00) = (uintptr_t)fake_vm; // just point to itself...
	*(uintptr_t *)(fake_vm + 0x10) = (uintptr_t)ret0;
	*(uintptr_t *)(fake_vm + 0x14) = (uintptr_t)ret0;
	*(uintptr_t *)(fake_vm + 0x18) = (uintptr_t)GetEnv;

	memset(fake_env, 'A', sizeof(fake_env));
	*(uintptr_t *)(fake_env + 0x00) = (uintptr_t)fake_env; // just point to itself...
	*(uintptr_t *)(fake_env + 0x18) = (uintptr_t)FindClass;
	*(uintptr_t *)(fake_env + 0x54) = (uintptr_t)NewGlobalRef;
	*(uintptr_t *)(fake_env + 0x58) = (uintptr_t)DeleteGlobalRef;
	*(uintptr_t *)(fake_env + 0x5C) = (uintptr_t)DeleteLocalRef;
	*(uintptr_t *)(fake_env + 0x74) = (uintptr_t)NewObjectV;
	*(uintptr_t *)(fake_env + 0x7C) = (uintptr_t)GetObjectClass;
	*(uintptr_t *)(fake_env + 0x84) = (uintptr_t)GetMethodID;
	*(uintptr_t *)(fake_env + 0x8C) = (uintptr_t)CallObjectMethodV;
	*(uintptr_t *)(fake_env + 0x98) = (uintptr_t)CallBooleanMethodV;
	*(uintptr_t *)(fake_env + 0xC8) = (uintptr_t)CallIntMethodV;
	*(uintptr_t *)(fake_env + 0xD4) = (uintptr_t)CallLongMethodV;
	*(uintptr_t *)(fake_env + 0xF8) = (uintptr_t)CallVoidMethodV;
	*(uintptr_t *)(fake_env + 0x178) = (uintptr_t)GetFieldID;
	*(uintptr_t *)(fake_env + 0x17C) = (uintptr_t)GetBooleanField;
	*(uintptr_t *)(fake_env + 0x190) = (uintptr_t)GetIntField;
	*(uintptr_t *)(fake_env + 0x1C4) = (uintptr_t)GetStaticMethodID;
	*(uintptr_t *)(fake_env + 0x1CC) = (uintptr_t)CallStaticObjectMethodV;
	*(uintptr_t *)(fake_env + 0x1D8) = (uintptr_t)CallStaticBooleanMethodV;
	*(uintptr_t *)(fake_env + 0x208) = (uintptr_t)CallStaticIntMethodV;
	*(uintptr_t *)(fake_env + 0x238) = (uintptr_t)CallStaticVoidMethodV;
	*(uintptr_t *)(fake_env + 0x29C) = (uintptr_t)NewStringUTF;
	*(uintptr_t *)(fake_env + 0x2A4) = (uintptr_t)GetStringUTFChars;
	*(uintptr_t *)(fake_env + 0x2A8) = (uintptr_t)ret0;
	*(uintptr_t *)(fake_env + 0x2C0) = (uintptr_t)NewByteArray;
	*(uintptr_t *)(fake_env + 0x2EC) = (uintptr_t)GetIntArrayElements;
	*(uintptr_t *)(fake_env + 0x30C) = (uintptr_t)ReleaseByteArrayElements;
	*(uintptr_t *)(fake_env + 0x340) = (uintptr_t)SetByteArrayRegion;
	*(uintptr_t *)(fake_env + 0x36C) = (uintptr_t)GetJavaVM;
	
	int (* Java_com_Level5_LT1R_MainActivity_setViewSize)(void *env, void *obj, int w, int h) = (void *)so_symbol(&layton_mod, "Java_com_Level5_LT1R_MainActivity_setViewSize");
	int (* Java_com_Level5_LT1R_MainActivity_render)(void *env, void *obj, int frame, int button, int touch_num, float touch_x1, float touch_y1, float touch_x2, float touch_y2) = (void *)so_symbol(&layton_mod, "Java_com_Level5_LT1R_MainActivity_render");
	int (* JNI_OnLoad)(void *vm) = (void *)so_symbol(&layton_mod, "JNI_OnLoad");
	
	uint32_t *systemData = (uint8_t *)so_symbol(&layton_mod, "systemData");
	
	int cur_frame = 0;
	JNI_OnLoad(fake_vm);
	if (force_landscape)
		Java_com_Level5_LT1R_MainActivity_setViewSize(fake_env, NULL, SCREEN_W, SCREEN_H);
	else
		Java_com_Level5_LT1R_MainActivity_setViewSize(fake_env, NULL, SCREEN_H, SCREEN_W);
	
	GLuint main_fb, main_tex;
	if (!force_landscape) {
		glGenTextures(1, &main_tex);
		glBindTexture(GL_TEXTURE_2D, main_tex);
		glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, SCREEN_H, SCREEN_W, 0, GL_RGBA, GL_UNSIGNED_BYTE, NULL);
		glGenFramebuffers(1, &main_fb);
		glBindFramebuffer(GL_FRAMEBUFFER, main_fb);
		glFramebufferTexture(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, main_tex, 0);
	}
	
	printf("Entering loop\n");
	float *bg_attributes = (float*)malloc(sizeof(float) * 44);
	uint32_t tick = sceKernelGetProcessTimeLow();
	for (;;) {
		glEnable(GL_SCISSOR_TEST);
		SceTouchData touch;
		sceTouchPeek(SCE_TOUCH_PORT_FRONT, &touch, 1);
		uint32_t delta = sceKernelGetProcessTimeLow() - tick;
		tick += delta;
		if (force_landscape) {
			glViewport(0, 0, SCREEN_W, SCREEN_H);
			glScissor(0, 0, SCREEN_W, SCREEN_H);
			glClear(GL_COLOR_BUFFER_BIT);
			if (has_movie) {
				// Forcing landscape mode when playing videos
				int8_t *is_landscape = (int8_t *)(*systemData + 34580);
				*is_landscape = 0;
			
				int w, h;
				GLuint vid_tex = video_get_frame(&w, &h);
				if (vid_tex != 0xDEADBEEF) {
					glBindTexture(GL_TEXTURE_2D, vid_tex);
					setup_2d_draw(&bg_attributes[22], 0.0f, 0.0f, SCREEN_W, SCREEN_H);
					vglDrawObjects(GL_TRIANGLE_STRIP, 4, GL_TRUE);
				}
			}
			Java_com_Level5_LT1R_MainActivity_render(fake_env, NULL, delta / 16667, 0, touch.reportNum > 2 ? 2 : touch.reportNum,
				touch.report[0].x / 2, touch.report[0].y / 2,
				touch.report[1].x / 2, touch.report[1].y / 2);
		} else {
			glBindFramebuffer(GL_FRAMEBUFFER, main_fb);
			glViewport(0, 0, SCREEN_H, SCREEN_W);
			glScissor(0, 0, SCREEN_H, SCREEN_W);
			glClear(GL_COLOR_BUFFER_BIT);
			Java_com_Level5_LT1R_MainActivity_render(fake_env, NULL, delta / 16667, 0, touch.reportNum > 2 ? 2 : touch.reportNum,
				SCREEN_H - touch.report[0].y / 2, touch.report[0].x / 2,
				SCREEN_H - touch.report[1].y / 2, touch.report[1].x / 2);
			glBindFramebuffer(GL_FRAMEBUFFER, 0);
			glViewport(0, 0, SCREEN_W, SCREEN_H);
			glScissor(0, 0, SCREEN_W, SCREEN_H);
			glClear(GL_COLOR_BUFFER_BIT);
			if (has_movie) {
				// Forcing landscape mode when playing videos
				int8_t *is_landscape = (int8_t *)(*systemData + 34580);
				*is_landscape = 1;
			
				int w, h;
				GLuint vid_tex = video_get_frame(&w, &h);
				if (vid_tex != 0xDEADBEEF) {
					glBindTexture(GL_TEXTURE_2D, vid_tex);
					setup_2d_draw(&bg_attributes[22], 0.0f, 0.0f, SCREEN_W, SCREEN_H);
					vglDrawObjects(GL_TRIANGLE_STRIP, 4, GL_TRUE);
				}
			}
			glBindTexture(GL_TEXTURE_2D, main_tex);
			setup_2d_draw_rotated(bg_attributes, 0.0f, 0.0f, SCREEN_W, SCREEN_H);
			vglDrawObjects(GL_TRIANGLE_STRIP, 4, GL_TRUE);
		}
		vglSwapBuffers(has_edit_text);
		
		if (close_movie) {
			video_close();
			close_movie = 0;
		}
	}

	return NULL;
}

int main(int argc, char *argv[]) {
	pthread_t t;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, 0x400000);
	pthread_create(&t, &attr, real_main, NULL);
	pthread_join(t, NULL);
	
	return 0;
}
