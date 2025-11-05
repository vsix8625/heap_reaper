#include "heap_reaper.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct reaper_alloc_info
{
    void *ptr;
    size_t size;
    const char *tag;
    const char *file;
    int32_t line;
} reaper_alloc_info;

struct reaper_ctx
{
    reaper_alloc_info *items;
    size_t count;
    size_t capacity;
    const char *name;

    pthread_mutex_t lock;  // reaper_mutex in future
    bool thread_safe;

    size_t total_bytes;
    size_t peak_bytes;
};

//----------------
// Helpers
//----------------

static void reaper_mutex_lock(reaper_ctx *ctx)
{
    if (ctx->thread_safe)
    {
        pthread_mutex_lock(&ctx->lock);
    }
}

static void reaper_mutex_unlock(reaper_ctx *ctx)
{
    if (ctx->thread_safe)
    {
        pthread_mutex_unlock(&ctx->lock);
    }
}

static bool reaper_grow(reaper_ctx *ctx)
{
    size_t new_capacity = ctx->capacity ? ctx->capacity * 2 : 256;
    reaper_alloc_info *new_items = realloc(ctx->items, new_capacity * sizeof(reaper_alloc_info));
    if (new_items == NULL)
    {
        return false;
    }

    ctx->items = new_items;
    ctx->capacity = new_capacity;
    return true;
}

static void reaper_track_allocation_ctx(reaper_ctx *ctx, void *ptr, size_t size, const char *tag, const char *file,
                                        int32_t line)
{
    if (ptr == NULL)
    {
        return;
    }

    reaper_mutex_lock(ctx);

    if (ctx->count >= ctx->capacity)
    {
        if (!reaper_grow(ctx))
        {
            reaper_mutex_unlock(ctx);
            return;
        }
    }

    ctx->items[ctx->count++] = (reaper_alloc_info) {.ptr = ptr, .size = size, .tag = tag, .file = file, .line = line};
    ctx->total_bytes += size;
    if (ctx->total_bytes > ctx->peak_bytes)
    {
        ctx->peak_bytes = ctx->total_bytes;
    }

    reaper_mutex_unlock(ctx);
}

static void reaper_untrack_ctx(reaper_ctx *ctx, void *ptr)
{
    if (ctx == NULL || ptr == NULL)
    {
        return;
    }

    reaper_mutex_lock(ctx);

    for (size_t i = ctx->count; i-- > 0;)
    {
        if (ctx->items[i].ptr == ptr)
        {
            ctx->total_bytes -= ctx->items[i].size;
            ctx->items[i] = ctx->items[--ctx->count];  // keep list in order
            break;
        }
    }

    reaper_mutex_unlock(ctx);
}

//----------------
// Context management
//----------------

bool reaper_ctx_init(reaper_ctx *ctx, const char *name, bool thread_safe)
{
    if (ctx == NULL)
    {
        return false;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->name = name != NULL ? name : "reaper_creeper";
    ctx->thread_safe = thread_safe;
    if (thread_safe && pthread_mutex_init(&ctx->lock, NULL) != 0)
    {
        return false;
    }
    return true;
}

void reaper_ctx_destroy(reaper_ctx *ctx)
{
    if (ctx == NULL)
    {
        return;
    }

    reaper_collect_all(ctx);
    free(ctx->items);
    ctx->items = NULL;
    ctx->count = 0;
    ctx->capacity = 0;

    if (ctx->thread_safe)
    {
        pthread_mutex_destroy(&ctx->lock);
    }
}

//----------------
// GLOBAL context
//----------------

static reaper_ctx g_reaper_global_ctx;

bool reaper_init(void)
{
    return reaper_ctx_init(&g_reaper_global_ctx, "global", true);
}

void reaper_shutdown(void)
{
    reaper_ctx_destroy(&g_reaper_global_ctx);
}

void reaper_destroy_tag(const char *tag)
{
    if (tag == NULL)
    {
        return;
    }

    reaper_mutex_lock(&g_reaper_global_ctx);

    for (size_t i = 0; i < g_reaper_global_ctx.count;)
    {
        reaper_alloc_info *info = &g_reaper_global_ctx.items[i];
        if (info->tag && strcmp(info->tag, tag) == 0)
        {
            free(info->ptr);
            g_reaper_global_ctx.total_bytes -= info->size;
            g_reaper_global_ctx.items[i] = g_reaper_global_ctx.items[--g_reaper_global_ctx.count];
            continue;
        }
        i++;
    }

    reaper_mutex_unlock(&g_reaper_global_ctx);
}

// -------------------------
// Allocation helpers
// -------------------------

void *reaper_malloc_ctx(reaper_ctx *ctx, size_t size, const char *tag)
{
    if (ctx == NULL)
    {
        return NULL;
    }

    if (size == 0)
    {
        size = 1;
    }

    void *p = malloc(size);

    if (p == NULL)
    {
        fprintf(stderr, "%s: failed to malloc %zu bytes", __func__, size);
        return NULL;
    }
    reaper_track_allocation_ctx(ctx, p, size, tag, NULL, 0);
    return p;
}

void *reaper_calloc_ctx(reaper_ctx *ctx, size_t n, size_t size, const char *tag)
{
    if (size == 0)
    {
        size = 1;
    }
    if (n == 0)
    {
        n = 1;
    }

    void *p = calloc(n, size);

    if (p == NULL)
    {
        fprintf(stderr, "%s: failed to calloc %zu bytes", __func__, n * size);
        return NULL;
    }

    reaper_track_allocation_ctx(ctx, p, n * size, tag, NULL, 0);
    return p;
}

void *reaper_realloc_ctx(reaper_ctx *ctx, void *ptr, size_t size)
{
    if (size == 0)
    {
        size = 1;
    }
    void *new_ptr = malloc(size);

    if (new_ptr == NULL)
    {
        fprintf(stderr, "%s: failed to malloc %zu bytes", __func__, size);
        return NULL;
    }

    if (ptr)
    {
        reaper_mutex_lock(ctx);
        size_t old_size = 0;
        for (size_t i = ctx->count; i-- > 0;)
        {
            if (ctx->items[i].ptr == ptr)
            {
                old_size = ctx->items[i].size;
                break;
            }
        }
        reaper_mutex_unlock(ctx);

        memcpy(new_ptr, ptr, old_size < size ? old_size : size);
        reaper_free_ctx(ctx, ptr);
    }
    reaper_track_allocation_ctx(ctx, new_ptr, size, NULL, NULL, 0);
    return new_ptr;
}

void reaper_free_ctx(reaper_ctx *ctx, void *ptr)
{
    if (ptr == NULL)
    {
        return;
    }
    reaper_untrack_ctx(ctx, ptr);
    free(ptr);
}

char *reaper_strdup_ctx(reaper_ctx *ctx, const char *s, const char *tag)
{
    if (s == NULL)
    {
        return NULL;
    }
    size_t len = strlen(s) + 1;
    char *copy = reaper_malloc_ctx(ctx, len, tag);
    memcpy(copy, s, len);
    return copy;
}

// -------------------------
// Global alloc macros
// -------------------------
void *reaper_malloc(size_t size, const char *tag)
{
    return reaper_malloc_ctx(&g_reaper_global_ctx, size, tag);
}

void *reaper_calloc(size_t n, size_t size, const char *tag)
{
    return reaper_calloc_ctx(&g_reaper_global_ctx, n, size, tag);
}

void *reaper_realloc(void *ptr, size_t size)
{
    return reaper_realloc_ctx(&g_reaper_global_ctx, ptr, size);
}

void reaper_free(void *ptr)
{
    reaper_free_ctx(&g_reaper_global_ctx, ptr);
}

char *reaper_strdup(const char *s, const char *tag)
{
    return reaper_strdup_ctx(&g_reaper_global_ctx, s, tag);
}

// -------------------------
// Collection
// -------------------------
void reaper_collect_all(reaper_ctx *ctx)
{
    if (ctx == NULL || ctx->items == NULL)
    {
        return;
    }
    reaper_mutex_lock(ctx);

    for (size_t i = ctx->count; i-- > 0;)
    {
        if (ctx->items[i].ptr)
        {
            free(ctx->items[i].ptr);
        }
    }
    ctx->count = 0;
    ctx->total_bytes = 0;

    reaper_mutex_unlock(ctx);
}

void reaper_collect_tag_ctx(reaper_ctx *ctx, const char *tag)
{
    if (tag == NULL || ctx->items == NULL)
    {
        return;
    }
    reaper_mutex_lock(ctx);

    for (size_t i = 0; i < ctx->count;)
    {
        reaper_alloc_info *info = &ctx->items[i];
        if (info->tag && strcmp(info->tag, tag) == 0)
        {
            if (info->ptr)
            {
                free(info->ptr);
            }
            ctx->total_bytes -= info->size;
            ctx->items[i] = ctx->items[--ctx->count];
            continue;
        }
        i++;
    }

    reaper_mutex_unlock(ctx);
}

// -------------------------
// Debug / Stats
// -------------------------

void reaper_dump_glob(void)
{
    for (size_t i = 0; i < g_reaper_global_ctx.count; ++i)
    {
        const reaper_alloc_info *info = &g_reaper_global_ctx.items[i];
        printf("[%zu] %p (%zu bytes) tag=%s\n", i, info->ptr, info->size, info->tag ? info->tag : "N/A");
    }
}

void reaper_dump_ctx(const reaper_ctx *ctx)
{
    if (ctx == NULL)
    {
        return;
    }

    for (size_t i = 0; i < ctx->count; ++i)
    {
        const reaper_alloc_info *info = &ctx->items[i];
        printf("[%zu] %p (%zu bytes) tag=%s\n", i, info->ptr, info->size, info->tag ? info->tag : "N/A");
    }
}
