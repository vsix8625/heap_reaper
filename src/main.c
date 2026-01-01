#include "heap_reaper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ALLOC_COUNT 200
#define TAG_COUNT 5

static const char *tags[TAG_COUNT] = {"rendering", "physics", "audio", "ui", "global"};

/*
 * Each allocation record tracks:
 *  - ptr: the allocated memory
 *  - size: size of allocation
 *  - tag: string label
 *  - is_ctx: true if allocation came from a specific reaper_ctx, false if global
 *
 * The is_ctx flag is **essential for the test** because without it we can't safely free
 * allocations — some tags like "global" can exist in both a ctx and the global allocator.
 */
typedef struct
{
    void *ptr;
    size_t size;
    const char *tag;
    bool is_ctx;  // needed to safely know where to free
} alloc_record;

int main(void)
{
    srand((unsigned) time(NULL));

    if (!reaper_init())
    {
        fprintf(stderr, "Failed to init global reaper\n");
        return EXIT_FAILURE;
    }

    reaper_ctx *app_ctx = reaper_create_ctx("app_ctx", true);
    if (!app_ctx)
    {
        fprintf(stderr, "Failed to create app_ctx\n");
        reaper_shutdown();
        return EXIT_FAILURE;
    }

    alloc_record *recs = malloc(sizeof(alloc_record) * ALLOC_COUNT);
    if (!recs)
    {
        fprintf(stderr, "Failed to allocate record array\n");
        reaper_destroy_ctx(app_ctx);
        reaper_shutdown();
        return EXIT_FAILURE;
    }
    memset(recs, 0, sizeof(alloc_record) * ALLOC_COUNT);

    printf("Starting scalable stress test with %d allocations...\n", ALLOC_COUNT);

    // Phase 1: random allocations
    for (size_t i = 0; i < ALLOC_COUNT; ++i)
    {
        size_t sz = (rand() % 1024) + 1;  // 1–1024 bytes
        const char *tag = tags[rand() % TAG_COUNT];

        if (rand() % 2)
        {
            recs[i].ptr = reaper_malloc_ctx(app_ctx, sz, tag);
            recs[i].is_ctx = true;
        }
        else
        {
            recs[i].ptr = reaper_malloc(sz);  // goes to global reaper automatically
            recs[i].is_ctx = false;
        }

        recs[i].size = sz;
        recs[i].tag = tag;

        if (!recs[i].ptr)
        {
            fprintf(stderr, "Allocation %zu failed\n", i);
            break;
        }

        memset(recs[i].ptr, 0xA5, sz);  // poison-fill memory
    }

    printf("Phase 1 complete: allocations done\n");

    // Phase 2: random partial frees and reallocs
    for (size_t i = 0; i < ALLOC_COUNT; ++i)
    {
        if (recs[i].ptr == NULL)
            continue;

        int r = rand() % 5;

        if (r == 0)  // free
        {
            if (recs[i].is_ctx)
            {
                reaper_free_ctx(app_ctx, recs[i].ptr);
            }
            else
            {
                reaper_free(recs[i].ptr);
            }

            recs[i].ptr = NULL;
        }
        else if (r == 1)  // realloc
        {
            size_t new_size = recs[i].size + (rand() % 256);
            if (recs[i].is_ctx)
                recs[i].ptr = reaper_realloc_ctx(app_ctx, recs[i].ptr, new_size);
            else
                recs[i].ptr = reaper_realloc(recs[i].ptr, new_size);

            recs[i].size = new_size;
        }
    }

    reaper_print_stats(app_ctx);
    reaper_dump_ctx_file(app_ctx, "ctx_dump.txt");
    printf("Phase 2 complete: partial frees/reallocs done\n");

    // Phase 3: Tag-based cleanup for ctx
    for (int t = 0; t < TAG_COUNT; ++t)
    {
        printf("Destroying ctx tag: %s\n", tags[t]);
        reaper_collect_tag_ctx(app_ctx, tags[t]);
    }
    reaper_print_stats(app_ctx);

    // Phase 4: Context cleanup
    reaper_destroy_ctx(app_ctx);

    // Phase 5: Global cleanup
    reaper_dump_glob_file();
    reaper_print_stats(NULL);
    printf("Shutting down global reaper\n");
    reaper_shutdown();
    reaper_print_stats(NULL);

    free(recs);

    printf("Scalable stress test complete\n");
    return EXIT_SUCCESS;
}
