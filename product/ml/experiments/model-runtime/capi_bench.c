/*
 * LightGBM's C API on one flow at a time: load classifier.txt, then score
 * each row of a file of doubles with LGBM_BoosterPredictForMatSingleRowFast
 * (raw scores). Prints the time per flow, the memory before and after
 * loading, and writes the scores so measure.py can compare them.
 *
 * The declarations below are copied from LightGBM v4.7.0's
 * include/LightGBM/c_api.h, so no header is needed:
 * build with  cc -O2 capi_bench.c -o capi_bench -L<lib dir> -l_lightgbm
 * run with    ./capi_bench classifier.txt rows.f64 <columns> <classes> scores.f64
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef void *BoosterHandle;
typedef void *FastConfigHandle;
#define C_API_DTYPE_FLOAT64 (1)
#define C_API_PREDICT_RAW_SCORE (1)
int LGBM_BoosterCreateFromModelfile(const char *filename, int *out_num_iterations,
                                    BoosterHandle *out);
int LGBM_BoosterPredictForMatSingleRowFastInit(BoosterHandle handle, const int predict_type,
                                               const int start_iteration, const int num_iteration,
                                               const int data_type, const int32_t ncol,
                                               const char *parameter,
                                               FastConfigHandle *out_fastConfig);
int LGBM_BoosterPredictForMatSingleRowFast(FastConfigHandle fastConfig_handle, const void *data,
                                           int64_t *out_len, double *out_result);
int LGBM_FastConfigFree(FastConfigHandle fastConfig);
int LGBM_BoosterFree(BoosterHandle handle);
const char *LGBM_GetLastError(void);

static long rss_kb(void) {
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    long kb = -1;
    while (f && fgets(line, sizeof line, f))
        if (strncmp(line, "VmRSS:", 6) == 0) kb = strtol(line + 6, NULL, 10);
    if (f) fclose(f);
    return kb;
}

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

int main(int argc, char **argv) {
    if (argc != 6) {
        fprintf(stderr, "usage: %s model rows.f64 columns classes scores.f64\n", argv[0]);
        return 2;
    }
    int columns = atoi(argv[3]), classes = atoi(argv[4]), iterations = 0;
    FILE *in = fopen(argv[2], "rb");
    if (!in) return 2;
    fseek(in, 0, SEEK_END);
    long rows = ftell(in) / (long)(sizeof(double) * columns);
    rewind(in);
    double *data = malloc(sizeof(double) * columns * rows);
    double *scores = malloc(sizeof(double) * classes * rows);
    if (fread(data, sizeof(double), (size_t)columns * rows, in) != (size_t)columns * rows) return 2;
    fclose(in);

    long before = rss_kb();
    double t0 = now();
    BoosterHandle booster;
    FastConfigHandle fast;
    if (LGBM_BoosterCreateFromModelfile(argv[1], &iterations, &booster) != 0 ||
        LGBM_BoosterPredictForMatSingleRowFastInit(booster, C_API_PREDICT_RAW_SCORE, 0, -1,
                                                   C_API_DTYPE_FLOAT64, columns, "num_threads=1",
                                                   &fast) != 0) {
        fprintf(stderr, "LightGBM: %s\n", LGBM_GetLastError());
        return 1;
    }
    double loaded = now() - t0;
    long after = rss_kb();

    double t1 = now();
    for (long r = 0; r < rows; r++) {
        int64_t len = 0;
        if (LGBM_BoosterPredictForMatSingleRowFast(fast, data + r * columns, &len,
                                                   scores + r * classes) != 0) {
            fprintf(stderr, "LightGBM: %s\n", LGBM_GetLastError());
            return 1;
        }
    }
    double per_row = (now() - t1) / rows;

    FILE *out = fopen(argv[5], "wb");
    fwrite(scores, sizeof(double), (size_t)classes * rows, out);
    fclose(out);
    printf("{\"rows\": %ld, \"iterations\": %d, \"load_seconds\": %.6f, "
           "\"microseconds_per_flow\": %.3f, \"rss_kb_before_load\": %ld, "
           "\"rss_kb_after_load\": %ld}\n",
           rows, iterations, loaded, per_row * 1e6, before, after);
    LGBM_FastConfigFree(fast);
    LGBM_BoosterFree(booster);
    return 0;
}
