/*
 * The generated code (flagman_model.c, from codegen.py) on one flow at a
 * time: prints the time per flow and the memory, and writes the scores so
 * measure.py can compare them with LightGBM's.
 * build: cc -O2 codegen_bench.c flagman_model.c -o codegen_bench -lm
 * run:   ./codegen_bench rows.f64 <columns> <classes> scores.f64
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void flagman_raw_scores(const double *x, double *out);

static long rss_kb(void) {
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    long kb = -1;
    while (f && fgets(line, sizeof line, f))
        if (strncmp(line, "VmRSS:", 6) == 0) kb = strtol(line + 6, NULL, 10);
    if (f) fclose(f);
    return kb;
}

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: %s rows.f64 columns classes scores.f64\n", argv[0]);
        return 2;
    }
    int columns = atoi(argv[2]), classes = atoi(argv[3]);
    FILE *in = fopen(argv[1], "rb");
    if (!in) return 2;
    fseek(in, 0, SEEK_END);
    long rows = ftell(in) / (long)(sizeof(double) * columns);
    rewind(in);
    double *data = malloc(sizeof(double) * columns * rows);
    double *scores = malloc(sizeof(double) * classes * rows);
    if (fread(data, sizeof(double), (size_t)columns * rows, in) != (size_t)columns * rows) return 2;
    fclose(in);
    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    for (long r = 0; r < rows; r++) flagman_raw_scores(data + r * columns, scores + r * classes);
    clock_gettime(CLOCK_MONOTONIC, &b);
    double seconds = (b.tv_sec - a.tv_sec) + (b.tv_nsec - a.tv_nsec) / 1e9;
    FILE *out = fopen(argv[4], "wb");
    fwrite(scores, sizeof(double), (size_t)classes * rows, out);
    fclose(out);
    printf("{\"rows\": %ld, \"microseconds_per_flow\": %.3f, \"rss_kb\": %ld}\n", rows,
           seconds / rows * 1e6, rss_kb());
    return 0;
}
