#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <vsi.h>

static void print_usage(char* prg)
{
    fprintf(stderr, "\nUsage: %s [options] <vsi>\n\n", prg);
    fprintf(stderr, "Options: -h         (show this help page)\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "vsi-client vss_rel_1.0.vsi\n");
    fprintf(stderr, "\n");
    exit(-EXIT_FAILURE);
}

static char sigData[16];

int main(int argc, char** argv)
{
    char* vssName = NULL;
    int opt;
    vsi_handle vsiHandle;
    int status = 0;
    vsi_result result = {.domainId = 0, .data = sigData, .dataLength = 16 };

    while ((opt = getopt(argc, argv, "?h")) != -1) {
        switch (opt) {
        case 'h':
        case '?':
        default:
            print_usage(argv[0]);
            break;
        }
    }

    /* Parse vss filename and can interface name */
    vssName = argv[optind];
    if (NULL == vssName)
        print_usage(argv[0]);

    vsiHandle = vsi_initialize_file(false, vssName);
    if (!vsiHandle) {
        printf("Failed to initialize the VSI system!\n");
        return -EXIT_FAILURE;
    }

    result.signalId = 9;
    status = vsi_get_newest_signal(vsiHandle, &result);

    if (status) {
        printf("Failed to read signal\n");
    } else {
        printf("%s(%lu): %hhu\n", result.name, result.signalId, *(uint8_t*)result.data);
    }

    return EXIT_SUCCESS;
}
