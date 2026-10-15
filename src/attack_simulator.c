#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define CAN_IFACE "vcan0"

static volatile sig_atomic_t running = 1;

static void handle_signal(int sig)
{
    (void)sig;
    running = 0;
}

static int64_t monotonic_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
        return -1;

    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static int open_can_socket(void)
{
    unsigned int index = if_nametoindex(CAN_IFACE);

    if (index == 0) {
        fprintf(stderr, "%s interface is unavailable. Start vcan0 first.\n",
                CAN_IFACE);
        return -1;
    }

    int sock = socket(PF_CAN, SOCK_RAW, CAN_RAW);

    if (sock < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_can addr;
    memset(&addr, 0, sizeof(addr));
    addr.can_family = AF_CAN;
    addr.can_ifindex = (int)index;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }

    return sock;
}

int main(int argc, char *argv[])
{
    int mode = 1;

    if (argc > 2) {
        fprintf(stderr, "Usage: %s [1|2]\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (argc == 2) {
        char *end = NULL;
        errno = 0;
        long parsed = strtol(argv[1], &end, 10);

        if (errno || end == argv[1] || *end != '\0' ||
            (parsed != 1 && parsed != 2)) {
            fprintf(stderr, "Mode must be 1 (high frequency) or 2 (spoofed ID).\n");
            return EXIT_FAILURE;
        }

        mode = (int)parsed;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGINT, &sa, NULL) < 0 ||
        sigaction(SIGTERM, &sa, NULL) < 0) {
        perror("sigaction");
        return EXIT_FAILURE;
    }

    int sock = open_can_socket();

    if (sock < 0)
        return EXIT_FAILURE;

    struct can_frame frame;
    memset(&frame, 0, sizeof(frame));
    frame.can_dlc = 2;

    long delay_ns;

    if (mode == 1) {
        frame.can_id = 0x100;
        frame.data[0] = 0xFF;
        frame.data[1] = 0xFF;
        delay_ns = 1000000L;       /* target interval: 1 ms */

        printf("Attack simulator: HIGH-FREQUENCY mode\n");
        printf("CAN ID: 0x100, payload: FF FF, target interval: 1 ms\n");
    } else {
        /* 0x999 is above the 11-bit standard-ID limit, so use EFF. */
        frame.can_id = CAN_EFF_FLAG | 0x999;
        frame.data[0] = 0xDE;
        frame.data[1] = 0xAD;
        delay_ns = 50000000L;      /* target interval: 50 ms */

        printf("Attack simulator: UNEXPECTED EXTENDED-ID mode\n");
        printf("CAN ID: 0x999 (extended), payload: DE AD, target interval: 50 ms\n");
    }

    printf("Interface: %s (virtual only). Press Ctrl+C to stop.\n\n",
           CAN_IFACE);
    fflush(stdout);

    unsigned long sent = 0;
    unsigned long errors = 0;
    int exit_code = EXIT_SUCCESS;

    int64_t next_report = monotonic_ns() + 1000000000LL;
    struct timespec delay = {
        .tv_sec = delay_ns / 1000000000L,
        .tv_nsec = delay_ns % 1000000000L
    };

    while (running) {
        ssize_t n = write(sock, &frame, sizeof(frame));

        if (n == (ssize_t)sizeof(frame)) {
            sent++;
        } else {
            errors++;
            if (n < 0)
                perror("CAN frame write");
            else
                fprintf(stderr, "Incomplete CAN frame write.\n");

            exit_code = EXIT_FAILURE;
            break;
        }

        int64_t now = monotonic_ns();

        if (now < 0) {
            perror("clock_gettime");
            exit_code = EXIT_FAILURE;
            break;
        }

        if (now >= next_report) {
            printf("Frames sent: %lu | write errors: %lu\n", sent, errors);
            fflush(stdout);
            next_report = now + 1000000000LL;
        }

        struct timespec remaining = delay;

        while (running && nanosleep(&remaining, &remaining) < 0) {
            if (errno == EINTR)
                continue;

            perror("nanosleep");
            exit_code = EXIT_FAILURE;
            running = 0;
        }
    }

    printf("\nAttack simulation stopped.\n");
    printf("Frames sent: %lu | write errors: %lu\n", sent, errors);

    if (close(sock) < 0) {
        perror("close");
        exit_code = EXIT_FAILURE;
    }

    return exit_code;
}
