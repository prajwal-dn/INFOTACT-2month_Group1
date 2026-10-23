#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define CAN_IFACE "vcan0"

static volatile sig_atomic_t stop_requested = 0;

static void handle_signal(int sig)
{
    (void)sig;
    stop_requested = 1;
}

static int open_can_socket(void)
{
    unsigned int index = if_nametoindex(CAN_IFACE);

    if (index == 0) {
        fprintf(stderr,
                "Interface %s not found. Start the virtual CAN interface first.\n",
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

static void make_flags(canid_t can_id, char *out, size_t out_size)
{
    out[0] = '\0';

    if (can_id & CAN_RTR_FLAG)
        strncat(out, "RTR|", out_size - strlen(out) - 1);

    if (can_id & CAN_ERR_FLAG)
        strncat(out, "ERR|", out_size - strlen(out) - 1);

    size_t n = strlen(out);
    if (n > 0) {
        out[n - 1] = '\0'; /* Remove final | */
    } else {
        snprintf(out, out_size, "none");
    }
}

static void print_frame(const struct can_frame *frame)
{
    struct timespec ts;
    struct tm utc;
    char time_text[32];
    char flags[16];
    char payload[CAN_MAX_DLEN * 2 + 1];

    if (clock_gettime(CLOCK_REALTIME, &ts) < 0) {
        perror("clock_gettime");
        return;
    }

    if (gmtime_r(&ts.tv_sec, &utc) == NULL) {
        fprintf(stderr, "Failed to convert timestamp to UTC.\n");
        return;
    }

    if (strftime(time_text, sizeof(time_text),
                 "%Y-%m-%dT%H:%M:%S", &utc) == 0) {
        fprintf(stderr, "Failed to format timestamp.\n");
        return;
    }

    canid_t id;
    const char *frame_format;

    if (frame->can_id & CAN_ERR_FLAG) {
        id = frame->can_id & CAN_ERR_MASK;
        frame_format = "error";
    } else if (frame->can_id & CAN_EFF_FLAG) {
        id = frame->can_id & CAN_EFF_MASK;
        frame_format = "extended";
    } else {
        id = frame->can_id & CAN_SFF_MASK;
        frame_format = "standard";
    }

    make_flags(frame->can_id, flags, sizeof(flags));

    if (frame->can_id & CAN_RTR_FLAG) {
        payload[0] = '\0';
    } else {
        for (uint8_t i = 0; i < frame->can_dlc; i++) {
            snprintf(&payload[i * 2], sizeof(payload) - i * 2,
                     "%02X", (unsigned)frame->data[i]);
        }
        payload[frame->can_dlc * 2] = '\0';
    }

    printf("\"%s.%09ldZ\",%s,0x%X,%s,%s,%u,%s\n",
           time_text, ts.tv_nsec, CAN_IFACE, (unsigned)id,
           frame_format, flags, (unsigned)frame->can_dlc, payload);

    fflush(stdout);
}

int main(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGINT, &sa, NULL) < 0 ||
        sigaction(SIGTERM, &sa, NULL) < 0) {
        perror("sigaction");
        return 1;
    }

    int sock = open_can_socket();
    if (sock < 0)
        return 1;

    fprintf(stderr, "CAN-Sentinel sniffer listening on %s (virtual interface only).\n",
            CAN_IFACE);
    fprintf(stderr, "Press Ctrl+C to stop capture.\n");

    puts("timestamp_utc,interface,can_id,frame_format,flags,dlc,payload");
    fflush(stdout);

    unsigned long captured = 0;

    while (!stop_requested) {
        struct can_frame frame;
        ssize_t n = recv(sock, &frame, sizeof(frame), 0);

        if (n < 0) {
            if (errno == EINTR && stop_requested)
                break;

            if (errno == EINTR)
                continue;

            perror("recv");
            close(sock);
            return 1;
        }

        if (n != (ssize_t)sizeof(frame)) {
            fprintf(stderr, "Warning: received incomplete CAN frame (%zd bytes).\n",
                    n);
            continue;
        }

        if (frame.can_dlc > CAN_MAX_DLEN) {
            fprintf(stderr, "Warning: invalid CAN DLC: %u\n",
                    (unsigned)frame.can_dlc);
            continue;
        }

        print_frame(&frame);
        captured++;
    }

    close(sock);
    fprintf(stderr, "\nCapture stopped. Frames captured: %lu\n", captured);

    return 0;
}
