#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <limits.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define CAN_IFACE "vcan0"
#define SOCKET_PATH "/tmp/can_sentinel.sock"

static volatile sig_atomic_t stop_requested = 0;

struct frame_fields {
    char timestamp[48];
    char frame_format[12];
    char flags[16];
    char payload[CAN_MAX_DLEN * 2 + 1];
    unsigned int can_id;
};

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
        perror("CAN socket");
        return -1;
    }

    struct sockaddr_can addr;
    memset(&addr, 0, sizeof(addr));
    addr.can_family = AF_CAN;
    addr.can_ifindex = (int)index;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("CAN bind");
        close(sock);
        return -1;
    }

    return sock;
}

static int open_unix_socket(void)
{
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Unix socket");
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;

    if (strlen(SOCKET_PATH) >= sizeof(addr.sun_path)) {
        fprintf(stderr, "Unix socket path is too long.\n");
        close(sock);
        return -1;
    }

    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", SOCKET_PATH);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Connect to Python receiver");
        fprintf(stderr, "Start the Python receiver before the sniffer.\n");
        close(sock);
        return -1;
    }

    return sock;
}

static int send_all(int sock, const char *data, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        ssize_t n = send(sock, data + sent, length - sent, MSG_NOSIGNAL);

        if (n < 0) {
            if (errno == EINTR)
                continue;

            perror("Unix socket send");
            return -1;
        }

        if (n == 0) {
            fprintf(stderr, "Python receiver closed the socket.\n");
            return -1;
        }

        sent += (size_t)n;
    }

    return 0;
}

static void make_flags(canid_t can_id, char *out, size_t out_size)
{
    out[0] = '\0';

    if (can_id & CAN_RTR_FLAG)
        strncat(out, "RTR|", out_size - strlen(out) - 1);

    if (can_id & CAN_ERR_FLAG)
        strncat(out, "ERR|", out_size - strlen(out) - 1);

    size_t n = strlen(out);

    if (n > 0)
        out[n - 1] = '\0';
    else
        snprintf(out, out_size, "none");
}

static int extract_frame_fields(
    const struct can_frame *frame,
    struct frame_fields *fields)
{
    struct timespec ts;
    struct tm utc;
    char time_text[32];

    if (clock_gettime(CLOCK_REALTIME, &ts) < 0) {
        perror("clock_gettime");
        return -1;
    }

    if (gmtime_r(&ts.tv_sec, &utc) == NULL) {
        fprintf(stderr, "Failed to convert timestamp to UTC.\n");
        return -1;
    }

    if (strftime(time_text, sizeof(time_text),
                 "%Y-%m-%dT%H:%M:%S", &utc) == 0) {
        fprintf(stderr, "Failed to format timestamp.\n");
        return -1;
    }

    snprintf(fields->timestamp, sizeof(fields->timestamp),
             "%s.%09ldZ", time_text, ts.tv_nsec);

    canid_t id;

    if (frame->can_id & CAN_ERR_FLAG) {
        id = frame->can_id & CAN_ERR_MASK;
        snprintf(fields->frame_format, sizeof(fields->frame_format), "error");
    } else if (frame->can_id & CAN_EFF_FLAG) {
        id = frame->can_id & CAN_EFF_MASK;
        snprintf(fields->frame_format, sizeof(fields->frame_format), "extended");
    } else {
        id = frame->can_id & CAN_SFF_MASK;
        snprintf(fields->frame_format, sizeof(fields->frame_format), "standard");
    }

    fields->can_id = (unsigned int)id;
    make_flags(frame->can_id, fields->flags, sizeof(fields->flags));

    if (frame->can_id & CAN_RTR_FLAG) {
        fields->payload[0] = '\0';
    } else {
        for (uint8_t i = 0; i < frame->can_dlc; i++) {
            snprintf(&fields->payload[i * 2],
                     sizeof(fields->payload) - i * 2,
                     "%02X", (unsigned int)frame->data[i]);
        }

        fields->payload[frame->can_dlc * 2] = '\0';
    }

    return 0;
}

static void print_csv_frame(const struct frame_fields *fields,
                            const struct can_frame *frame)
{
    printf("\"%s\",%s,0x%X,%s,%s,%u,%s\n",
           fields->timestamp,
           CAN_IFACE,
           fields->can_id,
           fields->frame_format,
           fields->flags,
           (unsigned int)frame->can_dlc,
           fields->payload);

    fflush(stdout);
}

static int send_json_frame(int sock,
                           const struct frame_fields *fields,
                           const struct can_frame *frame)
{
    char json[512];

    int length = snprintf(
        json,
        sizeof(json),
        "{\"schema_version\":1,"
        "\"event_type\":\"can_frame\","
        "\"timestamp_utc\":\"%s\","
        "\"interface\":\"%s\","
        "\"can_id\":\"0x%X\","
        "\"frame_format\":\"%s\","
        "\"flags\":\"none\","
        "\"dlc\":%u,"
        "\"payload\":\"%s\"}\n",
        fields->timestamp,
        CAN_IFACE,
        fields->can_id,
        fields->frame_format,
        (unsigned int)frame->can_dlc,
        fields->payload
    );

    if (length < 0 || (size_t)length >= sizeof(json)) {
        fprintf(stderr, "Failed to format JSON event.\n");
        return -1;
    }

    return send_all(sock, json, (size_t)length);
}

static void usage(const char *program)
{
    fprintf(stderr,
            "Usage: %s [--socket] [--count N]\n"
            "  Default: CSV output to stdout\n"
            "  --socket: Send version 1 JSON events to the Python receiver\n"
            "  --count N: Stop after N accepted frames (optional)\n",
            program);
}

int main(int argc, char *argv[])
{
    int socket_mode = 0;
    unsigned long max_frames = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--socket") == 0) {
            socket_mode = 1;
        } else if (strcmp(argv[i], "--count") == 0) {
            if (i + 1 >= argc) {
                usage(argv[0]);
                return EXIT_FAILURE;
            }

            char *end = NULL;
            errno = 0;
            unsigned long parsed = strtoul(argv[++i], &end, 10);

            if (errno != 0 || end == argv[i] || *end != '\0' ||
                parsed == 0 || parsed == ULONG_MAX) {
                fprintf(stderr, "--count must be a positive integer.\n");
                return EXIT_FAILURE;
            }

            max_frames = parsed;
        } else {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
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

    int can_sock = open_can_socket();
    if (can_sock < 0)
        return EXIT_FAILURE;

    int ipc_sock = -1;

    if (socket_mode) {
        ipc_sock = open_unix_socket();

        if (ipc_sock < 0) {
            close(can_sock);
            return EXIT_FAILURE;
        }

        fprintf(stderr,
                "CAN-Sentinel sniffer connected to Python receiver at %s.\n",
                SOCKET_PATH);
        fprintf(stderr, "Sending JSON events from %s. Press Ctrl+C to stop.\n",
                CAN_IFACE);
    } else {
        fprintf(stderr,
                "CAN-Sentinel sniffer listening on %s (virtual interface only).\n",
                CAN_IFACE);
        fprintf(stderr, "Press Ctrl+C to stop capture.\n");
        puts("timestamp_utc,interface,can_id,frame_format,flags,dlc,payload");
        fflush(stdout);
    }

    unsigned long captured = 0;
    unsigned long skipped = 0;
    int exit_code = EXIT_SUCCESS;

    while (!stop_requested) {
        struct can_frame frame;
        ssize_t n = recv(can_sock, &frame, sizeof(frame), 0);

        if (n < 0) {
            if (errno == EINTR && stop_requested)
                break;

            if (errno == EINTR)
                continue;

            perror("CAN recv");
            exit_code = EXIT_FAILURE;
            break;
        }

        if (n != (ssize_t)sizeof(frame)) {
            fprintf(stderr,
                    "Warning: received incomplete CAN frame (%zd bytes).\n", n);
            continue;
        }

        if (frame.can_dlc > CAN_MAX_DLEN) {
            fprintf(stderr, "Warning: invalid CAN DLC: %u\n",
                    (unsigned int)frame.can_dlc);
            continue;
        }

        /*
         * Contract version 1 supports standard and extended data frames
         * with flags=none. Skip RTR and error frames in socket mode.
         */
        if (socket_mode &&
            (frame.can_id & (CAN_RTR_FLAG | CAN_ERR_FLAG))) {
            skipped++;
            continue;
        }

        struct frame_fields fields;

        if (extract_frame_fields(&frame, &fields) < 0) {
            exit_code = EXIT_FAILURE;
            break;
        }

        if (socket_mode) {
            if (send_json_frame(ipc_sock, &fields, &frame) < 0) {
                exit_code = EXIT_FAILURE;
                break;
            }
        } else {
            print_csv_frame(&fields, &frame);
        }

        captured++;

        if (max_frames > 0 && captured >= max_frames)
            break;
    }

    close(can_sock);

    if (ipc_sock >= 0)
        close(ipc_sock);

    fprintf(stderr,
            "\nSniffer stopped. Frames processed: %lu; unsupported frames skipped: %lu\n",
            captured, skipped);

    return exit_code;
}
