#define _GNU_SOURCE

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
#define NS_PER_MS 1000000LL
#define NS_PER_SEC 1000000000LL

struct message {
    const char *name;
    canid_t id;
    uint16_t value;
    int64_t period_ns;
    int64_t next_ns;
    unsigned long sent;
    unsigned long skipped;
    unsigned long errors;
};

static struct message messages[] = {
    {"RPM",     0x100, 3000,  100 * NS_PER_MS, 0, 0, 0, 0},
    {"SPEED",   0x101,   60,  100 * NS_PER_MS, 0, 0, 0, 0},
    {"COOLANT", 0x102,   90, 1000 * NS_PER_MS, 0, 0, 0, 0}
};

#define NUM_MESSAGES (sizeof(messages) / sizeof(messages[0]))

static volatile sig_atomic_t stop_requested = 0;

static void handle_signal(int sig)
{
    (void)sig;
    stop_requested = 1;
}

static int64_t now_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime");
        exit(EXIT_FAILURE);
    }

    return (int64_t)ts.tv_sec * NS_PER_SEC + ts.tv_nsec;
}

static int sleep_until_ns(int64_t deadline_ns)
{
    struct timespec deadline = {
        .tv_sec = deadline_ns / NS_PER_SEC,
        .tv_nsec = deadline_ns % NS_PER_SEC
    };

    while (!stop_requested) {
        int rc = clock_nanosleep(
            CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL);

        if (rc == 0)
            return 0;

        if (rc != EINTR) {
            fprintf(stderr, "clock_nanosleep: %s\n", strerror(rc));
            return -1;
        }
    }

    return -1;
}

static int open_can_socket(void)
{
    unsigned int index = if_nametoindex(CAN_IFACE);

    if (index == 0) {
        fprintf(stderr, "Interface %s not found or unavailable.\n",
                CAN_IFACE);
        return -1;
    }

    int sock = socket(PF_CAN, SOCK_RAW, CAN_RAW);

    if (sock < 0) {
        perror("socket");
        return -1;
    }

    /* This sender does not need to receive CAN frames. */
    if (setsockopt(sock, SOL_CAN_RAW, CAN_RAW_FILTER, NULL, 0) < 0) {
        perror("setsockopt");
        close(sock);
        return -1;
    }

    struct sockaddr_can address;
    memset(&address, 0, sizeof(address));
    address.can_family = AF_CAN;
    address.can_ifindex = (int)index;

    if (bind(sock, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }

    return sock;
}

/* 0 = sent, 1 = temporary send failure, -1 = fatal send failure. */
static int send_message(int sock, const struct message *msg)
{
    struct can_frame frame;
    memset(&frame, 0, sizeof(frame));

    frame.can_id = msg->id;
    frame.can_dlc = 2;
    frame.data[0] = (uint8_t)(msg->value >> 8);
    frame.data[1] = (uint8_t)(msg->value & 0xFF);

    ssize_t written = write(sock, &frame, sizeof(frame));

    if (written == (ssize_t)sizeof(frame))
        return 0;

    if (written < 0 &&
        (errno == ENOBUFS || errno == EAGAIN || errno == EINTR)) {
        fprintf(stderr, "Warning: dropped %s frame 0x%03X: %s\n",
                msg->name, (unsigned)msg->id, strerror(errno));
        return 1;
    }

    if (written < 0)
        perror("CAN write");
    else
        fprintf(stderr, "CAN write returned a short frame.\n");

    return -1;
}

int main(void)
{
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = handle_signal;
    sigemptyset(&action.sa_mask);

    if (sigaction(SIGINT, &action, NULL) < 0 ||
        sigaction(SIGTERM, &action, NULL) < 0) {
        perror("sigaction");
        return EXIT_FAILURE;
    }

    int sock = open_can_socket();

    if (sock < 0)
        return EXIT_FAILURE;

    int64_t start = now_ns() + 100 * NS_PER_MS;

    for (size_t i = 0; i < NUM_MESSAGES; i++)
        messages[i].next_ns = start;

    printf("CAN-Sentinel normal traffic generator\n");
    printf("Interface: %s (virtual interface only)\n", CAN_IFACE);
    printf("RPM: 3000 and speed: 60 km/h, target 100 ms\n");
    printf("Coolant: 90 C, target 1000 ms\n");
    printf("Scheduling: CLOCK_MONOTONIC absolute deadlines\n");
    printf("Press Ctrl+C to stop.\n\n");
    fflush(stdout);

    int exit_code = EXIT_SUCCESS;

    while (!stop_requested) {
        int64_t earliest = messages[0].next_ns;

        for (size_t i = 1; i < NUM_MESSAGES; i++) {
            if (messages[i].next_ns < earliest)
                earliest = messages[i].next_ns;
        }

        if (sleep_until_ns(earliest) != 0)
            break;

        for (size_t i = 0; i < NUM_MESSAGES; i++) {
            struct message *msg = &messages[i];
            int64_t before_send = now_ns();

            if (before_send < msg->next_ns)
                continue;

            int rc = send_message(sock, msg);

            if (rc < 0) {
                exit_code = EXIT_FAILURE;
                stop_requested = 1;
                break;
            }

            if (rc == 0)
                msg->sent++;
            else
                msg->errors++;

            /* Advance the original schedule, not the current time. */
            msg->next_ns += msg->period_ns;

            /*
             * Re-read the clock after sending. If deadlines were missed,
             * skip expired periods instead of sending catch-up bursts.
             */
            int64_t after_send = now_ns();

            if (msg->next_ns <= after_send) {
                int64_t missed =
                    (after_send - msg->next_ns) / msg->period_ns + 1;

                msg->next_ns += missed * msg->period_ns;
                msg->skipped += (unsigned long)missed;
            }
        }
    }

    printf("\nTraffic generator stopping.\n");

    for (size_t i = 0; i < NUM_MESSAGES; i++) {
        printf("%-8s ID 0x%03X: sent=%lu, skipped_periods=%lu, errors=%lu\n",
               messages[i].name, (unsigned)messages[i].id,
               messages[i].sent, messages[i].skipped,
               messages[i].errors);
    }

    if (close(sock) < 0) {
        perror("close");
        exit_code = EXIT_FAILURE;
    }

    return exit_code;
}
