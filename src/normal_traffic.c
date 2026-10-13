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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t running = 1;

static void handle_signal(int sig)
{
    (void)sig;
    running = 0;
}

static int send_signal_frame(int socket_fd,
                             canid_t can_id,
                             uint16_t value)
{
    struct can_frame frame;
    memset(&frame, 0, sizeof(frame));

    frame.can_id = can_id;
    frame.can_dlc = 2;
    frame.data[0] = (uint8_t)(value >> 8);
    frame.data[1] = (uint8_t)(value & 0xFF);

    ssize_t written = write(socket_fd, &frame, sizeof(frame));

    if (written != (ssize_t)sizeof(frame)) {
        if (written < 0) {
            perror("Failed to send CAN frame");
        } else {
            fprintf(stderr, "Incomplete CAN frame write\n");
        }
        return -1;
    }

    return 0;
}

int main(void)
{
    const char *interface_name = "vcan0";

    unsigned int interface_index = if_nametoindex(interface_name);
    if (interface_index == 0) {
        fprintf(stderr,
                "Interface %s not found. Bring vcan0 up first.\n",
                interface_name);
        return EXIT_FAILURE;
    }

    int socket_fd = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (socket_fd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    struct sockaddr_can address;
    memset(&address, 0, sizeof(address));
    address.can_family = AF_CAN;
    address.can_ifindex = (int)interface_index;

    if (bind(socket_fd,
             (struct sockaddr *)&address,
             sizeof(address)) < 0) {
        perror("bind");
        close(socket_fd);
        return EXIT_FAILURE;
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = handle_signal;
    sigemptyset(&action.sa_mask);

    if (sigaction(SIGINT, &action, NULL) < 0 ||
        sigaction(SIGTERM, &action, NULL) < 0) {
        perror("sigaction");
        close(socket_fd);
        return EXIT_FAILURE;
    }

    printf("CAN-Sentinel normal traffic generator\n");
    printf("Interface: %s (virtual only)\n", interface_name);
    printf("RPM: 3000 | Speed: 60 km/h | Coolant: 90 C\n");
    printf("Press Ctrl+C to stop.\n\n");
    fflush(stdout);

    struct timespec delay = {
        .tv_sec = 0,
        .tv_nsec = 100000000L
    };

    unsigned int cycle = 0;
    int result = EXIT_SUCCESS;

    while (running) {
        if (send_signal_frame(socket_fd, 0x100, 3000) < 0 ||
            send_signal_frame(socket_fd, 0x101, 60) < 0) {
            result = EXIT_FAILURE;
            break;
        }

        cycle++;

        if (cycle % 10 == 0) {
            if (send_signal_frame(socket_fd, 0x102, 90) < 0) {
                result = EXIT_FAILURE;
                break;
            }

            printf("Simulated RPM=3000, speed=60 km/h, coolant=90 C\n");
            fflush(stdout);
        }

        if (nanosleep(&delay, NULL) < 0 && errno != EINTR) {
            perror("nanosleep");
            result = EXIT_FAILURE;
            break;
        }
    }

    close(socket_fd);
    printf("\nTraffic generator stopped.\n");

    return result;
}
