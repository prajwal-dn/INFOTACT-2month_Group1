#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/can.h>
#include <linux/can/raw.h>

int main() {
    int s;
    struct sockaddr_can addr;
    struct ifreq ifr;
    struct can_frame frame;

    s = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (s < 0) { perror("Socket"); return 1; }

    strcpy(ifr.ifr_name, "vcan0");
    ioctl(s, SIOCGIFINDEX, &ifr);

    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Bind"); return 1;
    }

    printf("Normal traffic generator started on vcan0...\n");
    printf("Press Ctrl+C to stop\n\n");

    int counter = 0;
    while (1) {
        frame.can_id = 0x100;
        frame.can_dlc = 2;
        frame.data[0] = 0x0B;
        frame.data[1] = 0xB8;
        write(s, &frame, sizeof(frame));
        printf("[%d] RPM: 0x100#0BB8\n", counter);

        frame.can_id = 0x101;
        frame.can_dlc = 2;
        frame.data[0] = 0x00;
        frame.data[1] = 0x3C;
        write(s, &frame, sizeof(frame));
        printf("[%d] Speed: 0x101#003C\n", counter);

        if (counter % 10 == 0) {
            frame.can_id = 0x102;
            frame.can_dlc = 2;
            frame.data[0] = 0x00;
            frame.data[1] = 0x5A;
            write(s, &frame, sizeof(frame));
            printf("[%d] Temp: 0x102#005A\n", counter);
        }

        counter++;
        usleep(100000);
    }

    close(s);
    return 0;
}

