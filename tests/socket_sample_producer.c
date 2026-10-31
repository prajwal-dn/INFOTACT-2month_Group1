#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define SOCKET_PATH "/tmp/can_sentinel.sock"

static int send_all(int fd, const char *data, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        ssize_t n = send(fd, data + sent, length - sent, MSG_NOSIGNAL);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            perror("send");
            return -1;
        }

        if (n == 0) {
            fprintf(stderr, "Socket closed while sending.\n");
            return -1;
        }

        sent += (size_t)n;
    }

    return 0;
}

int main(void)
{
    const char *events[] = {
        "{\"schema_version\":1,\"event_type\":\"can_frame\","
        "\"timestamp_utc\":\"2026-10-31T18:20:30.123456789Z\","
        "\"interface\":\"vcan0\",\"can_id\":\"0x100\","
        "\"frame_format\":\"standard\",\"flags\":\"none\","
        "\"dlc\":2,\"payload\":\"FFFF\"}\n",

        "{\"schema_version\":1,\"event_type\":\"can_frame\","
        "\"timestamp_utc\":\"2026-10-31T18:20:31.223456789Z\","
        "\"interface\":\"vcan0\",\"can_id\":\"0x999\","
        "\"frame_format\":\"extended\",\"flags\":\"none\","
        "\"dlc\":2,\"payload\":\"DEAD\"}\n"
    };

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;

    if (strlen(SOCKET_PATH) >= sizeof(address.sun_path)) {
        fprintf(stderr, "Socket path is too long.\n");
        close(fd);
        return 1;
    }

    snprintf(address.sun_path, sizeof(address.sun_path), "%s", SOCKET_PATH);

    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("connect");
        close(fd);
        return 1;
    }

    for (size_t i = 0; i < sizeof(events) / sizeof(events[0]); i++) {
        if (send_all(fd, events[i], strlen(events[i])) < 0) {
            close(fd);
            return 1;
        }

        printf("Sent sample event %zu/%zu\n",
               i + 1, sizeof(events) / sizeof(events[0]));
    }

    shutdown(fd, SHUT_WR);
    close(fd);

    puts("C sample producer finished.");
    return 0;
}
