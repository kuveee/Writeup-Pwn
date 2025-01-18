#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#define FILE_PATH "./something.png"
#define IMG_DATA_SIZE 0x1000000
#define VALIDATE_PROT(p) ((p) & (PROT_READ | PROT_WRITE | PROT_EXEC))

__attribute__((section(".img")))
char img_data[IMG_DATA_SIZE];

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);

    puts("Simple PNG Header Reader");

    // Open the image file.
    int fd = open(FILE_PATH, O_RDONLY);
    if (fd < 0) {
        printf("Failed to open %s.\n", FILE_PATH);
        return -1;
    }

    // Prepare for writing it.
    mprotect(img_data, IMG_DATA_SIZE, VALIDATE_PROT(PROT_READ | PROT_WRITE));

    // Read the image data.
    int size = read(fd, img_data, IMG_DATA_SIZE);
    if (size < 0) {
        printf("Failed to read %s.\n", FILE_PATH);
        return -1;
    }
    printf("Loaded %d bytes from %s.\n", size, FILE_PATH);

    // Make the data read-only.
    mprotect(img_data, IMG_DATA_SIZE, VALIDATE_PROT(~PROT_WRITE));

    while (1) {
        // Wait for user input.
        printf("> ");
        char buf[0x100];
        scanf("%s", buf);

        if (!strcmp(buf, "show")) {
            // Show the image data.
            puts("Showing the image data...");
            printf("data[0] = %02x\n", ((unsigned char)img_data[0] % 0x100));
            printf("data[1:4] = %c%c%c\n", img_data[1], img_data[2], img_data[3]);
        } else if (!strcmp(buf, "exit")) {
            // Exit the program.
            puts("Bye!");
            return 0;
        } else {
            // Invalid command.
            puts("Invalid command.");
        }
    }
}
