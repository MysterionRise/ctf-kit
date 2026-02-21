#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void win() {
    system("cat flag.txt");
}

void vuln() {
    char buffer[64];
    printf("Enter input: ");
    gets(buffer);
    printf("You said: %s\n", buffer);
}

int main() {
    vuln();
    return 0;
}
