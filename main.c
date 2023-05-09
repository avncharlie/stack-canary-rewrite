//#include <stdio.h>
//
//void foo() {
//    printf("ello mate\n");
//}
//
//int main() {
//    char str[5];
//
//    printf("hello! enter something: ");
//
//    scanf("%s", str);
//
//    printf("\nyou entered: %s\n", str);
//
//}

#include <stdio.h>

void foo() {
    char str[5];
    printf("hello! enter something: ");
    scanf("%s", str);
    printf("\nyou entered: %s\n", str);
}

int main() {
    foo();
}

