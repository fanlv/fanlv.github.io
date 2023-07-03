//
//  main.c
//  Testc
//
//  Created by FanLv on 2020/6/6.
//  Copyright © 2020 FanLv. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

void thread_test1 (void *ptr);
void thread_test2 (void *ptr);
int running = 1;
int running2 = 1;

int main()
{
    
    int tmp1, tmp2;
    void *retval;
    pthread_t thread1, thread2;
    char *message1 = "thread1";
    char *message2 = "thread2";

    int ret_thrd1, ret_thrd2;

    ret_thrd1 = pthread_create(&thread1, NULL, (void *)&thread_test1, (void *) message1);
    ret_thrd2 = pthread_create(&thread2, NULL, (void *)&thread_test2, (void *) message2);

    // 线程创建成功，返回0,失败返回失败号
    if (ret_thrd1 != 0) {
        printf("线程1创建失败\n");
    } else {
        printf("线程1创建成功\n");
    }

    if (ret_thrd2 != 0) {
        printf("线程2创建失败\n");
    } else {
        printf("线程2创建成功\n");
    }

    //同样，pthread_join的返回值成功为0
    tmp1 = pthread_join(thread1, &retval);
    if (tmp1 != 0) {
        printf("cannot join with thread1\n");
    }

    tmp2 = pthread_join(thread1, &retval);
    if (tmp2 != 0) {
        printf("cannot join with thread2\n");
    }
    
    while (1) {
        
    }

}

void thread_test1( void *ptr ) {
 
    printf("thread1 start\n");
    int count = 0;
    while (running) {
        count ++;
    }
    running2 = 0;
    printf("thread1 end , count = %d\n", count);
}


void thread_test2( void *ptr ) {
    printf("thread2 start\n");
    int count = 0;
    while (running2) {
        running = 0;
        count ++;
    }
    printf("thread2 end , count = %d\n", count);
}



//int main(int argc, const char * argv[]) {
//    printf("Hello, World!\n");
//    unsigned int  a;
//    a = 0;
//    printf("int put code:");
//    scanf("%d",&a);
//    if (a == 588) {
//        printf("right!!\n");
//    }else{
//        printf("wrong!!\n");
//    }
//
//    return 0;
//}




//
// // overflow_test.c
// #include <stdio.h>
// #include <stdlib.h>
// //char shellcode[] =
// //    "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
// //    "\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
// //    "\x80\xe8\xdc\xff\xff\xff/bin/sh";
//
// int test()
// {
//     int i;
//     unsigned int stack[10];
// //    char my_str[16];
// //    printf("addr of shellcode in decimal: %d\n", &shellcode);
//     for (i = 0; i < 10; i++)
//         stack[i] = 0;
//
//     while (1) {
//         printf("index of item to fill: (-1 to quit): ");
//         scanf("%d",&i);
//         if (i == -1) {
//             break;
//         }
//         printf("value of item[%d]:", i);
//         scanf("%d",&stack[i]);
//     }
//
//     return 0;
// }
//
// int main()
// {
//     test();
//     printf("Overflow Failed\n");
//
//     return 0;
// }
//
//
