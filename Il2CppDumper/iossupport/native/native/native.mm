//
//  native.mm
//  native
//
//  Created by 123456qwerty on 2022/8/18.
//

#import <Foundation/Foundation.h>
#include <termios.h>

#include <string>
#include <iostream>

extern "C" {
    static NSProcessInfo *processInfo = nil;
    static NSArray<NSString *> *args = nil;
    
    int getArgsLength(void) {
        return (int)args.count;
    }
    
    const char *getArgs(int index) {
        return args[index].UTF8String;
    }
    
    const char *getRealProcessName(void) {
        return processInfo.processName.UTF8String;
    }
    
    void _printf(char *str) {
        std::cout << str;
    }
    
    const char *_ReadLine(void) {
        char a[1024];
        scanf("%s", a);
        void *mem = malloc(sizeof(a));
        memcpy(mem, (void *)a, sizeof(a));
        const char *result = (const char *)mem;
        return result;
    }
    
    char readKey(void) {
        struct termios orig_settings;
        tcgetattr(0, &orig_settings);
        struct termios new_settings = orig_settings;
        new_settings.c_lflag &= (~ICANON);
        new_settings.c_lflag &= (~ECHO);
        new_settings.c_cc[VTIME] = 0;
        new_settings.c_cc[VMIN] = 1;
        tcsetattr(0, TCSANOW, &new_settings);
        char result = getchar() - '0';
        tcsetattr(0, TCSANOW, &orig_settings);
        return result;
    }
    
    static void __attribute__((constructor)) initGvs(void) {
        processInfo = NSProcessInfo.processInfo;
        args = processInfo.arguments;
    }
}
