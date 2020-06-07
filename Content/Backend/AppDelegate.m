//
//  AppDelegate.m
//  TestIOS
//
//  Created by FanLv on 2020/6/6.
//  Copyright © 2020 FanLv. All rights reserved.
//

#import "AppDelegate.h"

@interface AppDelegate ()

@end

@implementation AppDelegate
//
//bool running = true;
//bool running2 = true;
//
//- (void)therad1Test {
//    NSLog(@"thread1 start");
//    int count = 0;
//    while (running) {
//        count ++;
//    }
//    running2 = false;
//    NSLog(@"thread1 end");
//
//}
//
//- (void)therad2Test {
//    NSLog(@"thread2 start");
//    while (running2) {
//        running = false;
//    }
//    NSLog(@"thread2 end");
//}
//
//



- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
//    NSThread *thread=[[NSThread alloc]initWithTarget:self selector:@selector(therad1Test) object:nil];
//    [thread start];
//    NSThread *thread2=[[NSThread alloc]initWithTarget:self selector:@selector(therad2Test) object:nil];
//    [thread2 start];

   __block bool running = true;

    dispatch_queue_t queue1 = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
    dispatch_async(queue1,^{
        NSLog(@"thread1 start");
        while (running) {
        }
        NSLog(@"thread1 end");
    });
    
    dispatch_queue_t queue2 = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
    dispatch_async(queue2,^{
        sleep(2);
        NSLog(@"thread2 start");
        while (1) {
            running = false;
        }
        
    });

    
    

    return YES;
}


#pragma mark - UISceneSession lifecycle


- (UISceneConfiguration *)application:(UIApplication *)application configurationForConnectingSceneSession:(UISceneSession *)connectingSceneSession options:(UISceneConnectionOptions *)options {
    // Called when a new scene session is being created.
    // Use this method to select a configuration to create the new scene with.
    return [[UISceneConfiguration alloc] initWithName:@"Default Configuration" sessionRole:connectingSceneSession.role];
}


- (void)application:(UIApplication *)application didDiscardSceneSessions:(NSSet<UISceneSession *> *)sceneSessions {
    // Called when the user discards a scene session.
    // If any sessions were discarded while the application was not running, this will be called shortly after application:didFinishLaunchingWithOptions.
    // Use this method to release any resources that were specific to the discarded scenes, as they will not return.
}


@end
