/* Plan F prototype, revision 12 (THROWAWAY, macOS only): a host thread left inside a class's +initialize
 * when the shim forks, as a multi-threaded Objective-C host can be. The fork child makes no Objective-C or
 * CoreFoundation call, so the runtime's "+initialize may have been in progress" fork check never runs. */
#import <Foundation/Foundation.h>
#include <pthread.h>
#include <unistd.h>
static int entered[2];
@interface CoscaBlocksInInitialize : NSObject
@end
@implementation CoscaBlocksInInitialize
+ (void)initialize { char c = 1; (void)!write(entered[1], &c, 1); for (;;) pause(); }
@end
static void *run(void *a) { (void)a; [CoscaBlocksInInitialize class]; return 0; }
void start_objc_initialize_thread(void) {
    pthread_t t; char c; (void)!pipe(entered);
    pthread_create(&t, 0, run, 0);
    (void)!read(entered[0], &c, 1); /* returns once +initialize is running in that thread */
}
