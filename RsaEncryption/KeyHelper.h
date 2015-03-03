//
//  Created by ozgur sahin on 20/01/15.
//

#import <Foundation/Foundation.h>

@interface KeyHelper : NSObject
- (NSData *)getPublicKeyExpFromKeyData:(NSData*) pk;
- (NSData *)getPublicKeyModFromKeyData:(NSData*)pk;
- (NSData *)getPublicKeyBitsWithtag:(NSString*)publicTag;
- (SecKeyRef)getPrivateKeyRefWithTag:(NSString*)privateTag;
@end
