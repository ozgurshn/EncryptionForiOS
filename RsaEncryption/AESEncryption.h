//
//  AESEncryption.h
//
//  Created by Ozgur Sahin on 01/07/14.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCryptor.h>

@interface AESEncryption : NSObject

+ (NSData *)AES256Encrypt:(NSData*)data withKey:(NSString *)key  iv:(NSData**)iv
                     salt:(NSData**)salt
                    error:(NSError**)error;


+(NSData *)AES256Decrypt:(NSData*)data withKey:(NSString *)key iv:(NSString*)ivString;
+(NSData*)randomDataOfLength:(size_t)length;
@end
