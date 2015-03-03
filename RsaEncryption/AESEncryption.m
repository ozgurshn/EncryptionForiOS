//
//  AESEncryption.m
//
//  Created by Ozgur Sahin on 01/07/14.
//

#import "AESEncryption.h"
#import "Base64.h"

@implementation AESEncryption

+ (NSData *)AES256Encrypt:(NSData*)data withKey:(NSString *)key  iv:(NSData**)iv
                     salt:(NSData**)salt
                    error:(NSError**)error
{
	
	char keyPtr[kCCKeySizeAES256+1];
	bzero(keyPtr, sizeof(keyPtr));
	
	
	[key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
	
	NSUInteger dataLength = [data length];
    *iv= [self randomDataOfLength:kCCBlockSizeAES128];
    
	size_t bufferSize = dataLength + kCCBlockSizeAES128;
	void *buffer = malloc(bufferSize);
	
	size_t numBytesEncrypted = 0;
	CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                                          keyPtr,
                                          kCCKeySizeAES256,
                                          (*iv).bytes ,
                                          data.bytes, dataLength, /* input */
                                          buffer,
                                          bufferSize, /* output */
                                          &numBytesEncrypted);
	if (cryptStatus == kCCSuccess) {
		return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
	}
    
	free(buffer);
	return nil;
}

+ (NSData*)randomDataOfLength:(size_t)length
{
    NSMutableData* data=[NSMutableData dataWithLength:length];
    
    int result= SecRandomCopyBytes(kSecRandomDefault, length, data.mutableBytes);
    NSAssert(result==0, @"Unable to generate random bytes:%d",errno);
    return data;
}

+(NSData *)AES256Decrypt:(NSData*)data withKey:(NSString *)key iv:(NSString*)ivString
{
    
    NSData* keyData=[NSData dataWithBase64EncodedString:key];
    NSUInteger dataLength = [data length];
    
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesDecrypted = 0;
    
    //IV init
    NSData* ivData=[NSData dataWithBase64EncodedString:ivString];

    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding ,
                                          [keyData bytes],
                                          kCCKeySizeAES256,
                                          [ivData bytes],
                                          [data bytes], dataLength,
                                          buffer, bufferSize,
                                          &numBytesDecrypted);
    
    if (cryptStatus == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
    }
    
    free(buffer);
    return nil;
}


@end
