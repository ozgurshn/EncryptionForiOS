//
//  Created by ozgur sahin on 20/01/15.
//

#import "KeyHelper.h"

@implementation KeyHelper
- (NSData *)getPublicKeyBits: (NSString*) publicKeyIdentifier {
    
    OSStatus sanityCheck = noErr;
    NSData * publicKeyBits = nil;
    CFTypeRef pk;
    NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
    
    NSData* publicTag = [publicKeyIdentifier dataUsingEncoding:NSUTF8StringEncoding];
    
    // Set the public key query dictionary.
    [queryPublicKey setObject:(__bridge_transfer id)kSecClassKey forKey:(__bridge_transfer id)kSecClass];
    
    [queryPublicKey setObject:publicTag forKey:(__bridge_transfer id)kSecAttrApplicationTag];
    [queryPublicKey setObject:(__bridge_transfer id)kSecAttrKeyTypeRSA forKey:(__bridge_transfer id)kSecAttrKeyType];
    [queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge_transfer id)kSecReturnData];
    
    // Get the key bits.
    sanityCheck = SecItemCopyMatching((__bridge_retained CFDictionaryRef)queryPublicKey, &pk);
    if (sanityCheck != noErr)
    {
        publicKeyBits = nil;
    }
    publicKeyBits = (__bridge_transfer NSData*)pk;
    //NSLog(@"public bits %@",publicKeyBits);
    
    return publicKeyBits;
}
- (NSData *)getPublicKeyExpFromKeyData:(NSData*) pk
{
   // NSData* pk = [self getPublicKeyBits:@"RSA Public Key"];
    if (pk == NULL) return NULL;
    
    int iterator = 0;
    
    iterator++; // TYPE - bit stream - mod + exp
    [self derEncodingGetSizeFrom:pk at:&iterator]; // Total size
    
    iterator++; // TYPE - bit stream mod
    int mod_size = [self derEncodingGetSizeFrom:pk at:&iterator];
    iterator += mod_size;
    
    iterator++; // TYPE - bit stream exp
    int exp_size = [self derEncodingGetSizeFrom:pk at:&iterator];
    
    return [pk subdataWithRange:NSMakeRange(iterator, exp_size)];
    return pk;
}



- (NSData *)getPublicKeyExp
{
    NSData* pk = [self getPublicKeyBits:@"RSA Public Key"];
    if (pk == NULL) return NULL;
    
    int iterator = 0;
    
    iterator++; // TYPE - bit stream - mod + exp
    [self derEncodingGetSizeFrom:pk at:&iterator]; // Total size
    
    iterator++; // TYPE - bit stream mod
    int mod_size = [self derEncodingGetSizeFrom:pk at:&iterator];
    iterator += mod_size;
    
    iterator++; // TYPE - bit stream exp
    int exp_size = [self derEncodingGetSizeFrom:pk at:&iterator];
    
    return [pk subdataWithRange:NSMakeRange(iterator, exp_size)];
    return pk;
}
- (NSData *)getPublicKeyModFromKeyData:(NSData*)pk
{
    //NSData* pk = [self getPublicKeyBits:@"RSA Public Key"];
    if (pk == NULL) return NULL;
    
    int iterator = 0;
    
    iterator++; // TYPE - bit stream - mod + exp
    [self derEncodingGetSizeFrom:pk at:&iterator]; // Total size
    
    iterator++; // TYPE - bit stream mod
    int mod_size = [self derEncodingGetSizeFrom:pk at:&iterator];
    NSLog(@"public size: %d",pk.length);
    return [pk subdataWithRange:NSMakeRange(iterator, mod_size)];
    return pk;
    
}
- (NSData *)getPublicKeyMod
{
    NSData* pk = [self getPublicKeyBits:@"RSA Public Key"];
    if (pk == NULL) return NULL;
    
    int iterator = 0;
    
    iterator++; // TYPE - bit stream - mod + exp
    [self derEncodingGetSizeFrom:pk at:&iterator]; // Total size
    
    iterator++; // TYPE - bit stream mod
    int mod_size = [self derEncodingGetSizeFrom:pk at:&iterator];
        NSLog(@"public size: %d",pk.length);
    return [pk subdataWithRange:NSMakeRange(iterator, mod_size)];
    return pk;

}

- (int)derEncodingGetSizeFrom:(NSData*)buf at:(int*)iterator
{
    const uint8_t* data = [buf bytes];
    int itr = *iterator;
    int num_bytes = 1;
    int ret = 0;
    
    if (data[itr] > 0x80) {
        num_bytes = data[itr] - 0x80;
        itr++;
    }
    
    for (int i = 0 ; i < num_bytes; i++)
        ret = (ret * 0x100) + data[itr + i];
    
    *iterator = itr + num_bytes;
    return ret;
}
- (NSData *)getPublicKeyBitsWithtag:(NSString*)publicTag {
    OSStatus sanityCheck = noErr;
    NSData * publicKeyBits = nil;
    
    NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
    
    // Set the public key query dictionary.
    [queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPublicKey setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnData];
    
    // Get the key bits.
    sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryPublicKey, (void *)&publicKeyBits);
    
    if (sanityCheck != noErr)
    {
        publicKeyBits = nil;
    }
    
    
    return publicKeyBits;
}
- (SecKeyRef)getPrivateKeyRefWithTag:(NSString*)privateTag{
    OSStatus resultCode = noErr;
    SecKeyRef privateKeyReference = NULL;

    NSMutableDictionary * queryPrivateKey = [[NSMutableDictionary alloc] init];
    
    // Set the private key query dictionary.
    [queryPrivateKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPrivateKey setObject:privateTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPrivateKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [queryPrivateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    
    // Get the key.
    resultCode = SecItemCopyMatching((__bridge CFDictionaryRef)queryPrivateKey, (CFTypeRef *)&privateKeyReference);
    NSLog(@"getPrivateKey: result code: %ld", resultCode);
    
    if(resultCode != noErr)
    {
        privateKeyReference = NULL;
    }
    
    //        [queryPrivateKey release];
    //    } else {
    //        privateKeyReference = privateKey;
    //    }
    
    return privateKeyReference;
}
//assumes utf8 encoded string
- (SecKeyRef)_getKeyNamed:(NSData *)keyNameUTF8
{
    OSStatus    err;
    SecKeyRef   keyRef = NULL;
    err = SecItemCopyMatching((__bridge CFDictionaryRef)
                              [NSDictionary dictionaryWithObjectsAndKeys:
                               (__bridge id)
                               kSecClassKey,           kSecClass,
                               keyNameUTF8,             kSecAttrApplicationTag,
                               kCFBooleanTrue,         kSecReturnRef,
                               nil
                               ],
                              (CFTypeRef *) &keyRef
                              );
    assert( (err == noErr) == (keyRef != NULL) );
    return keyRef;
}
@end
