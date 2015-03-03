//
//  RsaHelper.m
//  RsaEncryption
//
//  Created by Ozgur Sahin on 24/01/15.
//

#import "RsaHelper.h"

@implementation RsaHelper

-(void)test
{
    NSString* publicTag=@"publicTag";
    NSString* privateTag=@"privateTag";
    
    
    //creating key pair
    [self createKeyPairWithTag:publicTag privateTag:privateTag];
    
    //write public as a modulus and exponent
    //[self writePublicKeyModAndExpWithTag:publicTag];
    
    
    
    //encryption
    NSString* cipherText= [self encryptWithModulus:[self getModulusWithTag:publicTag] exponent:[self getExponentWithTag:publicTag] publicKeyTag:publicTag content:@"plainText"];
    
    NSLog(@"cipherText:%@",cipherText);
    
    //decryption using mod and expo
    NSString* plainText= [self decrypt:cipherText privateTag:privateTag];
    
     NSLog(@"plainText:%@",plainText);

}

/**
 *  Generate and Save key pair to the keychain with tags
 */
-(void)createKeyPairWithTag:(NSString*)publicTag privateTag:(NSString*)privateTag
{
    bool result=[CryptoUtil generateRSAKeyWithKeySizeInBits:1024 publicKeyTag:publicTag     privateKeyTag:privateTag];
    
    if (result==noErr) {
        [self writePublicKeyModAndExpWithTag:publicTag];
    }

}
/**
 *  Get modulus of public key with tag
 */
-(NSString*)getModulusWithTag:(NSString*)publicTag
{
    KeyHelper* keyHelper =[[KeyHelper alloc]init];
    NSData* pubkeyData=  [keyHelper getPublicKeyBitsWithtag:publicTag];
    NSData *modData=  [keyHelper getPublicKeyModFromKeyData:pubkeyData];
    return [modData base64Encoding];
}
/**
 *  Get exponent of public key with tag
 */
-(NSString*)getExponentWithTag:(NSString*)publicTag
{
    KeyHelper* keyHelper =[[KeyHelper alloc]init];
    NSData* pubkeyData=  [keyHelper getPublicKeyBitsWithtag:publicTag];
    NSData *expoData=  [keyHelper getPublicKeyExpFromKeyData:pubkeyData];
    return [expoData base64Encoding];
}

/**
 *  Print public key as modulus and exponent
 */
-(void)writePublicKeyModAndExpWithTag:(NSString*)publicTag
{
    KeyHelper* keyHelper =[[KeyHelper alloc]init];
    NSData* pubkeyData=  [keyHelper getPublicKeyBitsWithtag:publicTag];
    
    NSLog(@"pubKey :%@",[pubkeyData base64Encoding]);
    
    NSData *modData=  [keyHelper getPublicKeyModFromKeyData:pubkeyData];
    NSLog(@"modulus :%@",[modData base64Encoding]);
    
    NSData *expoData=  [keyHelper getPublicKeyExpFromKeyData:pubkeyData];
    NSLog(@"exponent :%@",[expoData base64Encoding]);
}
/**
 *  Encrypt Using Modulus and Exponent
 */
-(NSString*)encryptWithModulus:(NSString*)modulus exponent:(NSString*)exponent publicKeyTag:(NSString*)publicKeyTag content:(NSString*)content
{
    NSData *modulusData=  [NSData dataWithBase64EncodedString:modulus];
    NSData *expoData=  [NSData dataWithBase64EncodedString:exponent];
    NSData* publicKeyData= [CryptoUtil generateRSAPublicKeyWithModulus:modulusData exponent:expoData];
    bool success= [CryptoUtil saveRSAPublicKey:publicKeyData appTag:publicKeyTag overwrite:YES];
    NSString* encryptedString;
    if (success) {
        SecKeyRef publicKey= [CryptoUtil loadRSAPublicKeyRefWithAppTag:publicKeyTag];
        
        NSData* encryptedData= [CryptoUtil encryptString:content RSAPublicKey:publicKey padding:kSecPaddingPKCS1];
        encryptedString=[encryptedData base64Encoding];
        NSLog(@"EncrpytedString :%@",encryptedString);
       
    }
    else
    {
        NSLog(@"RSA Public key couldn't be saved.");
    }
    return encryptedString;

}

-(NSString *)decrypt:(NSString*)cipher privateTag:(NSString*)privateTag
{
    KeyHelper* keyHelper =[[KeyHelper alloc]init];
    SecKeyRef privateKey=[keyHelper getPrivateKeyRefWithTag:privateTag];
    NSString* plaintText= [self rsaDecryptWithData:[cipher base64DecodedData] key:privateKey];
    return plaintText;
}

-(NSString *)rsaDecryptWithData:(NSData*)content key:(SecKeyRef)key{
    
    size_t cipherLen = [content length];
    void *cipher = malloc(cipherLen);
    [content getBytes:cipher length:cipherLen];
    
    size_t keyBufferSize = [content length];
    
    NSMutableData *bits = [NSMutableData dataWithLength:keyBufferSize];
    OSStatus sanityCheck = SecKeyDecrypt(key,
                                         kSecPaddingPKCS1,
                                         cipher,
                                         cipherLen,
                                         [bits mutableBytes],
                                         &keyBufferSize);
    
    if (sanityCheck != 0) {
        NSError *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:sanityCheck userInfo:nil];
        NSLog(@"Error: %@", [error description]);
    }
    
    [bits setLength:keyBufferSize];
    return [[NSString alloc] initWithData:bits
                                 encoding:NSUTF8StringEncoding];
}
@end
