//
//  ViewController.m
//  RsaEncryption
//
//  Created by Ozgur Sahin on 24/01/15.
//

#import "ViewController.h"
#import "RsaHelper.h"
#import "AESEncryption.h"
@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    RsaHelper* rsa=[[RsaHelper alloc]init];
    [rsa test];
    
    //[self testAESEncryption];
}
-(void)testAESEncryption
{
//    NSString* key=  @"Passw0rD!";
//    NSData* value = [@"value" dataUsingEncoding:NSUTF8StringEncoding];
//    NSData* encryptedData=[AESEncryption AES256Encrypt:value withKey:key];
//    NSLog(@"Encrypted:%@",[encryptedData base64EncodedString]);
//    
//    NSData *decrypted = [AESEncryption AES256Decrypt:encryptedData withKey:key];
//
//    NSLog(@"%@",[[NSString alloc] initWithData:decrypted encoding:NSUTF8StringEncoding]);

   
}
- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
