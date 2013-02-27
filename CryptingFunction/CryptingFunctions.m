//
//  CryptingFunctions.m
//
//  Created by Florian on 25.01.13.
//  Copyright (c) 2013 Florian Killius. All rights reserved.
//

#define KEY_IV @"key_iv"
#define KEY_SALT @"key_salt"
#define KEY_HMAC @"key_hmac"
#define KEY_ENCRYPTED_DATA @"key_encrypted_data"

// what for is this domain thing?
#define MY_DOMAIN @"crypting.functions.domain"

#import "CryptingFunctions.h"

#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import <Security/SecRandom.h>


@implementation CryptingFunctions


+(void)saveFileAtPath:(NSString *)path 
                 data:(NSData *)data 
             password:(NSString *)password 
                error:(NSError **)error
{
    NSData *iv;
    NSData *salt;
    NSError *encryptError = NULL;
    
    NSData *encryptedData = [CryptingFunctions encryptData:data 
                                                  password:password 
                                                        iv:&iv 
                                                      salt:&salt 
                                                     error:&encryptError];
    if ( encryptError && error ) {
        NSMutableDictionary* details = [NSMutableDictionary dictionary];
        [details setValue:ERROR_WRITING_FILE 
                   forKey:NSLocalizedDescriptionKey];
        *error = [NSError errorWithDomain:MY_DOMAIN 
                                     code:200 
                                 userInfo:details];
        return;
    }
    
    NSData *key = [CryptingFunctions AESKeyForPassword:password salt:salt];
    NSData *hmac = [CryptingFunctions getHMACData:data key:key];
    
    NSDictionary *fileData = [NSDictionary dictionaryWithObjectsAndKeys:iv, KEY_IV,
                              salt, KEY_SALT,
                              hmac, KEY_HMAC,
                              encryptedData, KEY_ENCRYPTED_DATA, nil];
    
    BOOL success = [fileData writeToFile:path 
                              atomically:NO];
    
    if ( !success ) {
        NSDictionary* details = [NSDictionary dictionaryWithObject:ERROR_WRITING_FILE 
                                                            forKey:NSLocalizedDescriptionKey];
        *error = [NSError errorWithDomain:MY_DOMAIN 
                                     code:200 
                                 userInfo:details];
    }
}

+ (NSData *)loadEncryptedFileAtPath:(NSString *)path 
                           password:(NSString *)password 
                              error:(NSError **)error
{
    if(![[NSFileManager defaultManager] isReadableFileAtPath:path]) {
        if(error) {
            NSDictionary* details = [NSDictionary dictionaryWithObject:ERROR_FILE_NOT_FOUND_OR_NOT_READABLE 
                                                                forKey:NSLocalizedDescriptionKey];
            *error = [NSError errorWithDomain:MY_DOMAIN 
                                         code:200 
                                     userInfo:details];
        }
        return nil;
    }
    
    NSDictionary *fileData = [NSDictionary dictionaryWithContentsOfFile:path];
    
    NSData *iv = [fileData objectForKey:KEY_IV];
    NSData *salt = [fileData objectForKey:KEY_SALT];
    NSData *encryptedData = [fileData objectForKey:KEY_ENCRYPTED_DATA];
    NSData *hmac = [fileData objectForKey:KEY_HMAC];
    
    NSError *decryptionError = NULL;
    
    if (!iv || !salt || !encryptedData || !hmac) {
        if(error) {
            NSDictionary* details = [NSDictionary dictionaryWithObject:ERROR_CORRUPTED_FILE_FORMAT 
                                                                forKey:NSLocalizedDescriptionKey];
            *error = [NSError errorWithDomain:MY_DOMAIN 
                                         code:200 
                                     userInfo:details];
        }
        return nil;
    }
    
    NSData *decryptedData = [CryptingFunctions decryptData:encryptedData 
                                                  password:password 
                                                        iv:iv 
                                                      salt:salt
                                                     error:&decryptionError];
    
    if(decryptionError) {
        if (error) {
            NSDictionary* details = [NSDictionary dictionaryWithObject:ERROR_DECRYPTING 
                                                                forKey:NSLocalizedDescriptionKey];
            *error = [NSError errorWithDomain:MY_DOMAIN 
                                         code:200 
                                     userInfo:details];
        }
        return nil;
    }
    
    NSData *key = [CryptingFunctions AESKeyForPassword:password 
                                                  salt:salt];
    NSData *newHmac = [CryptingFunctions getHMACData:decryptedData 
                                                 key:key];
    
    if (![newHmac isEqualToData:hmac]){
        if(error) {
            NSDictionary* details = [NSDictionary dictionaryWithObject:ERROR_WRONG_PASSWORD 
                                                                forKey:NSLocalizedDescriptionKey];
            *error = [NSError errorWithDomain:MY_DOMAIN 
                                         code:200 
                                     userInfo:details];
        }
        return nil;
    }
    
    return decryptedData;
}


+(NSData *)encryptData:(NSData *)data
              password:(NSString *)password
                    iv:(NSData **)iv
                  salt:(NSData **)salt
                 error:(NSError **)error 
{
    
    const CCAlgorithm kAlgorithm = kCCAlgorithmAES128;
    const NSUInteger kAlgorithmBlockSize = kCCBlockSizeAES128;
    const NSUInteger kAlgorithmIVSize = kCCBlockSizeAES128;
    const NSUInteger kPBKDFSaltSize = 8;
    
    
    if(!iv) {
        NSLog(@"IV must not be NULL");
        if (error) {
            NSDictionary* details = [NSDictionary dictionaryWithObject:ERROR_ENCRYPTING 
                                                                forKey:NSLocalizedDescriptionKey];
            *error = [NSError errorWithDomain:MY_DOMAIN 
                                         code:200 
                                     userInfo:details];
        }
        return nil;
    }
    if(!salt) {
        NSLog(@"salt must not be NULL");
        if (error) {
            NSDictionary* details = [NSDictionary dictionaryWithObject:ERROR_ENCRYPTING 
                                                                forKey:NSLocalizedDescriptionKey];
            *error = [NSError errorWithDomain:MY_DOMAIN 
                                         code:200 
                                     userInfo:details];
        }
        return nil;
    }
    *iv = [self randomDataOfLength:kAlgorithmIVSize];
    *salt = [self randomDataOfLength:kPBKDFSaltSize];
    
    if(!(*iv) || !(*salt)) {
        NSLog(@"Could not generate random bytes");
        if (error) {
            NSDictionary* details = [NSDictionary dictionaryWithObject:ERROR_ENCRYPTING 
                                                                forKey:NSLocalizedDescriptionKey];
            *error = [NSError errorWithDomain:MY_DOMAIN 
                                         code:200 
                                     userInfo:details];
        }
        return nil;
    }
    
    NSData *key = [self AESKeyForPassword:password salt:*salt];
    
    if( !key ) {
        NSLog(@"Could not create key for password and salt");
        if (error) {
            NSDictionary* details = [NSDictionary dictionaryWithObject:ERROR_ENCRYPTING 
                                                                forKey:NSLocalizedDescriptionKey];
            *error = [NSError errorWithDomain:MY_DOMAIN 
                                         code:200 
                                     userInfo:details];
        }
        return nil;
    }
    
    size_t outLength;
    NSMutableData *cipherData = [NSMutableData dataWithLength:data.length +
                                 kAlgorithmBlockSize];
    
    CCCryptorStatus result = CCCrypt(kCCEncrypt, // operation
                                     kAlgorithm, // Algorithm
                                     kCCOptionPKCS7Padding, // options
                                     key.bytes, // key
                                     key.length, // keylength
                                     (*iv).bytes,// iv
                                     data.bytes, // dataIn
                                     data.length, // dataInLength,
                                     cipherData.mutableBytes, // dataOut
                                     cipherData.length, // dataOutAvailable
                                     &outLength); // dataOutMoved
    
    if (result == kCCSuccess) {
        cipherData.length = outLength;
    }
    else {
        if (error) {
            NSDictionary* details = [NSDictionary dictionaryWithObject:ERROR_ENCRYPTING 
                                                                forKey:NSLocalizedDescriptionKey];
            *error = [NSError errorWithDomain:MY_DOMAIN 
                                         code:200 
                                     userInfo:details];
        }
        return nil;
    }
    
    return cipherData;
}

+ (NSData *)randomDataOfLength:(size_t)length 
{
    NSMutableData *data = [NSMutableData dataWithLength:length];
    
    int result = SecRandomCopyBytes(kSecRandomDefault, length, data.mutableBytes);
    
    if(result == -1) {
        NSLog(@"%@: %d", ERROR_COULD_NOT_CREATE_RANDOM_BYTES, errno);
        return nil;
    }
    
    return data;
}

+ (NSData *)AESKeyForPassword:(NSString *)password 
                         salt:(NSData *)salt 
{
    
    const NSUInteger kAlgorithmKeySize = kCCKeySizeAES128;
    const NSUInteger kPBKDFRounds = 10000;
    
    NSMutableData *derivedKey = [NSMutableData dataWithLength:kAlgorithmKeySize];
    
    int result = CCKeyDerivationPBKDF(kCCPBKDF2,            // algorithm
                                  password.UTF8String,  // password
                                  password.length,  // passwordLength
                                  salt.bytes,           // salt
                                  salt.length,          // saltLen
                                  kCCPRFHmacAlgSHA1,    // PRF
                                  kPBKDFRounds,         // rounds
                                  derivedKey.mutableBytes, // derivedKey
                                  derivedKey.length); // derivedKeyLen
    
    if(result != kCCSuccess) {
        NSLog(@"Unable to create AES key for password: %d", result);
        return nil;
    }
    return derivedKey;
}

+(NSData *)decryptData:(NSData *)data 
              password:(NSString *)password 
                    iv:(NSData *)iv 
                  salt:(NSData *)salt 
                 error:(NSError **)error
{
    NSData *key = [self AESKeyForPassword:password 
                                     salt:salt];
    
    
    const CCAlgorithm kAlgorithm = kCCAlgorithmAES128;
    const NSUInteger kAlgorithmBlockSize = kCCBlockSizeAES128;
    
    NSMutableData *outputData = [NSMutableData dataWithLength:data.length +
                                 kAlgorithmBlockSize];
    
    size_t outLength;
    
    CCCryptorStatus result = CCCrypt(kCCDecrypt, // operation
                                     kAlgorithm, // Algorithm
                                     kCCOptionPKCS7Padding, // options
                                     key.bytes, // key
                                     key.length, // keylength
                                     iv.bytes,// iv
                                     data.bytes, // dataIn
                                     data.length, // dataInLength,
                                     outputData.mutableBytes, // dataOut
                                     outputData.length, // dataOutAvailable
                                     &outLength); // dataOutMoved
    
    if (result == kCCSuccess) {
        outputData.length = outLength;
    }
    else {
        NSLog(@"could not decrypt string.");
        if (error) {
            NSDictionary* details = [NSDictionary dictionaryWithObject:ERROR_DECRYPTING 
                                                                forKey:NSLocalizedDescriptionKey];
            *error = [NSError errorWithDomain:MY_DOMAIN 
                                         code:200 
                                     userInfo:details];
        }
        return nil;
    }
    
    return outputData;
}

+(NSData *)getHMACData:(NSData *)data 
              key:(NSData *)key
{
    NSString *sData = [[NSString alloc] initWithData:data 
                                            encoding:NSASCIIStringEncoding];
    NSString *sKey = [[NSString alloc] initWithData:key 
                                           encoding:NSASCIIStringEncoding];
    
    const char *cKey  = [sKey cStringUsingEncoding:NSUTF8StringEncoding];
    const char *cData = [sData cStringUsingEncoding:NSUTF8StringEncoding];
    
    unsigned char cHMAC[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, cKey, strlen(cKey), cData, strlen(cData), cHMAC);
    
    NSString *hash;
    
    NSMutableString* output = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    
    for(int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++)
        [output appendFormat:@"%02x", cHMAC[i]];
    
    hash = output;
    return [hash dataUsingEncoding:NSUTF8StringEncoding];

}

@end
