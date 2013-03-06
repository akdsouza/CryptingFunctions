//
//  CryptingFunctions.m
//
//  Created by Florian on 25.01.13.
//  Copyright (c) 2013 whateva0x29a. All rights reserved.
//

#define KEY_IV @"key_iv"
#define KEY_SALT @"key_salt"
#define KEY_HMAC @"key_hmac"
#define KEY_ENCRYPTED_DATA @"key_encrypted_data"
#define KEY_USER_INFO @"user_info"

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
             userInfo:(NSDictionary *)userInfo 
                error:(NSError **)error
{
    // we should say something here...
    if( !path || !data || !password )
        return;

    
    NSData *iv;
    NSData *salt;
    NSError *encryptError = NULL;
    
    // encrypt Data
    NSData *encryptedData = [CryptingFunctions encryptData:data 
                                                  password:password 
                                                        iv:&iv 
                                                      salt:&salt 
                                                     error:&encryptError];
    // check for error
    if( encryptError ) 
    {
        if( error )
        {
            NSMutableDictionary* details = [NSMutableDictionary dictionary];
            [details setValue:ERROR_WRITING_FILE 
                       forKey:NSLocalizedDescriptionKey];
            *error = [NSError errorWithDomain:MY_DOMAIN 
                                         code:ERROR_CODE_WRITING_FILE 
                                     userInfo:details];
        }
        else 
        {
#ifdef DEBUG_CRYPTING_FUNCTIONS
            NSLog(@"%@", ERROR_WRITING_FILE);
#endif
        }
        return;
    }
    
    // get HMAC for password check
    NSData *key = [CryptingFunctions AESKeyForPassword:password salt:salt];
    NSData *hmac = [CryptingFunctions getHMACData:data key:key];
    
    NSMutableDictionary *fileData = [NSMutableDictionary dictionaryWithObjectsAndKeys:iv, KEY_IV,
                                     salt, KEY_SALT,
                                     hmac, KEY_HMAC,
                                     encryptedData, KEY_ENCRYPTED_DATA,nil];
    
    if( userInfo )
    {
        [fileData setObject:userInfo forKey:KEY_USER_INFO];
    }
    
    BOOL success = [fileData writeToFile:path 
                              atomically:NO];
    
    if ( !success ) 
    {
        if( error )
        {
            NSDictionary* details = [NSDictionary dictionaryWithObject:ERROR_WRITING_FILE 
                                                                forKey:NSLocalizedDescriptionKey];
            *error = [NSError errorWithDomain:MY_DOMAIN 
                                         code:ERROR_CODE_WRITING_FILE 
                                     userInfo:details];
        }
        else {
#ifdef DEBUG_CRYPTING_FUNCTIONS
            NSLog(@"%@", ERROR_WRITING_FILE);
#endif
        }
    }
}

+ (NSData *)loadEncryptedFileAtPath:(NSString *)path 
                           password:(NSString *)password 
                           userInfo:(NSDictionary **)userInfo 
                              error:(NSError **)error
{
    if( ![[NSFileManager defaultManager] isReadableFileAtPath:path] ) 
    {
        if( error ) 
        {
            NSDictionary* details = [NSDictionary dictionaryWithObject:ERROR_FILE_NOT_FOUND_OR_NOT_READABLE 
                                                                forKey:NSLocalizedDescriptionKey];
            *error = [NSError errorWithDomain:MY_DOMAIN 
                                         code:ERROR_CODE_FILE_NOT_FOUND_OR_NOT_READABLE 
                                     userInfo:details];
        }
        else 
        {
#ifdef DEBUG_CRYPTING_FUNCTIONS
            NSLog(@"%@", ERROR_FILE_NOT_FOUND_OR_NOT_READABLE);
#endif
        }
        return nil;
    }
    
    NSDictionary *fileData = [NSDictionary dictionaryWithContentsOfFile:path];
    
    NSData *iv = [fileData objectForKey:KEY_IV];
    NSData *salt = [fileData objectForKey:KEY_SALT];
    NSData *encryptedData = [fileData objectForKey:KEY_ENCRYPTED_DATA];
    NSData *hmac = [fileData objectForKey:KEY_HMAC];
    NSDictionary *userInfoData = [fileData objectForKey:KEY_USER_INFO];
    
    if( userInfo )
        if( userInfoData )
            *userInfo = [NSDictionary dictionaryWithDictionary:userInfoData];
    
    NSError *decryptionError = NULL;
    
    if( !iv || !salt || !encryptedData || !hmac ) 
    {
        if( error ) 
        {
            NSDictionary* details = [NSDictionary dictionaryWithObject:ERROR_CORRUPTED_FILE_FORMAT 
                                                                forKey:NSLocalizedDescriptionKey];
            *error = [NSError errorWithDomain:MY_DOMAIN 
                                         code:ERROR_CODE_CORRUPTED_FILE_FORMAT 
                                     userInfo:details];
        }
        else 
        {
#ifdef DEBUG_CRYPTING_FUNCTIONS
            NSLog(@"%@", ERROR_CORRUPTED_FILE_FORMAT);
#endif
        }
        return nil;
    }
    
    NSData *decryptedData = [CryptingFunctions decryptData:encryptedData 
                                                  password:password 
                                                        iv:iv 
                                                      salt:salt
                                                     error:&decryptionError];
    
    NSData *key = [CryptingFunctions AESKeyForPassword:password 
                                                  salt:salt];
    NSData *newHmac = [CryptingFunctions getHMACData:decryptedData 
                                                 key:key];
    
    if ( ![newHmac isEqualToData:hmac] )
    {
        if( error ) 
        {
            NSDictionary* details = [NSDictionary dictionaryWithObject:ERROR_WRONG_PASSWORD 
                                                                forKey:NSLocalizedDescriptionKey];
            *error = [NSError errorWithDomain:MY_DOMAIN 
                                         code:ERROR_CODE_WRONG_PASSWORD 
                                     userInfo:details];
        }
        else 
        {
#ifdef DEBUG_CRYPTING_FUNCTIONS
            NSLog(@"%@", ERROR_WRONG_PASSWORD);
#endif
        }
        return nil;
    }
    
    if( decryptionError ) 
    {
        if ( error ) 
        {
            NSDictionary* details = [NSDictionary dictionaryWithObject:ERROR_DECRYPTING 
                                                                forKey:NSLocalizedDescriptionKey];
            *error = [NSError errorWithDomain:MY_DOMAIN 
                                         code:ERROR_CODE_DECRYPTING 
                                     userInfo:details];
        }
        else 
        {
#ifdef DEBUG_CRYPTING_FUNCTIONS
            NSLog(@"%@", ERROR_DECRYPTING);
#endif
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
    
    
    if( !iv ) 
    {
        if( error ) 
        {
            NSDictionary* details = [NSDictionary dictionaryWithObject:ERROR_ENCRYPTING 
                                                                forKey:NSLocalizedDescriptionKey];
            *error = [NSError errorWithDomain:MY_DOMAIN 
                                         code:200 
                                     userInfo:details];
        }
#ifdef DEBUG_CRYPTING_FUNCTIONS
        NSLog(@"IV must not be NULL");
#endif
        return nil;
    }
    if( !salt ) 
    {
        if( error ) 
        {
            NSDictionary* details = [NSDictionary dictionaryWithObject:ERROR_ENCRYPTING 
                                                                forKey:NSLocalizedDescriptionKey];
            *error = [NSError errorWithDomain:MY_DOMAIN 
                                         code:200 
                                     userInfo:details];
        }
#ifdef DEBUG_CRYPTING_FUNCTIONS
        NSLog(@"salt must not be NULL");
#endif
        return nil;
    }
    *iv = [self randomDataOfLength:kAlgorithmIVSize];
    *salt = [self randomDataOfLength:kPBKDFSaltSize];
    
    if(!(*iv) || !(*salt)) 
    {
        if( error ) 
        {
            NSDictionary* details = [NSDictionary dictionaryWithObject:ERROR_ENCRYPTING 
                                                                forKey:NSLocalizedDescriptionKey];
            *error = [NSError errorWithDomain:MY_DOMAIN 
                                         code:200 
                                     userInfo:details];
        }
#ifdef DEBUG_CRYPTING_FUNCTIONS
        NSLog(@"Could not generate random bytes");
#endif
        return nil;
    }
    
    NSData *key = [self AESKeyForPassword:password salt:*salt];
    
    if( !key ) 
    {
        if( error ) 
        {
            NSDictionary* details = [NSDictionary dictionaryWithObject:ERROR_ENCRYPTING 
                                                                forKey:NSLocalizedDescriptionKey];
            *error = [NSError errorWithDomain:MY_DOMAIN 
                                         code:200 
                                     userInfo:details];
        }
#ifdef DEBUG_CRYPTING_FUNCTIONS
        NSLog(@"Could not create key for password and salt");
#endif
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
    
    if( result == kCCSuccess ) 
    {
        cipherData.length = outLength;
    }
    else 
    {
        if( error ) 
        {
            NSDictionary* details = [NSDictionary dictionaryWithObject:ERROR_ENCRYPTING 
                                                                forKey:NSLocalizedDescriptionKey];
            *error = [NSError errorWithDomain:MY_DOMAIN 
                                         code:ERROR_CODE_ENCRYPTING 
                                     userInfo:details];
        }
        else 
        {
#ifdef DEBUG_CRYPTING_FUNCTIONS
            NSLog(@"%@", ERROR_ENCRYPTING);
#endif
        }
        return nil;
    }
    
    return cipherData;
}

+ (NSData *)randomDataOfLength:(size_t)length 
{
    NSMutableData *data = [NSMutableData dataWithLength:length];
    
    int result = SecRandomCopyBytes(kSecRandomDefault, length, data.mutableBytes);
    
    if( result == -1 ) 
    {
#ifdef DEBUG_CRYPTING_FUNCTIONS
        NSLog(@"%@: %d", ERROR_COULD_NOT_CREATE_RANDOM_BYTES, errno);
#endif
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
    
    if( result != kCCSuccess ) 
    {
#ifdef DEBUG_CRYPTING_FUNCTIONS
        NSLog(@"Unable to create AES key for password: %d", result);
#endif
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
    
    if( result == kCCSuccess ) 
    {
        outputData.length = outLength;
    }
    else 
    {
        if ( error ) 
        {
            NSDictionary* details = [NSDictionary dictionaryWithObject:ERROR_DECRYPTING 
                                                                forKey:NSLocalizedDescriptionKey];
            *error = [NSError errorWithDomain:MY_DOMAIN 
                                         code:ERROR_CODE_DECRYPTING 
                                     userInfo:details];
        }
        else 
        {
#ifdef DEBUG_CRYPTING_FUNCTIONS
            NSLog(@"%@", ERROR_DECRYPTING);
#endif
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
