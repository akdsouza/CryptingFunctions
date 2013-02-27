//
//  CryptingFunctions.h
//
//  Created by Florian on 25.01.13.
//  Copyright (c) 2013 Florian Killius. All rights reserved.
//

// Simple class for encrypting and decrypting data, check if password is correct and save that data in a xml(/plist)-like file

// use with following frameworks:
//
// Security.framework
// libcommonCrypto.dylib



#define ERROR_WRONG_PASSWORD @"Wrong password."
#define ERROR_ENCRYPTING @"Could not encrypt data."
#define ERROR_WRITING_FILE @"Could not write file."

#define ERROR_FILE_NOT_FOUND_OR_NOT_READABLE @"File not found or not readable."
#define ERROR_CORRUPTED_FILE_FORMAT @"Corrupted file format."
#define ERROR_DECRYPTING @"Could not decrypt data."

#define ERROR_COULD_NOT_CREATE_RANDOM_BYTES @"Could not create random bytes."



#import <Foundation/Foundation.h>

@interface CryptingFunctions : NSObject

// easy to use crypting functions to save and load data 

+ (void)saveFileAtPath:(NSString *)path
                  data:(NSData *)data
              password:(NSString *)password
                 error:(NSError **)error;

// If you have a big file and/or the user have to enter the password, don't use this method, if you have to call it more than once because the password is wrong this function will always reload the data into memory, instead you should load the data once and then hold it until the user enters the correct password (look into this method for reference on how to do so)
+ (NSData *)loadEncryptedFileAtPath:(NSString *)path 
                           password:(NSString *)password 
                              error:(NSError **)error;


// Generic functions to encrypt and decrypt data

// mostly from http://robnapier.net/blog/aes-commoncrypto-564 

// returns the encrypted data, returns nil on error
// iv and salt have to be existing (empty) variables, save them with the enrcypted data, because you will need them to decrypt the data
// error can be nil
+ (NSData *)encryptData:(NSData *)data
               password:(NSString *)password
                     iv:(NSData **)iv
                   salt:(NSData **)salt
                  error:(NSError **)error;

// returns the decrypted data, returns nil on error
// error can be nil
+ (NSData *)decryptData:(NSData *)data 
               password:(NSString *)password
                     iv:(NSData *)iv
                   salt:(NSData *)salt 
                  error:(NSError **)error;

// only for encryptedData:password:iv:salt:error: and decryptData:password:iv:salt:error:
+ (NSData *)randomDataOfLength:(size_t)length;

// only for encryptedData:password:iv:salt:error: and decryptData:password:iv:salt:error:
+ (NSData *)AESKeyForPassword:(NSString *)password 
                         salt:(NSData *)salt;


// use this to check if a certain password is correct
// see http://en.wikipedia.org/wiki/Hash-based_message_authentication_code
// see also encryptedData:password:iv:salt:error: and decryptData:password:iv:salt:error: to understand how to use this method
+ (NSData *)getHMACData:(NSData *)data
                    key:(NSData *)key;

@end
