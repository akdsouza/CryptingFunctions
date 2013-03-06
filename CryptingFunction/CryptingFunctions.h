//
//  CryptingFunctions.h
//
//  Created by Florian on 25.01.13.
//  Copyright (c) 2013 whateva0x29a. All rights reserved.
//

// Simple class for encrypting and decrypting data, check if password is correct and save that data in a xml(/plist)-like file

// include following frameworks:
//
// Security.framework
// libcommonCrypto.dylib

// CryptingFunctions V1.0.1



#define ERROR_ENCRYPTING @"Could not encrypt data."
#define ERROR_CODE_ENCRYPTING 201
#define ERROR_WRITING_FILE @"Could not write file."
#define ERROR_CODE_WRITING_FILE 202

#define ERROR_WRONG_PASSWORD @"Wrong password."
#define ERROR_CODE_WRONG_PASSWORD 200
#define ERROR_FILE_NOT_FOUND_OR_NOT_READABLE @"File not found or not readable."
#define ERROR_CODE_FILE_NOT_FOUND_OR_NOT_READABLE 300
#define ERROR_CORRUPTED_FILE_FORMAT @"Corrupted file format."
#define ERROR_CODE_CORRUPTED_FILE_FORMAT 301
#define ERROR_DECRYPTING @"Could not decrypt data."
#define ERROR_CODE_DECRYPTING 302

#define ERROR_COULD_NOT_CREATE_RANDOM_BYTES @"Could not create random bytes."


#define DEBUG_CRYPTING_FUNCTIONS


#import <Foundation/Foundation.h>

@interface CryptingFunctions : NSObject

// easy to use crypting functions to save and load data 


+ (void)saveFileAtPath:(NSString *)path // path where to save the file
                  data:(NSData *)data // main data, that will be encrypted
              password:(NSString *)password // password to user
              userInfo:(NSDictionary *)userInfo // other data to save in file (unencrypted), e.g. data type
                 error:(NSError **)error;


// If you have a big file and/or the user have to enter the password, don't use this method, if you have to call it more than once because the password is wrong this function will always reload the data into memory, instead you should load the data once and then hold it until the user enters the correct password (look into this method for reference on how to do so)
+ (NSData *)loadEncryptedFileAtPath:(NSString *)path // path where the file (should) be
                           password:(NSString *)password // password to use
                           userInfo:(NSDictionary **)userInfo // other data in loaded file (see above, userInfo)
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
