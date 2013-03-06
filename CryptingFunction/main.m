//
//  main.m
//  CryptingFunction
//
//  Created by Florian on 28.01.13.
//  Copyright (c) 2013 Florian Killius. All rights reserved.
//

#import "CryptingFunctions.h"
#import <Foundation/Foundation.h>

int main(int argc, const char * argv[])
{

    @autoreleasepool {
        // Example:
        NSString *my_secret_message = [NSString stringWithString:@"our secret string"];
        NSString *password = [NSString stringWithString:@"password"];
        
        
        // SAVE FILE
        
        // we convert our text to a NSData object
        NSData *data = [my_secret_message dataUsingEncoding:NSUTF8StringEncoding];
        
        NSError *error = NULL;
        
        // to save in the resource path of your application bundle use [[NSBundle mainBundle] resourcePath] instead of NSHomeDirectory()
        NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"test.crypting"];
        
        [CryptingFunctions saveFileAtPath:path 
                                     data:data 
                                 password:password 
                                 userInfo:[NSDictionary dictionaryWithObjectsAndKeys:@"test.crypting", @"filename",
                                           @"textfile",@"filetype", nil]
                                    error:&error];
        
        if(error)
            NSLog(@"%@",error.localizedDescription);
        
        NSLog(@"\nfile saved. content: %@", my_secret_message);
        
        
        NSDictionary *userInfo = NULL;
        
        // LOAD FILE
        error = NULL;
        
        NSData *newData = [CryptingFunctions loadEncryptedFileAtPath:path 
                                                            password:password 
                                                            userInfo:&userInfo
                                                               error:&error];
        
        if(error)
        {
            // you can check for specific errors:
            if([error.localizedDescription isEqualToString:ERROR_WRONG_PASSWORD])
                NSLog(@"wrong password");
            
            if([error.localizedDescription isEqualToString:ERROR_FILE_NOT_FOUND_OR_NOT_READABLE])
                NSLog(@"file not found or not readable");
        } 
        
        NSLog(@"\nfile loaded. content: %@", [[NSString alloc] initWithData:newData encoding:NSUTF8StringEncoding]);
        NSLog(@"userInfo: %@", userInfo);
        
    }
    return 0;
}

