//
//  PhFacebook.m
//  PhFacebook
//
//  Created by Philippe on 10-08-25.
//  Copyright 2010 Philippe Casgrain. All rights reserved.
//

#import "PhFacebook.h"
#import "PhWebViewController.h"
#import "PhAuthenticationToken.h"
#import "PhFacebook_URLs.h"
#import "Debug.h"

#define kFBStoreAccessToken @"FBAStoreccessToken"
#define kFBStoreTokenExpiry @"FBStoreTokenExpiry"
#define kFBStoreAccessPermissions @"FBStoreAccessPermissions"

static NSString* kStringBoundary = @"3i2ndDfv2rTHiSisAbouNdArYfORhtTPEefj3q2f";

@implementation PhFacebook

#pragma mark Initialization

- (id) initWithApplicationID: (NSString*) appID delegate: (id) delegate
{
    if ((self = [super init]))
    {
        if (appID)
            _appID = [[NSString stringWithString: appID] retain];
        _delegate = delegate; // Don't retain delegate to avoid retain cycles
        _webViewController = nil;
        _authToken = nil;
        _permissions = nil;
        DebugLog(@"Initialized with AppID '%@'", _appID);
    }

    return self;
}

- (void) dealloc
{
    [_appID release];
    [_webViewController release];
    [_authToken release];
    [super dealloc];
}

- (void) notifyDelegateForToken: (PhAuthenticationToken*) token withError: (NSString*) errorReason
{
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    if (token)
    {
        // Save it to user defaults
        NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
        [defaults setObject: token.authenticationToken forKey: kFBStoreAccessToken];
        if (token.expiry)
            [defaults setObject: token.expiry forKey: kFBStoreTokenExpiry];
        else
            [defaults removeObjectForKey: kFBStoreTokenExpiry];
        [defaults setObject: token.permissions forKey: kFBStoreAccessPermissions];
        [defaults synchronize];
        
        [result setObject: [NSNumber numberWithBool: YES] forKey: @"valid"];
    }
    else
    {
        [result setObject: [NSNumber numberWithBool: NO] forKey: @"valid"];
        [result setObject: errorReason forKey: @"error"];
    }

    if ([_delegate respondsToSelector: @selector(tokenResult:)])
        [_delegate tokenResult: result];
}

#pragma mark Access

- (void)clearToken
{
    [_authToken release];
    _authToken = nil;
}

+ (NSString*)urlencodedString:(NSString*)s {
	NSString* result = (NSString *)CFURLCreateStringByAddingPercentEscapes(NULL,
																		   (CFStringRef)s,
																		   NULL,
																		   (CFStringRef)@"!*'();:@&=+$,/?%#[]",
																		   kCFStringEncodingUTF8);
	return [result autorelease];
}

+ (void)invalidateCachedToken
{
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    
    [defaults removeObjectForKey:kFBStoreAccessToken];
    [defaults removeObjectForKey: kFBStoreTokenExpiry];
    [defaults removeObjectForKey: kFBStoreAccessPermissions];
    [defaults synchronize];
    
    NSHTTPCookieStorage* cookies = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    NSArray* facebookCookies = [cookies cookiesForURL:
                                [NSURL URLWithString:@"http://login.facebook.com"]];
    
    for (NSHTTPCookie* cookie in facebookCookies) {
        [cookies deleteCookie:cookie];
    }
}

+ (BOOL)hasStoredCachedToken {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    return [defaults stringForKey:kFBStoreAccessToken] != nil 
        || [defaults objectForKey:kFBStoreTokenExpiry] != nil 
        || [defaults stringForKey:kFBStoreAccessPermissions] != nil;
}

- (void)invalidateCachedToken
{
    [self clearToken];
    [PhFacebook invalidateCachedToken];
}

- (void) setAccessToken: (NSString*) accessToken expires: (NSTimeInterval) tokenExpires permissions: (NSString*) perms
{
    [self clearToken];

    if (accessToken)
        _authToken = [[PhAuthenticationToken alloc] initWithToken: accessToken secondsToExpiry: tokenExpires permissions: perms];
}

- (void) getAccessTokenForPermissions: (NSArray*) permissions cached: (BOOL) canCache
{
    BOOL validToken = NO;
    NSString *scope = [permissions componentsJoinedByString: @","];

    if (canCache && _authToken == nil)
    {
        NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
        NSString *accessToken = [defaults stringForKey: kFBStoreAccessToken];
        NSDate *date = [defaults objectForKey: kFBStoreTokenExpiry];
        NSString *perms = [defaults stringForKey: kFBStoreAccessPermissions];
        if (accessToken && perms)
        {
            // Do not notify delegate yet...
            [self setAccessToken: accessToken expires: [date timeIntervalSinceNow] permissions: perms];
        }
    }

    if ([_authToken.permissions isCaseInsensitiveLike: scope])
    {
        // We already have a token for these permissions; check if it has expired or not
        if (_authToken.expiry == nil || [[_authToken.expiry laterDate: [NSDate date]] isEqual: _authToken.expiry])
            validToken = YES;
    }

    if (validToken)
    {
        [self notifyDelegateForToken: _authToken withError: nil];
    }
    else
    {
        [self clearToken];

        // Use _webViewController to request a new token
        NSString *authURL;
        if (scope)
            authURL = [NSString stringWithFormat: kFBAuthorizeWithScopeURL, _appID, kFBLoginSuccessURL, scope];
        else
            authURL = [NSString stringWithFormat: kFBAuthorizeURL, _appID, kFBLoginSuccessURL];
      
        if ([_delegate respondsToSelector: @selector(needsAuthentication:forPermissions:)]) 
        {
            if ([_delegate needsAuthentication: authURL forPermissions: scope]) 
            {
                // If needsAuthentication returns YES, let the delegate handle the authentication UI
                return;
            }
        }
      
        // Retrieve token from web page
        if (_webViewController == nil)
        {
            _webViewController = [[PhWebViewController alloc] init];
            [NSBundle loadNibNamed: @"FacebookBrowser" owner: _webViewController];
        }

        // Prepare window but keep it ordered out. The _webViewController will make it visible
        // if it needs to.
        _webViewController.parent = self;
        _webViewController.permissions = scope;
        [_webViewController.webView setMainFrameURL: authURL];
    }
}

- (void) setAccessToken: (NSString*) accessToken expires: (NSTimeInterval) tokenExpires permissions: (NSString*) perms error: (NSString*) errorReason
{
	[self setAccessToken: accessToken expires: tokenExpires permissions: perms];
	[self notifyDelegateForToken: _authToken withError: errorReason];
}

- (NSString*) accessToken
{
    return [[_authToken.authenticationToken copy] autorelease];
}

- (void)utfAppendBody:(NSMutableData *)body data:(NSString *)data {
    [body appendData:[data dataUsingEncoding:NSUTF8StringEncoding]];
}

- (void) sendFacebookRequest: (NSDictionary*) allParams
{
    NSAutoreleasePool *pool = [NSAutoreleasePool new];

    if (_authToken)
    {
        NSString *request = [allParams objectForKey: @"request"];
        NSString *str;
        BOOL postRequest = [[allParams objectForKey: @"postRequest"] boolValue];
                
        if (postRequest)
            str = [NSString stringWithFormat: kFBGraphApiPostURL, request];
        else
            str = [NSString stringWithFormat: kFBGraphApiGetURL, request, _authToken.authenticationToken];

        
        NSDictionary *params = [allParams objectForKey: @"params"];
        NSMutableData *postParams = [NSMutableData data];
        
        
        if (params != nil) 
        {
            if (postRequest)
            {
                NSString *endLine = [NSString stringWithFormat:@"\r\n--%@\r\n", kStringBoundary];
                
                // Start of post body
                [self utfAppendBody:postParams data:[NSString stringWithFormat:@"--%@\r\n", kStringBoundary]];
                
                // Auth Token
                [self utfAppendBody:postParams
                               data:[NSString
                                     stringWithFormat:@"Content-Disposition: form-data; name=\"%@\"\r\n\r\n",
                                     @"access_token"]];
                [self utfAppendBody:postParams data:_authToken.authenticationToken];
                [self utfAppendBody:postParams data:endLine];
                
                for (NSString *p in [params allKeys]) {
                    id dataParam = [params objectForKey:p];
                    if ([dataParam isKindOfClass:[NSImage class]]) {
                        // Image
                        NSBitmapImageRep *bitmap = [[(NSImage*)dataParam representations] objectAtIndex:0];
                        NSData* imageData = [bitmap representationUsingType:NSPNGFileType properties: nil];
                        [self utfAppendBody:postParams
                                       data:[NSString stringWithFormat:
                                             @"Content-Disposition: form-data; filename=\"%@\"\r\n", p]];
                        [self utfAppendBody:postParams
                                       data:[NSString stringWithString:@"Content-Type: image/png\r\n\r\n"]];
                        [postParams appendData:imageData];
                        [self utfAppendBody:postParams data:endLine];
                    } 
                    else {
                        //[postParams appendData:[[NSString stringWithFormat:@"&%@=%@", p, dataParam] dataUsingEncoding:NSUTF8StringEncoding]];
                        [self utfAppendBody:postParams
                                       data:[NSString
                                             stringWithFormat:@"Content-Disposition: form-data; name=\"%@\"\r\n\r\n",
                                             p]];
                        [self utfAppendBody:postParams data:dataParam];
                        [self utfAppendBody:postParams data:endLine];
                    }
                }
            }
            else
            {
                NSMutableString *strWithParams = [NSMutableString stringWithString: str];
                for (NSString *p in [params allKeys]) 
                    [strWithParams appendFormat: @"&%@=%@", p, [params objectForKey: p]];
                str = strWithParams;
            }
        }
        
        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL: [NSURL URLWithString: str]];
        
        if (postRequest)
        {
            [req setHTTPMethod: @"POST"];
            [req setHTTPBody: postParams];
            [req setValue: @"application/x-www-form-urlencoded" forHTTPHeaderField: @"content-type"];
            NSString* contentType = [NSString
                                     stringWithFormat:@"multipart/form-data; boundary=%@", kStringBoundary];
            [req setValue:contentType forHTTPHeaderField:@"Content-Type"];
        }
        
        NSURLResponse *response = nil;
        NSError *error = nil;
        NSData *data = [NSURLConnection sendSynchronousRequest: req returningResponse: &response error: &error];

        if ([_delegate respondsToSelector: @selector(requestResult:)])
        {
            NSString *str = [[NSString alloc] initWithBytesNoCopy: (void*)[data bytes] length: [data length] encoding:NSASCIIStringEncoding freeWhenDone: NO];

            NSDictionary *result = [NSDictionary dictionaryWithObjectsAndKeys:
                str, @"result",
                request, @"request",
                data, @"raw",                                    
                self, @"sender",
                nil];
            [_delegate performSelectorOnMainThread:@selector(requestResult:) withObject: result waitUntilDone:YES];
            [str release];
        }
    }
    [pool drain];
}

- (void) sendRequest: (NSString*) request params: (NSDictionary*) params usePostRequest: (BOOL) postRequest
{
    NSMutableDictionary *allParams = [NSMutableDictionary dictionaryWithObject: request forKey: @"request"];
    if (params != nil)
        [allParams setObject: params forKey: @"params"];
        
    [allParams setObject: [NSNumber numberWithBool: postRequest] forKey: @"postRequest"];

	[NSThread detachNewThreadSelector: @selector(sendFacebookRequest:) toTarget: self withObject: allParams];    
}

- (void) sendRequest: (NSString*) request
{
    [self sendRequest: request params: nil usePostRequest: NO];
}

#pragma mark Notifications

- (void) webViewWillShowUI
{
    if ([_delegate respondsToSelector: @selector(willShowUINotification:)])
        [_delegate performSelectorOnMainThread: @selector(willShowUINotification:) withObject: self waitUntilDone: YES];
}

- (void) didDismissUI
{
    if ([_delegate respondsToSelector: @selector(didDismissUI:)])
        [_delegate performSelectorOnMainThread: @selector(didDismissUI:) withObject: self waitUntilDone: YES];
}

@end
