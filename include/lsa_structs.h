/*
 * lsa_structs.h - Undocumented LSA structures not in MinGW headers
 * 
 * Based on reverse engineering from LSA Whisperer (MIT License)
 * by Evan McBroom / SpecterOps
 *
 * Standard LSA/Kerberos types (LSA_UNICODE_STRING, LSA_STRING,
 * SecHandle, KERB_*, MSV1_0_PROTOCOL_MESSAGE_TYPE, etc.) are
 * already provided by MinGW's <ntsecapi.h> which is pulled in
 * via bofdefs.h -> winternl.h. This file only defines types
 * that are NOT in the system headers.
 *
 * Adapted for Adaptix C2 BOF compatibility.
 */
#pragma once

#include <windows.h>
#include <ntsecapi.h>

/* ============================================================
 * Package name strings (may not be in all MinGW versions)
 * ============================================================ */

#ifndef MSV1_0_PACKAGE_NAME
#define MSV1_0_PACKAGE_NAME     "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"
#endif
#ifndef KERBEROS_PACKAGE_NAME
#define KERBEROS_PACKAGE_NAME   "Kerberos"
#endif
#ifndef NEGOTIATE_PACKAGE_NAME
#define NEGOTIATE_PACKAGE_NAME  "Negotiate"
#endif
#define CLOUDAP_PACKAGE_NAME    "CloudAP"
#define SCHANNEL_PACKAGE_NAME   "Schannel"
#define PKU2U_PACKAGE_NAME      "pku2u"
#define NEGOEXTS_PACKAGE_NAME   "NegoExtender"
#define LIVESSP_PACKAGE_NAME    "LiveSSP"

/* ============================================================
 * MSV1_0 extended enum values (beyond MinGW's definition)
 * MinGW defines up to MsV1_0ProvisionTbal. We add the rest.
 * ============================================================ */

#ifndef MsV1_0DeleteTbalSecret
#define MsV1_0DeleteTbalSecret  24
#endif

/* ============================================================
 * MSV1_0 - Undocumented request/response structures
 * ============================================================ */

#ifndef MSV1_0_SHA_PASSWORD_LENGTH
#define MSV1_0_SHA_PASSWORD_LENGTH    20
#endif
#ifndef MSV1_0_OWF_PASSWORD_LENGTH
#define MSV1_0_OWF_PASSWORD_LENGTH    16
#endif
#ifndef MSV1_0_CREDENTIAL_KEY_LENGTH
#define MSV1_0_CREDENTIAL_KEY_LENGTH  20
#endif

typedef struct _MSV1_0_GETCREDENTIALKEY_REQUEST {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    LUID LogonId;
    UCHAR Reserved[16];
} MSV1_0_GETCREDENTIALKEY_REQUEST, *PMSV1_0_GETCREDENTIALKEY_REQUEST;

typedef struct _MSV1_0_GETCREDENTIALKEY_RESPONSE {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    UCHAR Reserved[16];
    DWORD CredSize;
    UCHAR ShaPassword[MSV1_0_SHA_PASSWORD_LENGTH];
    UCHAR Key2[20];
} MSV1_0_GETCREDENTIALKEY_RESPONSE, *PMSV1_0_GETCREDENTIALKEY_RESPONSE;

typedef struct _MSV1_0_GETSTRONGCREDENTIALKEY_REQUEST {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    DWORD Version;
    DWORD Reserved[8];
    LUID LogonId;
    DWORD KeyType;
    DWORD KeyLength;
    PVOID Key;
    DWORD SidLength;
    PVOID Sid;
    DWORD IsProtectedUser;
} MSV1_0_GETSTRONGCREDENTIALKEY_REQUEST, *PMSV1_0_GETSTRONGCREDENTIALKEY_REQUEST;

#ifndef MSV1_0_RETURN_PASSWORD_EXPIRY
#define MSV1_0_RETURN_PASSWORD_EXPIRY     0x00000040
#endif
#ifndef MSV1_0_USE_CLIENT_CHALLENGE
#define MSV1_0_USE_CLIENT_CHALLENGE       0x00000080
#endif
#ifndef MSV1_0_RETURN_PROFILE_PATH
#define MSV1_0_RETURN_PROFILE_PATH        0x00000200
#endif
#ifndef MSV1_0_DISABLE_PERSONAL_FALLBACK
#define MSV1_0_DISABLE_PERSONAL_FALLBACK  0x00001000
#endif

/* Custom named variants to avoid potential conflicts with system MSV1_0_LM20 types */
typedef struct _MSV1_0_LM20_CHALLENGE_REQUEST_LSA {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
} MSV1_0_LM20_CHALLENGE_REQUEST_LSA;

typedef struct _MSV1_0_LM20_CHALLENGE_RESPONSE_REQ_LSA {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    ULONG ParameterControl;
    LUID LogonId;
    UNICODE_STRING Password;
    UCHAR ChallengeToClient[8];
} MSV1_0_LM20_CHALLENGE_RESPONSE_REQ_LSA;

typedef struct _STRING32 {
    USHORT Length;
    USHORT MaximumLength;
    ULONG  Buffer;
} STRING32;

typedef struct _MSV1_0_LM20_CHALLENGE_RESPONSE_RESP_LSA {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    STRING32 CaseSensitiveChallengeResponse;
    STRING32 CaseInsensitiveChallengeResponse;
    UNICODE_STRING UserName;
    UNICODE_STRING LogonDomainName;
    UNICODE_STRING UserParameters;
} MSV1_0_LM20_CHALLENGE_RESPONSE_RESP_LSA;

/* ============================================================
 * KERBEROS extended enum values (beyond MinGW's definition)
 * MinGW defines up to KerbRetrieveKeyTabMessage. We add the rest.
 * ============================================================ */

#ifndef KerbRefreshPolicyMessage
#define KerbRefreshPolicyMessage            35
#endif
#ifndef KerbPrintCloudKerberosDebugMessage
#define KerbPrintCloudKerberosDebugMessage   36
#endif

/* ============================================================
 * KERBEROS - Additional defines (guarded)
 * ============================================================ */

#ifndef KERB_ETYPE_DES_CBC_CRC
#define KERB_ETYPE_DES_CBC_CRC          0x0001
#endif
#ifndef KERB_ETYPE_DES_CBC_MD5
#define KERB_ETYPE_DES_CBC_MD5          0x0003
#endif
#ifndef KERB_ETYPE_AES128_CTS_HMAC_SHA1
#define KERB_ETYPE_AES128_CTS_HMAC_SHA1 0x0011
#endif
#ifndef KERB_ETYPE_AES256_CTS_HMAC_SHA1
#define KERB_ETYPE_AES256_CTS_HMAC_SHA1 0x0012
#endif
#ifndef KERB_ETYPE_RC4_HMAC_NT
#define KERB_ETYPE_RC4_HMAC_NT          0x0017
#endif
#ifndef KERB_ETYPE_RC4_HMAC_NT_EXP
#define KERB_ETYPE_RC4_HMAC_NT_EXP      0x0018
#endif

#ifndef KERB_TICKET_FLAGS_forwardable
#define KERB_TICKET_FLAGS_forwardable     0x40000000
#endif
#ifndef KERB_TICKET_FLAGS_forwarded
#define KERB_TICKET_FLAGS_forwarded       0x20000000
#endif
#ifndef KERB_TICKET_FLAGS_proxiable
#define KERB_TICKET_FLAGS_proxiable       0x10000000
#endif
#ifndef KERB_TICKET_FLAGS_proxy
#define KERB_TICKET_FLAGS_proxy           0x08000000
#endif
#ifndef KERB_TICKET_FLAGS_may_postdate
#define KERB_TICKET_FLAGS_may_postdate    0x04000000
#endif
#ifndef KERB_TICKET_FLAGS_postdated
#define KERB_TICKET_FLAGS_postdated       0x02000000
#endif
#ifndef KERB_TICKET_FLAGS_invalid
#define KERB_TICKET_FLAGS_invalid         0x01000000
#endif
#ifndef KERB_TICKET_FLAGS_renewable
#define KERB_TICKET_FLAGS_renewable       0x00800000
#endif
#ifndef KERB_TICKET_FLAGS_initial
#define KERB_TICKET_FLAGS_initial         0x00400000
#endif
#ifndef KERB_TICKET_FLAGS_pre_authent
#define KERB_TICKET_FLAGS_pre_authent     0x00200000
#endif
#ifndef KERB_TICKET_FLAGS_hw_authent
#define KERB_TICKET_FLAGS_hw_authent      0x00100000
#endif
#ifndef KERB_TICKET_FLAGS_ok_as_delegate
#define KERB_TICKET_FLAGS_ok_as_delegate  0x00040000
#endif
#ifndef KERB_TICKET_FLAGS_name_canonicalize
#define KERB_TICKET_FLAGS_name_canonicalize 0x00010000
#endif

#ifndef KERB_RETRIEVE_TICKET_DEFAULT
#define KERB_RETRIEVE_TICKET_DEFAULT        0x0
#endif
#ifndef KERB_RETRIEVE_TICKET_DONT_USE_CACHE
#define KERB_RETRIEVE_TICKET_DONT_USE_CACHE 0x1
#endif
#ifndef KERB_RETRIEVE_TICKET_USE_CACHE_ONLY
#define KERB_RETRIEVE_TICKET_USE_CACHE_ONLY 0x2
#endif
#ifndef KERB_RETRIEVE_TICKET_USE_CREDHANDLE
#define KERB_RETRIEVE_TICKET_USE_CREDHANDLE 0x4
#endif
#ifndef KERB_RETRIEVE_TICKET_AS_KERB_CRED
#define KERB_RETRIEVE_TICKET_AS_KERB_CRED   0x8
#endif
#ifndef KERB_RETRIEVE_TICKET_WITH_SEC_CRED
#define KERB_RETRIEVE_TICKET_WITH_SEC_CRED  0x10
#endif
#ifndef KERB_RETRIEVE_TICKET_CACHE_TICKET
#define KERB_RETRIEVE_TICKET_CACHE_TICKET   0x20
#endif
#ifndef KERB_RETRIEVE_TICKET_MAX_LIFETIME
#define KERB_RETRIEVE_TICKET_MAX_LIFETIME   0x40
#endif

/* ============================================================
 * CLOUDAP - Cloud Authentication Package (Undocumented)
 * ============================================================ */

typedef enum _CLOUDAP_CALL_ID {
    CloudApDisableOptimizedLogon = 0,
    CloudApGenARSOPwd = 1,
    CloudApGetAuthenticatingProvider = 2,
    CloudApGetDpApiCredKeyDecryptStatus = 3,
    CloudApGetPwdExpiryInfo = 4,
    CloudApGetTokenBlob = 5,
    CloudApGetUnlockKeyType = 6,
    CloudApIsCloudToOnPremTgtPresentInCache = 7,
    CloudApPluginCall = 8,
    CloudApRefreshTokenBlob = 9,
    CloudApRenewableRetrievePrt = 10,
    CloudApSetTestParas = 11,
    CloudApTransferCreds = 12,
} CLOUDAP_CALL_ID;

typedef enum _AAD_PLUGIN_CALL_ID {
    AadCreateDeviceSSOCookie = 0,
    AadCreateEnterpriseSSOCookie = 1,
    AadCreateSSOCookie = 2,
    AadDeviceValidityCheck = 3,
    AadGenerateBindingClaims = 4,
    AadGetAccountInfo = 5,
    AadGetPrtAuthority = 6,
    AadGetSSOData = 7,
    AadRefreshP2PCACert = 8,
    AadSignPayload = 9,
} AAD_PLUGIN_CALL_ID;

static const GUID GUID_PLUGIN_AAD = {
    0xB16898C6, 0xA148, 0x4967,
    { 0x91, 0x71, 0x64, 0xD7, 0x55, 0xDA, 0x85, 0x20 }
};

static const GUID GUID_PLUGIN_MSA = {
    0xD7F9888F, 0xE3FC, 0x49B0,
    { 0x9E, 0xA6, 0xA8, 0x5B, 0x5F, 0x39, 0x2A, 0x4F }
};

typedef struct _CLOUDAP_REQUEST_HEADER {
    ULONG dwCallId;
    LUID  LogonId;
} CLOUDAP_REQUEST_HEADER, *PCLOUDAP_REQUEST_HEADER;

typedef struct _CLOUDAP_PLUGIN_CALL_REQUEST {
    ULONG dwCallId;
    LUID  LogonId;
    GUID  PluginId;
    ULONG dwPluginCallId;
    ULONG cbPluginInput;
} CLOUDAP_PLUGIN_CALL_REQUEST, *PCLOUDAP_PLUGIN_CALL_REQUEST;

typedef struct _CLOUDAP_GET_AUTH_PROVIDER_RESPONSE {
    ULONG dwCallId;
    GUID  ProviderGuid;
} CLOUDAP_GET_AUTH_PROVIDER_RESPONSE;

typedef struct _CLOUDAP_CLOUD_TGT_RESPONSE {
    ULONG dwCallId;
    BOOL  bIsPresent;
} CLOUDAP_CLOUD_TGT_RESPONSE;

typedef struct _CLOUDAP_DPAPI_STATUS_RESPONSE {
    ULONG dwCallId;
    BOOL  bIsDecrypted;
} CLOUDAP_DPAPI_STATUS_RESPONSE;

typedef struct _AAD_SSO_COOKIE_RESPONSE {
    ULONG cbCookieLength;
} AAD_SSO_COOKIE_RESPONSE;

/* ============================================================
 * SECURITY_LOGON_SESSION_DATA (custom variant)
 * We use a renamed version to avoid potential conflicts with
 * system definitions that may have different field layouts.
 * ============================================================ */

typedef struct _SECURITY_LOGON_SESSION_DATA_LSA {
    ULONG               Size;
    LUID                LogonId;
    LSA_UNICODE_STRING  UserName;
    LSA_UNICODE_STRING  LogonDomain;
    LSA_UNICODE_STRING  AuthenticationPackage;
    ULONG               LogonType;
    ULONG               Session;
    PSID                Sid;
    LARGE_INTEGER       LogonTime;
    LSA_UNICODE_STRING  LogonServer;
    LSA_UNICODE_STRING  DnsDomainName;
    LSA_UNICODE_STRING  Upn;
    ULONG               UserFlags;
    LSA_LAST_INTER_LOGON_INFO LastLogonInfo;
    LSA_UNICODE_STRING  LogonScript;
    LSA_UNICODE_STRING  ProfilePath;
    LSA_UNICODE_STRING  HomeDirectory;
    LSA_UNICODE_STRING  HomeDirectoryDrive;
    LARGE_INTEGER       LogoffTime;
    LARGE_INTEGER       KickOffTime;
    LARGE_INTEGER       PasswordLastSet;
    LARGE_INTEGER       PasswordCanChange;
    LARGE_INTEGER       PasswordMustChange;
} SECURITY_LOGON_SESSION_DATA_LSA, *PSECURITY_LOGON_SESSION_DATA_LSA;

/* Logon types */
#ifndef LOGON_TYPE_INTERACTIVE
#define LOGON_TYPE_INTERACTIVE        2
#define LOGON_TYPE_NETWORK            3
#define LOGON_TYPE_BATCH              4
#define LOGON_TYPE_SERVICE            5
#define LOGON_TYPE_UNLOCK             7
#define LOGON_TYPE_NETWORK_CLEARTEXT  8
#define LOGON_TYPE_NEW_CREDENTIALS    9
#define LOGON_TYPE_REMOTE_INTERACTIVE 10
#define LOGON_TYPE_CACHED_INTERACTIVE 11
#define LOGON_TYPE_CACHED_REMOTE_INTERACTIVE 12
#define LOGON_TYPE_CACHED_UNLOCK      13
#endif
