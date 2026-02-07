#include <windows.h>
#include <stdio.h>
#include <activeds.h>
#include <dsgetdc.h>
#include <lm.h>

#pragma comment(lib, "activeds.lib")
#pragma comment(lib, "adsiid.lib")
#pragma comment(lib, "netapi32.lib")

// Convert FILETIME to readable string
void FileTimeToString(LARGE_INTEGER* pLargeInt, WCHAR* buffer, size_t bufSize) {
    if (pLargeInt->QuadPart == 0) {
        wcscpy_s(buffer, bufSize, L"Never");
        return;
    }

    FILETIME ft;
    ft.dwLowDateTime = pLargeInt->LowPart;
    ft.dwHighDateTime = pLargeInt->HighPart;

    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);
    swprintf_s(buffer, bufSize, L"%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

// Decode userAccountControl flags
void DecodeUAC(DWORD uac) {
    printf("  userAccountControl flags: 0x%X\n", uac);
    if (uac & 0x0001) printf("    - SCRIPT\n");
    if (uac & 0x0002) printf("    - ACCOUNTDISABLE\n");
    if (uac & 0x0008) printf("    - HOMEDIR_REQUIRED\n");
    if (uac & 0x0010) printf("    - LOCKOUT\n");
    if (uac & 0x0020) printf("    - PASSWD_NOTREQD\n");
    if (uac & 0x0040) printf("    - PASSWD_CANT_CHANGE\n");
    if (uac & 0x0080) printf("    - ENCRYPTED_TEXT_PWD_ALLOWED\n");
    if (uac & 0x0100) printf("    - TEMP_DUPLICATE_ACCOUNT\n");
    if (uac & 0x0200) printf("    - NORMAL_ACCOUNT\n");
    if (uac & 0x0800) printf("    - INTERDOMAIN_TRUST_ACCOUNT\n");
    if (uac & 0x1000) printf("    - WORKSTATION_TRUST_ACCOUNT\n");
    if (uac & 0x2000) printf("    - SERVER_TRUST_ACCOUNT\n");
    if (uac & 0x10000) printf("    - DONT_EXPIRE_PASSWORD\n");
    if (uac & 0x20000) printf("    - MNS_LOGON_ACCOUNT\n");
    if (uac & 0x40000) printf("    - SMARTCARD_REQUIRED\n");
    if (uac & 0x80000) printf("    - TRUSTED_FOR_DELEGATION\n");
    if (uac & 0x100000) printf("    - NOT_DELEGATED\n");
    if (uac & 0x200000) printf("    - USE_DES_KEY_ONLY\n");
    if (uac & 0x400000) printf("    - DONT_REQ_PREAUTH\n");
    if (uac & 0x800000) printf("    - PASSWORD_EXPIRED\n");
    if (uac & 0x1000000) printf("    - TRUSTED_TO_AUTH_FOR_DELEGATION\n");
}

// Enumerate computers in the domain
HRESULT EnumerateComputers(IADs* pDomain) {
    HRESULT hr;
    IDirectorySearch* pSearch = NULL;
    ADS_SEARCH_HANDLE hSearch = NULL;

    hr = ADsGetObject(L"LDAP://rootDSE", &IID_IADs, (void**)&pDomain);
    if (FAILED(hr)) {
        wprintf(L"Failed to connect to rootDSE: 0x%x\n", hr);
        return hr;
    }

    VARIANT var;
    VariantInit(&var);
    hr = pDomain->lpVtbl->Get(pDomain, L"defaultNamingContext", &var);
    if (FAILED(hr)) {
        pDomain->lpVtbl->Release(pDomain);
        return hr;
    }

    WCHAR searchPath[512];
    swprintf_s(searchPath, 512, L"LDAP://%s", var.bstrVal);
    VariantClear(&var);
    pDomain->lpVtbl->Release(pDomain);

    wprintf(L"\n=== Connecting to: %s ===\n\n", searchPath);

    hr = ADsGetObject(searchPath, &IID_IDirectorySearch, (void**)&pSearch);
    if (FAILED(hr)) {
        wprintf(L"Failed to create search: 0x%x\n", hr);
        return hr;
    }

    // Attributes to retrieve for computers
    LPWSTR computerAttr[] = {
        L"cn", L"dNSHostName", L"operatingSystem",
        L"operatingSystemVersion", L"description",
        L"distinguishedName", L"whenCreated", L"objectClass",
        L"lastLogon", L"servicePrincipalName", L"userAccountControl"
    };
    DWORD computerAttrCount = sizeof(computerAttr) / sizeof(LPWSTR);

    ADS_SEARCHPREF_INFO prefInfo[3];
    prefInfo[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefInfo[0].vValue.dwType = ADSTYPE_INTEGER;
    prefInfo[0].vValue.Integer = ADS_SCOPE_SUBTREE;

    prefInfo[1].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
    prefInfo[1].vValue.dwType = ADSTYPE_INTEGER;
    prefInfo[1].vValue.Integer = 1000;

    prefInfo[2].dwSearchPref = ADS_SEARCHPREF_ASYNCHRONOUS;
    prefInfo[2].vValue.dwType = ADSTYPE_BOOLEAN;
    prefInfo[2].vValue.Boolean = FALSE;

    hr = pSearch->lpVtbl->SetSearchPreference(pSearch, prefInfo, 3);
    if (FAILED(hr)) {
        wprintf(L"Failed to set search preferences: 0x%x\n", hr);
    }

    // Search for computers
    wprintf(L"=== COMPUTERS IN DOMAIN ===\n\n");
    hr = pSearch->lpVtbl->ExecuteSearch(
        pSearch,
        L"(objectClass=computer)",
        computerAttr,
        computerAttrCount,
        &hSearch
    );

    if (SUCCEEDED(hr)) {
        int computerCount = 0;
        HRESULT hrRow;

        while ((hrRow = pSearch->lpVtbl->GetNextRow(pSearch, hSearch)) != S_ADS_NOMORE_ROWS) {
            if (hrRow == S_OK) {
                computerCount++;
                ADS_SEARCH_COLUMN col;

                wprintf(L"--- Computer #%d ---\n", computerCount);

                for (DWORD i = 0; i < computerAttrCount; i++) {
                    hr = pSearch->lpVtbl->GetColumn(pSearch, hSearch, computerAttr[i], &col);
                    if (SUCCEEDED(hr)) {
                        wprintf(L"  %s: ", computerAttr[i]);

                        if (wcscmp(computerAttr[i], L"lastLogon") == 0) {
                            if (col.dwNumValues > 0 && col.pADsValues[0].LargeInteger.QuadPart != 0) {
                                WCHAR timeStr[64];
                                FileTimeToString(&col.pADsValues[0].LargeInteger, timeStr, 64);
                                wprintf(L"%s\n", timeStr);
                            }
                            else {
                                wprintf(L"Never\n");
                            }
                        }
                        else if (wcscmp(computerAttr[i], L"whenCreated") == 0) {
                            if (col.dwNumValues > 0 && col.dwADsType == ADSTYPE_UTC_TIME) {
                                SYSTEMTIME st = col.pADsValues[0].UTCTime;
                                wprintf(L"%04d-%02d-%02d %02d:%02d:%02d UTC\n",
                                    st.wYear, st.wMonth, st.wDay,
                                    st.wHour, st.wMinute, st.wSecond);
                            }
                            else {
                                wprintf(L"N/A\n");
                            }
                        }
                        else if (wcscmp(computerAttr[i], L"userAccountControl") == 0) {
                            if (col.dwNumValues > 0) {
                                wprintf(L"%d\n", col.pADsValues[0].Integer);
                                DecodeUAC(col.pADsValues[0].Integer);
                            }
                        }
                        else if (wcscmp(computerAttr[i], L"servicePrincipalName") == 0) {
                            if (col.dwNumValues > 0) {
                                wprintf(L"\n");
                                for (DWORD j = 0; j < col.dwNumValues; j++) {
                                    wprintf(L"    [%d] %s\n", j, col.pADsValues[j].CaseIgnoreString);
                                }
                            }
                            else {
                                wprintf(L"None\n");
                            }
                        }
                        else {
                            if (col.dwNumValues > 0) {
                                for (DWORD j = 0; j < col.dwNumValues; j++) {
                                    if (col.dwADsType == ADSTYPE_DN_STRING && col.pADsValues[j].DNString) {
                                        wprintf(L"%s", col.pADsValues[j].DNString);
                                    }
                                    else if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.pADsValues[j].CaseIgnoreString) {
                                        wprintf(L"%s", col.pADsValues[j].CaseIgnoreString);
                                    }
                                    else if (col.dwADsType == ADSTYPE_INTEGER) {
                                        wprintf(L"%d", col.pADsValues[j].Integer);
                                    }
                                    if (j < col.dwNumValues - 1) wprintf(L", ");
                                }
                                wprintf(L"\n");
                            }
                            else {
                                wprintf(L"N/A\n");
                            }
                        }
                        pSearch->lpVtbl->FreeColumn(pSearch, &col);
                    }
                }
                wprintf(L"\n");
            }
        }

        wprintf(L"Total computers found: %d\n\n", computerCount);
        pSearch->lpVtbl->CloseSearchHandle(pSearch, hSearch);
    }
    else {
        wprintf(L"ExecuteSearch failed: 0x%x\n", hr);
    }

    // Search for users
    wprintf(L"\n=== USERS ===\n\n");
    LPWSTR userAttr[] = {
        L"cn", L"sAMAccountName", L"mail", L"description",
        L"distinguishedName", L"memberOf", L"lastLogon",
        L"pwdLastSet", L"userAccountControl", L"adminCount"
    };
    DWORD userAttrCount = sizeof(userAttr) / sizeof(LPWSTR);

    hr = pSearch->lpVtbl->ExecuteSearch(
        pSearch,
        L"(&(objectClass=user)(objectCategory=person))",
        userAttr,
        userAttrCount,
        &hSearch
    );

    if (SUCCEEDED(hr)) {
        int userCount = 0;
        HRESULT hrRow;

        while ((hrRow = pSearch->lpVtbl->GetNextRow(pSearch, hSearch)) != S_ADS_NOMORE_ROWS) {
            if (hrRow == S_OK) {
                if (++userCount > 20) {
                    wprintf(L"... (showing first 20 users)\n");
                    break;
                }

                ADS_SEARCH_COLUMN col;
                wprintf(L"--- User #%d ---\n", userCount);

                for (DWORD i = 0; i < userAttrCount; i++) {
                    hr = pSearch->lpVtbl->GetColumn(pSearch, hSearch, userAttr[i], &col);
                    if (SUCCEEDED(hr)) {
                        wprintf(L"  %s: ", userAttr[i]);

                        if (wcscmp(userAttr[i], L"lastLogon") == 0 ||
                            wcscmp(userAttr[i], L"pwdLastSet") == 0) {
                            if (col.dwNumValues > 0 && col.pADsValues[0].LargeInteger.QuadPart != 0) {
                                WCHAR timeStr[64];
                                FileTimeToString(&col.pADsValues[0].LargeInteger, timeStr, 64);
                                wprintf(L"%s\n", timeStr);
                            }
                            else {
                                wprintf(L"Never\n");
                            }
                        }
                        else if (wcscmp(userAttr[i], L"userAccountControl") == 0) {
                            if (col.dwNumValues > 0) {
                                wprintf(L"%d\n", col.pADsValues[0].Integer);
                                DecodeUAC(col.pADsValues[0].Integer);
                            }
                        }
                        else if (wcscmp(userAttr[i], L"adminCount") == 0) {
                            if (col.dwNumValues > 0) {
                                wprintf(L"%d ", col.pADsValues[0].Integer);
                                if (col.pADsValues[0].Integer > 0) {
                                    wprintf(L"[PRIVILEGED USER]");
                                }
                                wprintf(L"\n");
                            }
                            else {
                                wprintf(L"0\n");
                            }
                        }
                        else if (wcscmp(userAttr[i], L"memberOf") == 0) {
                            if (col.dwNumValues > 0) {
                                wprintf(L"\n");
                                for (DWORD j = 0; j < col.dwNumValues; j++) {
                                    wprintf(L"    [%d] %s\n", j, col.pADsValues[j].DNString);
                                }
                            }
                            else {
                                wprintf(L"None\n");
                            }
                        }
                        else {
                            if (col.dwNumValues > 0) {
                                for (DWORD j = 0; j < col.dwNumValues; j++) {
                                    if (col.dwADsType == ADSTYPE_DN_STRING && col.pADsValues[j].DNString) {
                                        wprintf(L"%s", col.pADsValues[j].DNString);
                                    }
                                    else if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.pADsValues[j].CaseIgnoreString) {
                                        wprintf(L"%s", col.pADsValues[j].CaseIgnoreString);
                                    }
                                    if (j < col.dwNumValues - 1) wprintf(L", ");
                                }
                                wprintf(L"\n");
                            }
                            else {
                                wprintf(L"N/A\n");
                            }
                        }
                        pSearch->lpVtbl->FreeColumn(pSearch, &col);
                    }
                }
                wprintf(L"\n");
            }
        }

        wprintf(L"Total users found: %d\n\n", userCount);
        pSearch->lpVtbl->CloseSearchHandle(pSearch, hSearch);
    }

    // Search for groups
    wprintf(L"\n=== SECURITY GROUPS ===\n\n");
    LPWSTR groupAttr[] = {
        L"cn", L"description", L"distinguishedName", L"member"
    };
    DWORD groupAttrCount = sizeof(groupAttr) / sizeof(LPWSTR);

    hr = pSearch->lpVtbl->ExecuteSearch(
        pSearch,
        L"(objectClass=group)",
        groupAttr,
        groupAttrCount,
        &hSearch
    );

    if (SUCCEEDED(hr)) {
        int groupCount = 0;
        HRESULT hrRow;

        while ((hrRow = pSearch->lpVtbl->GetNextRow(pSearch, hSearch)) != S_ADS_NOMORE_ROWS) {
            if (hrRow == S_OK) {
                if (++groupCount > 15) {
                    wprintf(L"... (showing first 15 groups)\n");
                    break;
                }

                ADS_SEARCH_COLUMN col;
                wprintf(L"--- Group #%d ---\n", groupCount);

                for (DWORD i = 0; i < groupAttrCount; i++) {
                    hr = pSearch->lpVtbl->GetColumn(pSearch, hSearch, groupAttr[i], &col);
                    if (SUCCEEDED(hr)) {
                        wprintf(L"  %s: ", groupAttr[i]);

                        if (wcscmp(groupAttr[i], L"member") == 0) {
                            wprintf(L"(%d members)\n", col.dwNumValues);
                            if (col.dwNumValues > 0 && col.dwNumValues <= 5) {
                                for (DWORD j = 0; j < col.dwNumValues; j++) {
                                    wprintf(L"    [%d] %s\n", j, col.pADsValues[j].DNString);
                                }
                            }
                            else if (col.dwNumValues > 5) {
                                wprintf(L"    (too many to display, showing first 3)\n");
                                for (DWORD j = 0; j < 3; j++) {
                                    wprintf(L"    [%d] %s\n", j, col.pADsValues[j].DNString);
                                }
                            }
                        }
                        else {
                            if (col.dwNumValues > 0) {
                                if (col.pADsValues[0].DNString) {
                                    wprintf(L"%s\n", col.pADsValues[0].DNString);
                                }
                                else if (col.pADsValues[0].CaseIgnoreString) {
                                    wprintf(L"%s\n", col.pADsValues[0].CaseIgnoreString);
                                }
                                else {
                                    wprintf(L"N/A\n");
                                }
                            }
                            else {
                                wprintf(L"N/A\n");
                            }
                        }
                        pSearch->lpVtbl->FreeColumn(pSearch, &col);
                    }
                }
                wprintf(L"\n");
            }
        }

        wprintf(L"Total groups found: %d\n\n", groupCount);
        pSearch->lpVtbl->CloseSearchHandle(pSearch, hSearch);
    }

    // Search for service accounts (accounts with SPN)
    wprintf(L"\n=== SERVICE ACCOUNTS (with SPN) ===\n\n");
    LPWSTR spnAttr[] = {
        L"cn", L"sAMAccountName", L"servicePrincipalName",
        L"distinguishedName", L"pwdLastSet"
    };
    DWORD spnAttrCount = sizeof(spnAttr) / sizeof(LPWSTR);

    hr = pSearch->lpVtbl->ExecuteSearch(
        pSearch,
        L"(&(objectClass=user)(servicePrincipalName=*))",
        spnAttr,
        spnAttrCount,
        &hSearch
    );

    if (SUCCEEDED(hr)) {
        int spnCount = 0;
        HRESULT hrRow;

        while ((hrRow = pSearch->lpVtbl->GetNextRow(pSearch, hSearch)) != S_ADS_NOMORE_ROWS) {
            if (hrRow == S_OK) {
                spnCount++;
                ADS_SEARCH_COLUMN col;
                wprintf(L"--- Service Account #%d ---\n", spnCount);

                for (DWORD i = 0; i < spnAttrCount; i++) {
                    hr = pSearch->lpVtbl->GetColumn(pSearch, hSearch, spnAttr[i], &col);
                    if (SUCCEEDED(hr)) {
                        wprintf(L"  %s: ", spnAttr[i]);

                        if (wcscmp(spnAttr[i], L"pwdLastSet") == 0) {
                            if (col.dwNumValues > 0 && col.pADsValues[0].LargeInteger.QuadPart != 0) {
                                WCHAR timeStr[64];
                                FileTimeToString(&col.pADsValues[0].LargeInteger, timeStr, 64);
                                wprintf(L"%s\n", timeStr);
                            }
                            else {
                                wprintf(L"Never\n");
                            }
                        }
                        else if (wcscmp(spnAttr[i], L"servicePrincipalName") == 0) {
                            if (col.dwNumValues > 0) {
                                wprintf(L"\n");
                                for (DWORD j = 0; j < col.dwNumValues; j++) {
                                    wprintf(L"    [%d] %s\n", j, col.pADsValues[j].CaseIgnoreString);
                                }
                            }
                            else {
                                wprintf(L"None\n");
                            }
                        }
                        else {
                            if (col.dwNumValues > 0) {
                                if (col.pADsValues[0].DNString) {
                                    wprintf(L"%s\n", col.pADsValues[0].DNString);
                                }
                                else if (col.pADsValues[0].CaseIgnoreString) {
                                    wprintf(L"%s\n", col.pADsValues[0].CaseIgnoreString);
                                }
                                else {
                                    wprintf(L"N/A\n");
                                }
                            }
                            else {
                                wprintf(L"N/A\n");
                            }
                        }
                        pSearch->lpVtbl->FreeColumn(pSearch, &col);
                    }
                }
                wprintf(L"\n");
            }
        }

        wprintf(L"Total service accounts found: %d\n\n", spnCount);
        pSearch->lpVtbl->CloseSearchHandle(pSearch, hSearch);
    }

    pSearch->lpVtbl->Release(pSearch);
    return S_OK;
}

int wmain(int argc, wchar_t* argv[]) {
    HRESULT hr = CoInitialize(NULL);
    if (FAILED(hr)) {
        wprintf(L"COM initialization failed: 0x%x\n", hr);
        return 1;
    }

    wprintf(L"=== ACTIVE DIRECTORY ARCHITECTURE ENUMERATION ===\n");

    hr = EnumerateComputers(NULL);

    if (FAILED(hr)) {
        wprintf(L"Enumeration failed: 0x%x\n", hr);
    }

    CoUninitialize();
    return 0;
}