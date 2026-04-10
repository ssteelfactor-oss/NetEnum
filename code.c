/*
 * NetEnum - Passive Active Directory Enumeration Tool
 * Uses standard ADSI/COM interfaces — generates only normal domain LDAP traffic.
 *
 * Build: VS 2022+, /analyze for SAL validation, /W4 for full diagnostics.
 * Link:  activeds.lib  adsiid.lib  netapi32.lib
 *
 * SAL 2.0 annotations are enforced by PREfast (/analyze).
 * sal.h is pulled in automatically through windows.h.
 */

#include <windows.h>
#include <stdio.h>
#include <activeds.h>

#pragma comment(lib, "activeds.lib")
#pragma comment(lib, "adsiid.lib")


/* ── Configuration ──────────────────────────────────────────────────────── */

/* LDAP page size: keep moderate — large values generate bulkier responses.
 * 200 is indistinguishable from normal workstation queries. */
#define NE_PAGE_SIZE        200

/* Limits for high-cardinality object classes */
#define NE_LIMIT_USERS      20
#define NE_LIMIT_GROUPS     15

/* Timestamp buffer length: "YYYY-MM-DD HH:MM:SS" = 19 chars + NUL */
#define NE_TIMEBUF_LEN      32


/* ── UAC flag table ─────────────────────────────────────────────────────── */
/*
 * Table-driven UAC decoding replaces the original chain of 20 separate
 * if-statements. Adding or removing a flag now requires touching one line.
 */
typedef struct {
    DWORD       mask;
    const char* name;
} UacFlag;

static const UacFlag s_uacFlags[] = {
    { 0x0000001,  "SCRIPT"                        },
    { 0x0000002,  "ACCOUNTDISABLE"                },
    { 0x0000008,  "HOMEDIR_REQUIRED"              },
    { 0x0000010,  "LOCKOUT"                       },
    { 0x0000020,  "PASSWD_NOTREQD"                },
    { 0x0000040,  "PASSWD_CANT_CHANGE"            },
    { 0x0000080,  "ENCRYPTED_TEXT_PWD_ALLOWED"    },
    { 0x0000100,  "TEMP_DUPLICATE_ACCOUNT"        },
    { 0x0000200,  "NORMAL_ACCOUNT"                },
    { 0x0000800,  "INTERDOMAIN_TRUST_ACCOUNT"     },
    { 0x0001000,  "WORKSTATION_TRUST_ACCOUNT"     },
    { 0x0002000,  "SERVER_TRUST_ACCOUNT"          },
    { 0x0010000,  "DONT_EXPIRE_PASSWORD"          },
    { 0x0020000,  "MNS_LOGON_ACCOUNT"             },
    { 0x0040000,  "SMARTCARD_REQUIRED"            },
    { 0x0080000,  "TRUSTED_FOR_DELEGATION"        },
    { 0x0100000,  "NOT_DELEGATED"                 },
    { 0x0200000,  "USE_DES_KEY_ONLY"              },
    { 0x0400000,  "DONT_REQ_PREAUTH"              },
    { 0x0800000,  "PASSWORD_EXPIRED"              },
    { 0x1000000,  "TRUSTED_TO_AUTH_FOR_DELEGATION"},
};


/* ── Forward declarations ───────────────────────────────────────────────── */

static void    FormatLargeIntTime(_In_                    const LARGE_INTEGER* pLI,
                                  _Out_writes_z_(bufLen)  WCHAR*               buf,
                                  _In_                    size_t               bufLen);

static void    DecodeUAC(DWORD uac);

static void    PrintColumn(_In_    IDirectorySearch*   pSearch,
                           _In_z_  LPCWSTR             attrName,
                           _Inout_ ADS_SEARCH_COLUMN*  pCol);

static HRESULT RunQuery(_In_                  IDirectorySearch* pSearch,
                        _In_z_                LPCWSTR           filter,
                        _In_z_                LPCWSTR           title,
                        _In_reads_(attrCount) LPWSTR*           attrs,
                        _In_                  DWORD             attrCount,
                        _In_                  int               limit);

_Must_inspect_result_
_Success_(SUCCEEDED(return))
static HRESULT BuildSearchObject(_Outptr_ IDirectorySearch** ppSearch);

_Must_inspect_result_
_Success_(SUCCEEDED(return))
HRESULT RunEnumeration(void);


/* ═══════════════════════════════════════════════════════════════════════════
 * FormatLargeIntTime
 *
 * Converts a Windows FILETIME stored as LARGE_INTEGER (100-ns ticks since
 * 1601-01-01) into a human-readable "YYYY-MM-DD HH:MM:SS" wide string.
 * Writes "Never" when QuadPart == 0 (attribute not set / never occurred).
 *
 * _In_                  pLI     Read-only input; must not be NULL.
 * _Out_writes_z_(bufLen) buf     Output wide-char buffer, null-terminated.
 *                                PREfast verifies buffer is large enough.
 * _In_                  bufLen  Buffer capacity in WCHARs.
 * ═══════════════════════════════════════════════════════════════════════════ */
static void FormatLargeIntTime(
    _In_                    const LARGE_INTEGER* pLI,
    _Out_writes_z_(bufLen)  WCHAR*               buf,
    _In_                    size_t               bufLen)
{
    if (pLI->QuadPart == 0) {
        wcscpy_s(buf, bufLen, L"Never");
        return;
    }

    FILETIME   ft = { (DWORD)pLI->LowPart, (DWORD)pLI->HighPart };
    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);

    swprintf_s(buf, bufLen, L"%04u-%02u-%02u %02u:%02u:%02u",
               st.wYear, st.wMonth,  st.wDay,
               st.wHour, st.wMinute, st.wSecond);
}


/* ═══════════════════════════════════════════════════════════════════════════
 * DecodeUAC
 *
 * Prints all set bits in userAccountControl using the flag table above.
 * Pure console sink — reads uac by value, modifies nothing.
 * No SAL annotation needed on scalar-by-value parameters.
 * ═══════════════════════════════════════════════════════════════════════════ */
static void DecodeUAC(DWORD uac)
{
    printf("    UAC 0x%08X:", uac);

    BOOL anySet = FALSE;
    for (int i = 0; i < (int)ARRAYSIZE(s_uacFlags); i++) {
        if (uac & s_uacFlags[i].mask) {
            printf("\n      [+] %s", s_uacFlags[i].name);
            anySet = TRUE;
        }
    }

    if (!anySet) printf(" (none)");
    printf("\n");
}


/* ═══════════════════════════════════════════════════════════════════════════
 * PrintColumn
 *
 * Renders one ADS_SEARCH_COLUMN value to stdout, then releases it.
 * Centralises all attribute-specific formatting in a single place.
 *
 * _In_    pSearch   COM interface needed for FreeColumn; must not be NULL.
 * _In_z_  attrName  Null-terminated attribute name (dispatch key).
 * _Inout_ pCol      Written by caller via GetColumn, freed here.
 *                   _Inout_: function both reads values and invalidates struct.
 *
 * NOTE: hSearch is intentionally NOT a parameter — FreeColumn does not need
 * it (the original code passed it but the ADSI vtable ignores it).
 * ═══════════════════════════════════════════════════════════════════════════ */
static void PrintColumn(
    _In_    IDirectorySearch*  pSearch,
    _In_z_  LPCWSTR            attrName,
    _Inout_ ADS_SEARCH_COLUMN* pCol)
{
    /* ── Timestamp attributes ──────────────────────────────────────────── */
    if (wcscmp(attrName, L"lastLogon")  == 0 ||
        wcscmp(attrName, L"pwdLastSet") == 0)
    {
        WCHAR ts[NE_TIMEBUF_LEN];
        if (pCol->dwNumValues > 0)
            FormatLargeIntTime(&pCol->pADsValues[0].LargeInteger,
                               ts, NE_TIMEBUF_LEN);
        else
            wcscpy_s(ts, NE_TIMEBUF_LEN, L"Never");

        wprintf(L"%s\n", ts);
    }

    /* ── whenCreated is stored as UTC_TIME, not LargeInteger ──────────── */
    else if (wcscmp(attrName, L"whenCreated") == 0)
    {
        if (pCol->dwNumValues > 0 && pCol->dwADsType == ADSTYPE_UTC_TIME) {
            const SYSTEMTIME* s = &pCol->pADsValues[0].UTCTime;
            wprintf(L"%04u-%02u-%02u %02u:%02u:%02u UTC\n",
                    s->wYear, s->wMonth,  s->wDay,
                    s->wHour, s->wMinute, s->wSecond);
        } else {
            wprintf(L"N/A\n");
        }
    }

    /* ── userAccountControl — decode individual bits ───────────────────── */
    else if (wcscmp(attrName, L"userAccountControl") == 0)
    {
        if (pCol->dwNumValues > 0) {
            wprintf(L"\n");
            DecodeUAC((DWORD)pCol->pADsValues[0].Integer);
        }
    }

    /* ── adminCount — flag privileged accounts prominently ────────────── */
    else if (wcscmp(attrName, L"adminCount") == 0)
    {
        if (pCol->dwNumValues > 0) {
            LONG v = pCol->pADsValues[0].Integer;
            wprintf(L"%d%s\n", v, v > 0 ? L"  *** PRIVILEGED ***" : L"");
        } else {
            wprintf(L"0\n");
        }
    }

    /* ── Multi-value string lists (memberOf, servicePrincipalName) ─────── */
    else if (wcscmp(attrName, L"memberOf")             == 0 ||
             wcscmp(attrName, L"servicePrincipalName") == 0)
    {
        if (pCol->dwNumValues == 0) {
            wprintf(L"None\n");
        } else {
            wprintf(L"\n");
            for (DWORD j = 0; j < pCol->dwNumValues; j++)
                wprintf(L"      [%u] %s\n", j,
                        pCol->pADsValues[j].CaseIgnoreString);
        }
    }

    /* ── member — show count, list up to 5, truncate if more ──────────── */
    else if (wcscmp(attrName, L"member") == 0)
    {
        DWORD n     = pCol->dwNumValues;
        DWORD show  = (n > 5) ? 3 : n;

        wprintf(L"(%u total%s)\n",
                n, (n > 5) ? L", showing first 3" : L"");

        for (DWORD j = 0; j < show; j++)
            wprintf(L"      [%u] %s\n", j,
                    pCol->pADsValues[j].DNString);
    }

    /* ── Generic fallback: DN string, case-ignore string, or integer ───── */
    else
    {
        if (pCol->dwNumValues == 0) {
            wprintf(L"N/A\n");
        } else {
            for (DWORD j = 0; j < pCol->dwNumValues; j++) {
                switch (pCol->dwADsType) {
                case ADSTYPE_DN_STRING:
                    wprintf(L"%s", pCol->pADsValues[j].DNString
                                 ? pCol->pADsValues[j].DNString : L"(null)");
                    break;
                case ADSTYPE_CASE_IGNORE_STRING:
                    wprintf(L"%s", pCol->pADsValues[j].CaseIgnoreString
                                 ? pCol->pADsValues[j].CaseIgnoreString : L"(null)");
                    break;
                case ADSTYPE_INTEGER:
                    wprintf(L"%d", pCol->pADsValues[j].Integer);
                    break;
                default:
                    wprintf(L"[type=%u]", pCol->dwADsType);
                    break;
                }
                if (j < pCol->dwNumValues - 1) wprintf(L", ");
            }
            wprintf(L"\n");
        }
    }

    pSearch->lpVtbl->FreeColumn(pSearch, pCol);
}


/* ═══════════════════════════════════════════════════════════════════════════
 * RunQuery
 *
 * Executes one LDAP search, iterates rows, prints attributes.
 * All searches share this path — no duplicated loop logic.
 *
 * _In_                  pSearch    Active IDirectorySearch; must not be NULL.
 * _In_z_                filter     LDAP filter string.
 * _In_z_                title      Section header for console output.
 * _In_reads_(attrCount) attrs      Array of attribute name strings.
 * _In_                  attrCount  Element count of attrs[].
 * _In_                  limit      Max rows to print (0 = unlimited).
 *
 * Returns S_OK on success, propagates ADSI HRESULTs on failure.
 * ═══════════════════════════════════════════════════════════════════════════ */
static HRESULT RunQuery(
    _In_                  IDirectorySearch* pSearch,
    _In_z_                LPCWSTR           filter,
    _In_z_                LPCWSTR           title,
    _In_reads_(attrCount) LPWSTR*           attrs,
    _In_                  DWORD             attrCount,
    _In_                  int               limit)
{
    wprintf(L"\n\n╔══ %s ══\n\n", title);

    ADS_SEARCH_HANDLE hSearch = NULL;
    HRESULT hr = pSearch->lpVtbl->ExecuteSearch(
        pSearch, filter, attrs, attrCount, &hSearch);

    if (FAILED(hr)) {
        wprintf(L"  [!] ExecuteSearch failed: 0x%08X\n", hr);
        return hr;
    }

    int     count = 0;
    HRESULT hrRow;

    while ((hrRow = pSearch->lpVtbl->GetNextRow(pSearch, hSearch))
           != S_ADS_NOMORE_ROWS)
    {
        if (FAILED(hrRow)) break;   /* network / server error */

        count++;

        if (limit > 0 && count > limit) {
            wprintf(L"  ... result set capped at %d entries\n", limit);
            break;
        }

        wprintf(L"  ─── #%d ───\n", count);

        for (DWORD i = 0; i < attrCount; i++) {
            ADS_SEARCH_COLUMN col;
            hr = pSearch->lpVtbl->GetColumn(pSearch, hSearch, attrs[i], &col);
            if (SUCCEEDED(hr)) {
                wprintf(L"  %-30s ", attrs[i]);
                PrintColumn(pSearch, attrs[i], &col);
            }
        }

        wprintf(L"\n");
    }

    wprintf(L"  Total: %d\n", count);
    pSearch->lpVtbl->CloseSearchHandle(pSearch, hSearch);
    return S_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * BuildSearchObject
 *
 * Connects to LDAP://rootDSE, reads defaultNamingContext, returns a ready
 * IDirectorySearch bound to that naming context.
 *
 * Centralises all connection + preference setup so RunEnumeration stays
 * focused on "what to query" rather than "how to connect".
 *
 * _Outptr_ ppSearch  Receives the COM object on success; always NULL on
 *                    failure. _Outptr_ guarantees PREfast that the pointer
 *                    itself (not just *ppSearch) is non-NULL.
 *
 * Cleanup: on any failure all locally acquired COM objects are released
 * via goto — no resource leaks on error paths.
 * ═══════════════════════════════════════════════════════════════════════════ */
_Must_inspect_result_
_Success_(SUCCEEDED(return))
static HRESULT BuildSearchObject(_Outptr_ IDirectorySearch** ppSearch)
{
    *ppSearch = NULL;   /* guarantee caller's pointer is clean on failure */

    HRESULT  hr;
    IADs*    pDSE    = NULL;
    VARIANT  var;
    WCHAR    path[512];

    VariantInit(&var);

    /* Step 1 – bind to the DSA entry point */
    hr = ADsGetObject(L"LDAP://rootDSE", &IID_IADs, (void**)&pDSE);
    if (FAILED(hr)) {
        wprintf(L"[!] rootDSE bind failed: 0x%08X\n", hr);
        goto done;
    }

    /* Step 2 – read the default naming context */
    hr = pDSE->lpVtbl->Get(pDSE, L"defaultNamingContext", &var);
    if (FAILED(hr)) {
        wprintf(L"[!] defaultNamingContext read failed: 0x%08X\n", hr);
        goto done;
    }

    swprintf_s(path, ARRAYSIZE(path), L"LDAP://%s", var.bstrVal);
    wprintf(L"[*] Domain path: %s\n", path);

    /* Step 3 – bind a search object to the naming context */
    hr = ADsGetObject(path, &IID_IDirectorySearch, (void**)ppSearch);
    if (FAILED(hr)) {
        wprintf(L"[!] IDirectorySearch bind failed: 0x%08X\n", hr);
        goto done;
    }

    /* Step 4 – apply search preferences.
     *
     * ASYNCHRONOUS = FALSE keeps the call synchronous; combined with paged
     * results (NE_PAGE_SIZE) this produces the same traffic pattern as any
     * standard domain-joined tool performing AD lookups. */
    ADS_SEARCHPREF_INFO prefs[3];

    prefs[0].dwSearchPref    = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType   = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer  = ADS_SCOPE_SUBTREE;

    prefs[1].dwSearchPref    = ADS_SEARCHPREF_PAGESIZE;
    prefs[1].vValue.dwType   = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer  = NE_PAGE_SIZE;

    prefs[2].dwSearchPref    = ADS_SEARCHPREF_ASYNCHRONOUS;
    prefs[2].vValue.dwType   = ADSTYPE_BOOLEAN;
    prefs[2].vValue.Boolean  = FALSE;

    hr = (*ppSearch)->lpVtbl->SetSearchPreference(*ppSearch, prefs, ARRAYSIZE(prefs));
    if (FAILED(hr)) {
        /* Non-fatal: ADSI will use defaults; log and continue. */
        wprintf(L"[!] SetSearchPreference warning: 0x%08X\n", hr);
        hr = S_OK;
    }

done:
    VariantClear(&var);
    if (pDSE) pDSE->lpVtbl->Release(pDSE);

    /* On failure ensure caller receives NULL, not a partial object */
    if (FAILED(hr) && *ppSearch) {
        (*ppSearch)->lpVtbl->Release(*ppSearch);
        *ppSearch = NULL;
    }

    return hr;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * RunEnumeration
 *
 * Orchestrates four sequential LDAP queries:
 *   1. Computers          – all, no limit
 *   2. User accounts      – capped at NE_LIMIT_USERS
 *   3. Security groups    – capped at NE_LIMIT_GROUPS
 *   4. Service accounts   – SPN-bearing users, no limit
 *
 * Attribute arrays are declared const-correct (LPWSTR required by ADSI ABI
 * even though the strings are never mutated — ADSI predates const here).
 *
 * _Must_inspect_result_         Caller must check HRESULT.
 * _Success_(SUCCEEDED(return))  Post-condition for static analysis paths.
 * ═══════════════════════════════════════════════════════════════════════════ */
_Must_inspect_result_
_Success_(SUCCEEDED(return))
HRESULT RunEnumeration(void)
{
    IDirectorySearch* pSearch = NULL;

    HRESULT hr = BuildSearchObject(&pSearch);
    if (FAILED(hr)) return hr;

    /* ── 1. Computers ───────────────────────────────────────────────────── */
    LPWSTR compAttrs[] = {
        L"cn", L"dNSHostName", L"operatingSystem",
        L"operatingSystemVersion", L"description",
        L"distinguishedName", L"whenCreated",
        L"lastLogon", L"servicePrincipalName", L"userAccountControl"
    };
    RunQuery(pSearch,
             L"(objectClass=computer)",
             L"COMPUTERS",
             compAttrs, ARRAYSIZE(compAttrs),
             0);

    /* ── 2. User accounts ───────────────────────────────────────────────── */
    LPWSTR userAttrs[] = {
        L"cn", L"sAMAccountName", L"mail", L"description",
        L"distinguishedName", L"memberOf",
        L"lastLogon", L"pwdLastSet",
        L"userAccountControl", L"adminCount"
    };
    RunQuery(pSearch,
             L"(&(objectClass=user)(objectCategory=person))",
             L"USER ACCOUNTS",
             userAttrs, ARRAYSIZE(userAttrs),
             NE_LIMIT_USERS);

    /* ── 3. Security groups ─────────────────────────────────────────────── */
    LPWSTR groupAttrs[] = {
        L"cn", L"description", L"distinguishedName", L"member"
    };
    RunQuery(pSearch,
             L"(objectClass=group)",
             L"SECURITY GROUPS",
             groupAttrs, ARRAYSIZE(groupAttrs),
             NE_LIMIT_GROUPS);

    /* ── 4. Service accounts (Kerberoastable candidates) ────────────────── */
    LPWSTR spnAttrs[] = {
        L"cn", L"sAMAccountName",
        L"servicePrincipalName", L"distinguishedName", L"pwdLastSet"
    };
    RunQuery(pSearch,
             L"(&(objectClass=user)(servicePrincipalName=*))",
             L"SERVICE ACCOUNTS  [SPN set — potential Kerberoast targets]",
             spnAttrs, ARRAYSIZE(spnAttrs),
             0);

    pSearch->lpVtbl->Release(pSearch);
    return S_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * wmain
 *
 * Entry point. Initialises COM (STA), runs enumeration, tears down.
 *
 * _In_              argc   Argument count.
 * _In_reads_(argc)  argv   Argument vector; argc elements guaranteed.
 *
 * Currently no CLI flags are parsed; argc/argv are suppressed via (void)
 * to avoid C4100 while keeping the annotations in place for future use.
 * ═══════════════════════════════════════════════════════════════════════════ */
int wmain(
    _In_             int      argc,
    _In_reads_(argc) wchar_t* argv[])
{
    (void)argc;
    (void)argv;

    /*
     * CoInitializeEx with COINIT_APARTMENTTHREADED is preferred over
     * CoInitialize() — explicit threading model, same behaviour for
     * single-threaded console tools, better for future extension.
     */
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        wprintf(L"[!] COM init failed: 0x%08X\n", hr);
        return 1;
    }

    wprintf(L"NetEnum — Passive AD Enumeration\n");
    wprintf(L"Uses standard ADSI/LDAP; no elevated privileges required.\n\n");

    hr = RunEnumeration();

    if (FAILED(hr))
        wprintf(L"\n[!] Enumeration terminated: 0x%08X\n", hr);
    else
        wprintf(L"\n[*] Done.\n");

    CoUninitialize();
    return SUCCEEDED(hr) ? 0 : 1;
}
