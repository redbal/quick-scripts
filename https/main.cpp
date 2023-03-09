/*
 * C++ example of using pinned SSL/TLS certificates with libtls
 * without using libcurl.
 *
 * Based initially off of
 * https://gist.github.com/kinichiro/9ac1f6768d490bb3d9828e9ffac7d098
 */

#include <err.h>
#include <stdio.h>
#include <string>
#include <chrono>
#include <iostream>
#include <sstream>
#include <vector>
#include <codecvt>
#include <iomanip>
#include <thread>

#include <tls.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#include "base64.hpp"

#include "http.h"

using namespace std::chrono_literals;


const char *USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) "
                         "AppleWebKit/537.36 (KHTML, like Gecko) "
                         "Chrome/65.0.3325.181 Safari/537.36";
bool flag_printResponseHeaders = true;
bool flag_printRequest = true;

void handleErrors();

void parse_response(std::vector<std::string> input);
void do_http(const char *pemBundleString, unsigned int pemBundleLength, const char *url);

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext);

#ifndef NDEBUG
#define PERR(A) warn A;
#else
#define PERR(A)
#endif

const char pinnedCertsPEM[] =
    // DigiCert Global Root CA (badssl.com)
    "-----BEGIN CERTIFICATE-----\n\
MIIDRjCCAi4CCQDGOQ7pFXcJnTANBgkqhkiG9w0BAQsFADBlMQswCQYDVQQGEwJV\n\
UzERMA8GA1UECAwITWFyeWxhbmQxEjAQBgNVBAcMCUhhbXBzdGVhZDESMBAGA1UE\n\
AwwJbG9jYWxob3N0MRswGQYJKoZIhvcNAQkBFgxtZUBsb2NhbGhvc3QwHhcNMjMw\n\
MjI1MDExOTU5WhcNMjQwMjI1MDExOTU5WjBlMQswCQYDVQQGEwJVUzERMA8GA1UE\n\
CAwITWFyeWxhbmQxEjAQBgNVBAcMCUhhbXBzdGVhZDESMBAGA1UEAwwJbG9jYWxo\n\
b3N0MRswGQYJKoZIhvcNAQkBFgxtZUBsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB\n\
AQUAA4IBDwAwggEKAoIBAQC+hJupJiyHoLbC69BQ91i6ByzZSYMby1kqg4dMp4JS\n\
e1nqerbVcvUtoTLLkSU2hx6dOFHqKPxI3w2a6zI+td/g99hTM31X02OJZC+DbBEH\n\
/okXA4qQCBWggM+xrxNPx0cP1ySipJcKzxGtv7cHL9dn9o4YWtAsYtIC7UgA/OeZ\n\
gSK4WAYk3GKgShE7G9NVpCBWLFlwlsOip00VzxUHEMBHIebU1ELnoPI2d+W28yHS\n\
Wg1Jfs+1lYrfV0ZXEDIWtZl+0O4zneHwtk65duqBHV7G1k5u+OU9IN1U5NqKhsiH\n\
ZDgtSKvkWip6AynboNicN/4psCVoxYL1Y0iIzKH01C6RAgMBAAEwDQYJKoZIhvcN\n\
AQELBQADggEBAGQXzzWC720CyDPTNbuUjbFJ+WnP++dgC41IT3bfyi31XRSjE2qQ\n\
8YTpkNfery1prYgGIGAwmZq/v2nqnJHFVJKUD/xHyaGVsOhH9nU4bNxk9TnSxglC\n\
w+DGDvAHStgHrHnW53hTGTtu1faROfm940ALma8Su9/wJLdTQxKfGaFr2tEZlQKx\n\
9kPvnaiy3r7rd3znTe2763AHYtEIc+pLpF4f9qSpOLV6v+4bN3nYHRIjzAp5FHo/\n\
vMJhQbOCQQ1LGx3W9TSQXDQFqZXhBJzAOIuAK4aVfWtTBqHncRyh+yZc2Nktu8v4\n\
K22QnAggakbg1yZqBLADYNZ2+HZHtpmkiCQ=\n\
-----END CERTIFICATE-----\n";

/**
 *
 */
int httpSend(HttpRequest &request, HttpResponse &response,
             const char *pemBundleString, unsigned int pemBundleLength) {
  struct tls_config *cfg = NULL;
  struct tls *ctx = NULL;
  ssize_t writelen;
 

  /*
  ** initialize libtls
  */

  if (tls_init() != 0) {
    PERR(("tls_init:"));
    return 1;
  }

  /*
  ** configure libtls
  */
  
  if ((cfg = tls_config_new()) == NULL) {
    PERR(("tls_config_new:"));
    return 2;
  }

  /* set root certificate (CA) */
  if (tls_config_set_ca_mem(cfg, (const uint8_t *)pemBundleString,
                            pemBundleLength) != 0) {
    PERR(("tls_config_set_ca_mem:"));
    return 3;
  }

  /* set protocols */
  if (tls_config_set_protocols(cfg, TLS_PROTOCOL_TLSv1_2) != 0) {
    PERR(("tls_config_set_protocols:"));
    return 3;
  }

  /* set protocols */
  if (tls_config_set_ciphers(cfg, "DEFAULT") != 0) {
    PERR(("tls_config_set_protocols:"));
    return 3;
  }
  

  /*
  ** initiate client context
  */

  if ((ctx = tls_client()) == NULL) {
    PERR(("tls_client:"));
    return 4;
  }

  /*
  ** apply config to context
  */

  if (tls_configure(ctx, cfg) != 0) {
    PERR(("tls_configure: %s", tls_error(ctx)));
    return 5;
  }

  /*
  ** connect to server
  */

  if (tls_connect(
          ctx, request.host.c_str(),
          (request.portstr.length() == 0 ? "443" : request.portstr.c_str())) !=
      0) {
    PERR(("tls_connect: %s", tls_error(ctx)));
    return 6;
  }

  
    std::string requestStr = request.generate();
    HttpReader *httpReader = HttpReaderNew(response);
    if (flag_printRequest)
      printf("sending\n%s\n", requestStr.c_str());

    if ((writelen = tls_write(ctx, requestStr.c_str(), requestStr.length())) <
        0) {
      PERR(("tls_write: %s", tls_error(ctx)));
      return 7;
    }

    char readbuf[8192];
    size_t readlen;
    std::vector<std::string> vect;
    while ((readlen = tls_read(ctx, readbuf, sizeof(readbuf) - 1)) > 0) {
      readbuf[readlen] = 0;
      vect.push_back(readbuf);
      httpReader->onBuffer(readbuf, readlen, sizeof(readbuf));
      if (httpReader->isFinished())
        break;
    }
    delete httpReader;
    parse_response(vect);



  // clean up
  tls_free(ctx);
  tls_config_free(cfg);
  //if (tls_close(ctx) != 0)
  //  err(1, "tls_close: %s", tls_error(ctx));

  return 0;
}

/**
 * @brief Simple function to read a small text file into 'dest' param.
 * @returns 0 on success, -1 otherwise.
 */
int read_text_file(const std::string path, std::string &dest) {
  char achLine[2048];
  FILE *pf = fopen(path.c_str(), "rt");
  if (NULL == pf)
    return -1;

  while (!feof(pf)) {
    char *pstr = fgets(achLine, sizeof(achLine), pf);
    if (pstr != NULL)
      dest.append(pstr);
  }

  fclose(pf);
  return 0;
}


void parse_response(std::vector<std::string> input){

  /* std::cout << "Processing " << input.size() << " bytes" << std::endl;
  std::cout << "One element: " << input[0] << std::endl;
  std::cout << "Two element: " << input[1] << std::endl;
  std::cout << "Three element: " << input[2] << std::endl;
   */
  std::cout << "Last element: " << input[input.size() -1] << std::endl;
  std::string val = base64::from_base64(input[input.size() -1]);
  std::cout << "CIPHERTEXT: " << val << std::endl;
  
  /*  for (auto i : val) { 
    std::cout << " ( " << std::hex << std::setfill('0') << std::setw(2) << i << " ) ";
    std::cout << "[ " << i << " | " << static_cast<int>(i) << std::hex << " ]"; }
 
  std::cout << std::endl;
  */ 
  std::string key {"Sixteen byte key"};
  
  std::string a {"localhost"}; 
  std::string a_orig {"localhost"}; 
  
  reverse(a.begin(), a.end());
  //std::cout << "a: " << a << std::endl;   
  
  //UTF-8 to UTF-16 
  std::string b_tmp = a.substr(0,4);  
  //std::wstring_convert<std::codecvt_utf8_utf16<char16_t>,char16_t> convert; 
  //std::u16string b = convert.from_bytes(b_tmp); 
  //std::cout << "b: " ;
  //for ( auto i : b ) { std::cout << char(i); }   
  //std::cout << std::endl;
  
  std::string c = a.substr(0,3);  
  //std::cout << "c: " << c << std::endl;   
  
  std::string d_tmp = a_orig;
  //std::u16string d = convert.from_bytes(d_tmp); 
  //std::cout << "d: " ;
  //for ( auto i : d ) { std::cout << char(i); }   
  //std::cout << std::endl;
  
  std::string e = a_orig.substr(0, 5); 
  //std::cout << "e: " << e << std::endl;  

  std::string nonce = a + b_tmp + c + d_tmp +e;
  
  auto t = base64::to_base64(nonce);
  //std::cout << "PRE: " << nonce << " BASE64: " << t << '\n'; 

  std::stringstream ss;
  for(int i=0; i<t.size(); i++){
      //std::cout << nonce[i] << std::endl;
      ss << std::hex << static_cast<int>(t[i]);
  }
  std::string d_nonce = ss.str();
  //auto s = base64::to_base64(d_nonce);
  //std::cout << "PRE: " << mystr << " BASE64: " << s << '\n'; 
  /*
  nonce = base64.b64encode(a+b+c+d+e).hex().encode('utf-8')
  a = hostname[::-1].encode('utf_8')
  3 b = hostname[::-1][:-5].encode('utf_16')
  2 c = hostname[::-1][:3].encode('utf_8')
  1 d = hostname.encode('utf1_16')
18  e = hostname[:-4].encode('utf_8')

  std::string c = val[::-1][:3].encode('utf_7');
  std::string d = val.encode('cp1006');
  std::string e = val[:-4].encode('hz');
 */  //nonce = base64.b64encode(a+b+c+d+e).hex().encode('utf-8')
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  //auto cipher = AES.new(key, AES.MODE_EAX, nonce=nonce);

  auto *c_key = reinterpret_cast<const unsigned char*>(key.c_str());
  int key_size = key.length();
  
  auto c_nonce = reinterpret_cast<const unsigned char*>(d_nonce.c_str());
  int c_nonce_size = d_nonce.length();

  unsigned char data[val.size() + 1];
  std::copy(val.begin(), val.end(), data);
  unsigned char *c_val = data;
  std::cout << "DATA: " << data << std::endl;
  std::cout << "VAL: " << val.data() << std::endl;

  EVP_CIPHER* ch = reinterpret_cast<EVP_CIPHER*>(val.data());
  
  std::cout << "ch: " << ch << std::endl;

  //EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv);

  //EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, cd, ce);
  //EVP_DecryptInit_ex(ctx, ch, cd, ce);
  int max_decrypt_buffer = 256;
  unsigned char decryptedtext[max_decrypt_buffer];
  unsigned char* plaintext = decryptedtext;
  int *len = &max_decrypt_buffer;
  int outl = val.length();

  std::cout << "IV/NONCE: " << c_nonce << " | " << c_nonce_size << std::endl;
    /* Initialise the decryption operation. */
  if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
      std::cout << "ERROR" << std::endl;

  /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
  if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, c_nonce_size, NULL))
      std::cout << "ERROR" << std::endl;

  /* Initialise key and IV */
  if(!EVP_DecryptInit_ex(ctx, NULL, NULL, c_key, c_nonce))
      std::cout << "ERROR" << std::endl;

 //int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
 //                      int *outl, const unsigned char *in, int inl);

 /*  if ( EVP_DecryptUpdate(ctx, plaintext, len, cf, outl) ){
    std::cout << "TRUE" << std::endl;
  } else { std::cout << "FAILED TO UPDATE DECRYPTER" << std::endl; }
  */
  if(!EVP_DecryptUpdate(ctx, plaintext, len, c_val, outl))
        std::cout << "ERROR" << std::endl;

  int ret = EVP_DecryptFinal_ex(ctx, plaintext, len);

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  if(ret > 0) {
      /* Success */
      std::cout << "Finalize Success" << std::endl;
  } else {
      /* Verify failed */
      std::cout << "Finalized Failed" << std::endl;
  }

  //std::cout << "PLAINTEXT: " << plaintext << std::endl;
  unsigned char k[key.size()+1];
  unsigned char *kk = k;
  for ( int i=0; i<key.size(); i++){
    k[i] = key[i];
  }
  unsigned char j[d_nonce.size()+1];
  unsigned char *jj = j;
  for ( int i=0; i<d_nonce.size(); i++){
    j[i] = d_nonce[i];
  }
  std::cout << "KK: [" << kk << "] JJ: [" << jj << "]" << std::endl;
  int do_decrypt = gcm_decrypt(c_val, val.size(), kk, jj, c_nonce_size+1, plaintext);
  std::cout << "return: " << do_decrypt << std::endl;
}


int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext)
{
    
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();
    
    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();
    
    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();
    std::cout << "1" << std::endl;
    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();
*/
    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;
    std::cout << "1" << std::endl;
    /* Set expected tag value. Works in OpenSSL 1.0.1d and later 
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        handleErrors();
*/
    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
}

void handleErrors(){
  std::cout << "Error" << std::endl;
}


/**
 * main
 */
int main(int argc, char *argv[]) {
  if (argc < 2) {
    printf("usage: %s url <optional/path/to/cabundle.pem>\n\n", argv[0]);
    return 1;
  }

  const char *url = argv[1];
  const char *pemBundleString = pinnedCertsPEM;
  unsigned int pemBundleLength = sizeof(pinnedCertsPEM);

  std::string pemBundleFileContents = std::string();
  if (argc > 2) {
    const char *pem_filename = argv[2];
    int status = read_text_file(pem_filename, pemBundleFileContents);
    if (status != 0) {
      printf("Error reading PEM bundle file at '%s'\n", pem_filename);
      return 2;
    }
    pemBundleString = pemBundleFileContents.c_str();
    pemBundleLength = pemBundleFileContents.length();
  }
  //do_http(pemBundleString, pemBundleLength, url);
  std::thread kkworker(do_http, std::ref(pemBundleString), pemBundleLength, std::ref(url));
  std::cout << "Started kkworker thread" << std::endl;
  kkworker.join();
  return 0;
}

void do_http(const char *pemBundleString, unsigned int pemBundleLength, const char *url){
  while (true){  
    HttpRequest request = HttpRequest(url);    
    HttpResponse response = HttpResponse();
    request.customHeaders.push_back(HttpHeader("User-Agent", USER_AGENT));
    if (httpSend(request, response, pemBundleString, pemBundleLength)) {
      printf("request failed\n");
      break;
    }
    printf("success\n statusCode:%d headers:%lu response:%lu bytes\n",
          response.statusCode, response.headers.size(), response.body.length());

    if (flag_printResponseHeaders) {
      for (auto hdr : response.headers) {
        printf("%s:%s\n", hdr.name.c_str(), hdr.value.c_str());
      }
    }
    std::this_thread::sleep_for(4000ms);
  }
}
