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
#include <openssl/err.h>

#include "base64.hpp"
#include "http.h"

using namespace std::chrono_literals;

const char *USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) "
                         "AppleWebKit/537.36 (KHTML, like Gecko) "
                         "Chrome/65.0.3325.181 Safari/537.36";

void handleErrors();
void parse_response(std::vector<std::string> input);
void do_http(struct tls &ctx, struct tls_config &cfg, const char *pemBundleString, unsigned int pemBundleLength, const char *url);
int httpSend(struct tls &ctx, struct tls_config &cfg, HttpRequest &request, HttpResponse &response,
             const char *pemBundleString, unsigned int pemBundleLength);

std::string_view get_option(
  const std::vector<std::string_view>& args, 
  const std::string_view& option_name);

bool has_option(
  const std::vector<std::string_view>& args, 
  const std::string_view& option_name) ;

std::vector<std::byte> getBytes(std::string const &s);

void usage(){
  std::cout << "tclient {url} -t {tls_version} -z {tls_cipherstrings}" << std::endl;
  std::cout << "---------------" << std::endl;
}

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext);

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


void handleErrors(){
  std::cout << "Error" << std::endl;
}

int main(int argc, char *argv[]) {
  if (argc < 4) { // minimal url -t tls_version
    usage();
    return 1;
  }

  const std::vector<std::string_view> args(argv, argv + argc);
  const char *url = argv[1];
  const char *pemBundleString = pinnedCertsPEM;
  unsigned int pemBundleLength = sizeof(pinnedCertsPEM);
  struct tls_config *cfg ={nullptr};
  struct tls *ctx{nullptr};

  if (tls_init() != 0) {
    std::cerr << "tls_init:" << std::endl;
    return 1;
  }
  
   if ((cfg = tls_config_new()) == NULL) {
    std::cerr << "tls_config_new:" << std::endl;
    return 2;
  }

  if (tls_config_set_ca_mem(cfg, (const uint8_t *)pemBundleString,
                            pemBundleLength) != 0) {
    std::cerr << "tls_config_set_ca_mem:" <<std::endl;
    return 3;
  }

  std::string_view tls_version;
  if ( has_option(args, "-t") ) {
      tls_version = get_option(args, "-t");
  }
  unsigned int protocol{0};
  if (tls_version == "1.3") { protocol = TLS_PROTOCOL_TLSv1_3; }
  if (tls_version == "1.2") { protocol = TLS_PROTOCOL_TLSv1_2; }
  if (tls_version == "1.1") { protocol = TLS_PROTOCOL_TLSv1_1; }

  if (tls_config_set_protocols(cfg, protocol) != 0) {
    std::cerr << "tls_config_set_protocols:" << std::endl;
    return 3;
  }
   std::string_view tls_ciphers;
    if ( has_option(args, "-z") ) {
        tls_ciphers = get_option(args, "-z");
    }
    
  if (tls_config_set_ciphers(cfg, tls_ciphers.data()) != 0) {
    std::cerr << "tls_config_set_protocols:" << std::endl;
    return 3;
  }
  
  if ((ctx = tls_client()) == NULL) {
    std::cerr << "tls_client:" << std::endl;
    return 4;
  }

  if (tls_configure(ctx, cfg) != 0) {
    std::cerr << "tls_configure:" << std::endl;
    return 5;
  }

  do_http(*ctx, *cfg, pemBundleString, pemBundleLength, url);
  return 0;
}

void parse_response(std::vector<std::string> input){

/* KEY: b'Sixteen byte key'
NONCE: b'64484e76614778685932397364484e766148527a62327876593246736147397a6447787659324673'  len: 80
CIPHERTEXT: b'w\x81\x8f\xfa\xd3-h\xf6O\xbe\xca\x80q\xbc\x14h'
CIPHERTEXT: d4GP+tMtaPZPvsqAcbwUaA==
PLAINTEXT: b'The answer is no'
 */
  std::cout << "CIPHERTEXT ENCODED [" << input[input.size() -1] << "]" << std::endl;
  std::string cipher_text = base64::from_base64(input[input.size() -1 ]);
  std::cout << "CIPHERTEXT DECODED [" << cipher_text << "]" << std::endl;
  std::vector<std::byte> ciphertext_bytes = getBytes(cipher_text);
  //for (auto i : cipher_text) { printf("%c\t\\x%hhx\t\n", char(i), i) ;}
  for (auto i : ciphertext_bytes) { printf("\\x%hhx", i) ;}
  std::cout << std::endl;
  //printf("w\x81\x8f\xfa\xd3-h\xf6O\xbe\xca\x80q\xbc\x14h \n");
  //std::cout << std::endl;

  //for (auto i : val) {
  //  std::cout << std::hex << std::setfill('0') << std::setw(2) << val[i];
  //}

  std::string key = "Sixteen byte key";  
  std::byte key_bytes[key.length()];
  std::memcpy(key_bytes, key.data(), key.length());

  std::string a {"localhost"}; 
  std::string a_orig {"localhost"}; 
  
  reverse(a.begin(), a.end());
  std::string b_tmp = a.substr(0,4);    
  std::string c = a.substr(0,3);    
  std::string d_tmp = a_orig;
  std::string e = a_orig.substr(0, 5); 
  std::string nonce = a + b_tmp + c + d_tmp +e;  
  auto t = base64::to_base64(nonce);
  std::stringstream ss;
  for(int i=0; i<t.size(); i++){
      std::cout << std::hex << t[i] << std::endl;
      ss << std::hex << static_cast<int>(t[i]);
  }

  std::string d_nonce = ss.str();
  auto s = base64::to_base64(d_nonce);
  std::cout << "PRE: " << d_nonce << " BASE64: " << s << '\n'; 
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

  const unsigned char *c_key = reinterpret_cast<const unsigned char*>(key_bytes);
  int key_size = key.length();
  auto c_nonce = reinterpret_cast<const unsigned char*>(d_nonce.c_str());
  int c_nonce_size = d_nonce.length();
  std::cout << "IV/NONCE: " << c_nonce << " | size: " << c_nonce_size << std::endl;
  //std::cout << "KEY string: " << key << " | size: " << key_size << std::endl;
  std::cout << "KEY bytes: ";
  for (auto i : key_bytes) {std::cout << std::hex << (char)i; }
  std::cout << std::endl;
  //unsigned char data[val.size()];
  //std::copy(val.begin(), val.end(), data);
  //unsigned char *c_val = data;
  //std::cout << "DATA: " << data << std::endl;

  EVP_CIPHER* ch = reinterpret_cast<EVP_CIPHER*>(cipher_text.data());
  
  //EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv);
  //EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, cd, ce);
  //EVP_DecryptInit_ex(ctx, ch, cd, ce);
  int max_decrypt_buffer = 2048;
  unsigned char decryptedtext[max_decrypt_buffer];
  unsigned char* plaintext = decryptedtext;
  int *len = &max_decrypt_buffer;
  int outl = cipher_text.length();

    /* Initialise the decryption operation. */
  if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
      std::cout << "ERROR EVP_DecryptInit_ex" << std::endl;

  /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
  std::vector<std::byte> bytes = getBytes(d_nonce);
  std::cout << "NONCE BYTES " << sizeof(bytes) << std::endl;
  //if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(bytes), NULL))
  //    std::cout << "ERROR EVP_CIPHER_CTX_ctrl" << std::endl;

/*   if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, c_nonce_size, NULL))
      std::cout << "ERROR EVP_CIPHER_CTX_ctrl" << std::endl;
 */
  /* Initialise key and IV */
  if(!EVP_DecryptInit_ex(ctx, NULL, NULL, c_key, c_nonce))
      std::cout << "ERROR EVP_DecryptInit_ex" << std::endl;

 //int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
 //                      int *outl, const unsigned char *in, int inl);

 /*  if ( EVP_DecryptUpdate(ctx, plaintext, len, cf, outl) ){
    std::cout << "TRUE" << std::endl;
  } else { std::cout << "FAILED TO UPDATE DECRYPTER" << std::endl; }
  if(!EVP_DecryptUpdate(ctx, plaintext, len, reinterpret_cast<unsigned char*>(val.data()), outl))
  */
  EVP_CIPHER_CTX_set_padding(ctx, 15); // padding

  if(EVP_DecryptUpdate(ctx, plaintext, len, reinterpret_cast<const unsigned char*>(cipher_text.c_str()), cipher_text.length())) {
      std::cout << "SUCCESS EVP_DecryptUpdate" << std::endl;
  } else { std::cout << "ERROR EVP_DecryptUpdate" << std::endl; }
  

  int ret = EVP_DecryptFinal_ex(ctx, plaintext, len+2);
  if(ret == 1) {
      /* Success */
      std::cout << "SUCCESS EVP_DecryptFinal_ex" << std::endl;
  } else {
      /* Verify failed */
      std::cout << "ERROR EVP_DecryptFinal_ex" << std::endl;

  }

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  //std::cout << "PLAINTEXT: " << plaintext << std::endl;
/*   unsigned char k[key.size()+1];
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
  std::cout << "return: " << do_decrypt << std::endl; */
}

std::vector<std::byte> getBytes(std::string const &s)
{
    std::vector<std::byte> bytes;
    bytes.reserve(std::size(s));
 
    std::transform(std::begin(s), std::end(s), std::back_inserter(bytes), [](char const &c){
        return std::byte(c);
    });
 
    return bytes;
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

int httpSend(struct tls &ctx, struct tls_config &cfg, HttpRequest &request, HttpResponse &response,
             const char *pemBundleString, unsigned int pemBundleLength) {

  ssize_t writelen;

  if (tls_connect(&ctx, request.host.c_str(),
          (request.portstr.length() == 0 ? "443" : request.portstr.c_str())) !=
      0) {
    std::cerr << "tls_connect: " << tls_error(&ctx) << std::endl;
    return 6;
  } else { std::cout << "tls_connect success" << std::endl; }

    std::string requestStr = request.generate();     
    HttpReader *httpReader = HttpReaderNew(response);
    if ((writelen = tls_write(&ctx, requestStr.c_str(), requestStr.length())) <
        0) {
      std::cerr << "tls_write: " << tls_error(&ctx) << std::endl;
      return 7;
    } else { std::cout << "tls_write success" << std::endl; }

    char readbuf[8192] {0};
    size_t readlen;
    std::vector<std::string> vect;
    while ((readlen = tls_read(&ctx, readbuf, sizeof(readbuf) - 1)) > 0) {
      readbuf[readlen] = 0;
      vect.push_back(readbuf);
      httpReader->onBuffer(readbuf, readlen, sizeof(readbuf));
      if (httpReader->isFinished())
        break;
    }
    delete httpReader;
    parse_response(vect);

  tls_free(&ctx);
  tls_config_free(&cfg);

  return 0;
}

void do_http(struct tls &ctx, struct tls_config &cfg, const char *pemBundleString, unsigned int pemBundleLength, const char *url){
    HttpRequest request = HttpRequest(url);    
    HttpResponse response = HttpResponse();
    request.customHeaders.push_back(HttpHeader("User-Agent", USER_AGENT));
    if (httpSend(ctx, cfg, request, response, pemBundleString, pemBundleLength)) {
      std::cerr << "request failed" << std::endl;
    }
    printf("success\tstatusCode:%d headers:%lu response:%lu bytes\n",
          response.statusCode, response.headers.size(), response.body.length());
    //std::this_thread::sleep_for(40ms);
}

std::string_view get_option(
    const std::vector<std::string_view>& args, 
    const std::string_view& option_name) {
    for (auto it = args.begin(), end = args.end(); it != end; ++it) {
        if (*it == option_name)
            if (it + 1 != end)
                return *(it + 1);
    } 
    return "";
}

bool has_option(
    const std::vector<std::string_view>& args, 
    const std::string_view& option_name) {
    for (auto it = args.begin(), end = args.end(); it != end; ++it) {
        if (*it == option_name)
            return true;
    }   
    return false;
}
