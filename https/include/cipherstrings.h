#include <string>
#include <map>
#include <array>
#include <utility> 

namespace Dropper {

template <typename Key, typename Value, std::size_t Size>
struct Map {
  std::array<std::pair<Key, Value>, Size> data;

  [[nodiscard]] constexpr Value at(const Key &key) const {
    const auto itr =
        std::find_if(begin(data), end(data),
                     [&key](const auto &v) { return v.first == key; });
    if (itr != end(data)) {
      return itr->second;
    } else {
      throw std::range_error("Not Found");
    }
  }

};

using namespace std::literals::string_view_literals;
static constexpr std::array<std::pair<std::string_view, std::string_view>, 46> cipherstrings_map{
    {
        {"ADH"sv, "Cipher suites using ephemeral DH for key exchange without doing any server authentication. Equivalent to DH+aNULL"sv},
        {"AEAD"sv, "Cipher suites using Authenticated Encryption with Additional Data"sv},
        {"AECDH"sv, "Ciphersuites using ephemeral ECDH for key exchange without doing any server authentication. Equivalent to ECDH+aNULL"sv},
        {"aECDSA"sv, "Cipher suites using ECDSA server authentication"sv},
        {"AES"sv, "Cipher suites using AES or AESGCM for symmetric encryption"sv},
        {"AES128"sv, "Cipher suites using AES(128) or AESGCM(128) for symmetric encryption"sv},
        {"AES256"sv, "Cipher suites using AES(256) or AESGCM(256) for symmetric encryption"sv},
        {"AESGCM"sv, "Cipher suites using AESGCM for symmetric encryption"sv},
        {"aGOST"sv, "An alias for aGOST01"sv},
        {"aGOST01"sv, "Cipher suites using GOST R 34.10-2001 server authentication"sv},
        {"ALL"sv, "All cipher suites except those selected by eNULL"sv},
        {"aNULL"sv, "Cipher suites that don't do any server authentication. Not enabled by DEFAULT. Beware of man-in-the-middle attacks"sv},
        {"aRSA"sv, "Cipher suites using RSA server authentication"sv},
        {"CAMELLIA"sv, "Cipher suites using Camellia for symmetric encryption"sv},
        {"CAMELLIA128"sv, "Cipher suites using Camellia(128) for symmetric encryption"sv},
        {"CAMELLIA256"sv, "Cipher suites using Camellia(256) for symmetric encryption"sv},
        {"CHACHA20"sv, "Cipher suites using ChaCha20-Poly1305 for symmetric encryption"sv},
        {"COMPLEMENTOFALL"sv, "Cipher suites that are not included in ALL. Currently an alias for eNULL"sv},
        {"COMPLEMENTOFDEFAULT"sv, "Cipher suites that are included in ALLsv,  but not included in DEFAULT. Currently similar to aNULL:!eNULL except for the order of the cipher suites which are not selected"sv},
        {"3DES"sv, "Cipher suites using triple DES for symmetric encryption"sv},
        {"DH"sv, "Cipher suites using ephemeral DH for key exchange"sv},
        {"DHE"sv, "Cipher suites using ephemeral DH for key exchangesv, but excluding those that don't do any server authentication. Similar to DH:!aNULL except for the order of the cipher suites which are not selected"sv},
        {"ECDH"sv, "Cipher suites using ephemeral ECDH for key exchange"sv},
        {"ECDHE"sv, "Cipher suites using ephemeral ECDH for key exchangesv, but excluding those that don't do any server authentication. Similar to ECDH:!aNULL except for the order of the cipher suites which are not selected"sv},
        {"ECDSA"sv, "An alias for aECDSA"sv},
        {"eNULL"sv, "Cipher suites that do not use any encryption. Not enabled by DEFAULTsv, and not even included in ALL"sv},
        {"GOST89MAC"sv, "Cipher suites using GOST 28147-89 for message authentication instead of HMAC"sv},
        {"GOST94"sv, "Cipher suites using HMAC based on GOST R 34.11-94 for message authentication"sv},
        {"HIGH"sv, "Cipher suites of high strength"sv},
        {"kGOST"sv, "Cipher suites using VKO 34.10 key exchangesv,  specified in RFC 4357"sv},
        {"kRSA"sv, "Cipher suites using RSA key exchange"sv},
        {"LOW"sv, "Cipher suites of low strength"sv},
        {"MD5"sv, "Cipher suites using MD5 for message authentication"sv},
        {"MEDIUM"sv, "Cipher suites of medium strength"sv},
        {"NULL"sv, "An alias for eNULL"sv},
        {"RC4"sv, "Cipher suites using RC4 for symmetric encryption"sv},
        {"RSA"sv, "Cipher suites using RSA for both key exchange and server authentication. Equivalent to kRSA+aRSA"sv},
        {"SHA"sv, "An alias for SHA1"sv},
        {"SHA1"sv, "Cipher suites using SHA1 for message authentication"sv},
        {"SHA256"sv, "Cipher suites using SHA256 for message authentication"sv},
        {"SHA384"sv, "Cipher suites using SHA384 for message authentication"sv},
        {"SSLv3"sv, "An alias for TLSv1"sv},
        {"STREEBOG256"sv, "Cipher suites using STREEBOG256 for message authentication"sv},
        {"TLSv1"sv, "Cipher suites usable with the TLSv1.0sv,  TLSv1.1sv, and TLSv1.2 protocols"sv},
        {"TLSv1.2"sv, "Cipher suites for the TLSv1.2 protocol"sv},
        {"TLSv1.3"sv, "Cipher suites for the TLSv1.3 protocol. If the control string selects at least one cipher suite but neither contains the word TLSv1.3 nor specifically includes nor excludes any TLSv1.3 cipher suitessv, all the TLSv1.3 cipher suites are made available too"sv}
    }};
}