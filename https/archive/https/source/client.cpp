#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <map>

#include "tls_socket.h"
#include "cipherstrings.h"
#include "http.h"

using namespace Dropper;

std::string_view lookup_value(const std::string_view sv);
std::vector<std::string_view> get_cipherstrings();

std::string_view get_option(
    const std::vector<std::string_view>& args, 
    const std::string_view& option_name);

bool has_option(
    const std::vector<std::string_view>& args, 
    const std::string_view& option_name) ;
    
int main(int argc, char* argv[])
{
    std::cout << "Dropper" << std::endl;
    const std::vector<std::string_view> args(argv, argv + argc);
     
    std::cout << "Dropper cstrings" << std::endl;
    std::vector<std::string_view> cstrings = get_cipherstrings();
    for (auto i : cstrings) { std::cout << i.data() << std::endl; }

    std::string_view cert_path;
    if ( has_option(args, "-c") ) {
        cert_path = get_option(args, "-c");
    }

    std::string_view host; 
    if ( has_option(args, "-h") ) {
        host = get_option(args, "-h");
    }
 
    std::string_view port;
    if ( has_option(args, "-p") ) {
        port = get_option(args, "-p");
    }

    std::string_view tls_version;
    if ( has_option(args, "-t") ) {
        tls_version = get_option(args, "-t");
    }

    std::string_view tls_ciphers;
    if ( has_option(args, "-z") ) {
        tls_ciphers = get_option(args, "-z");
        std::string_view zz = lookup_value(tls_ciphers);
        std::cout << "STRING VIEW LOOKUP: " << zz << std::endl;
    }

    std::string_view tls_extensions;
    if ( has_option(args, "-x") ) {
        tls_extensions = get_option(args, "-x");
    }


    Dropper::TLS_Socket a;
    a.create_socket();
    a.connect(host.data(), atoi(port.data()));
    a.set_tls_version(tls_version.data());
    a.set_tls_ciphers(tls_ciphers.data());
    a.set_tls_extensions(tls_extensions.data());
    
    std::ifstream file(cert_path.data(), std::ios::binary | std::ios::ate);
    std::streamsize size = file.tellg();
    std::vector<char> cert_buffer(size);
    file.seekg(0, std::ios::beg);

     if (file.read(cert_buffer.data(), size)){
        std::cout << "Read cert file into vector" << std::endl; }
    
    a.set_tls_cert_buff(cert_buffer);
    a.tls_connect();
    a.send();
    a.recv(); 
    a.cleanup();

    return 0;
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

std::string_view lookup_value(const std::string_view sv) {
  static constexpr auto map =
      Map<std::string_view, std::string_view, 
          cipherstrings_map.size()>{{cipherstrings_map}};
  return map.at(sv);
}

std::vector<std::string_view> get_cipherstrings(){
    //std::array<std::pair<Key, Value>, Size> data;
    static constexpr auto map =
      Map<std::string_view, std::string_view, 
          cipherstrings_map.size()>{{cipherstrings_map}};
    std::vector<std::string_view> rtn;
    //std::cout << "CIPHERSTRINGS DATA: " << cipherstrings_map.data('Size') << std::endl;
    //std::array<std::pair<Key, Value>, Size> data;
    //for (auto it : map) { std::cout << it.Key << std::endl; }
    return rtn;
}
