#include <iostream>
#include <vector>
#include <numeric>
#include <iostream>
#include <iomanip>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <openssl/bio.h>
#include <openssl/err.h>

namespace
{
    int closesocket(int sock)
    {
        return close(sock);
    }

    template<typename T>
    struct deleter_impl
    {
    };

    template<typename T>
    struct deleter
    {
        void operator()(T* ptr)
        {
            // Rather than specialize Deleter for each type, we specialize
            // DeleterImpl. This allows bssl::UniquePtr<T> to be used while only
            // including base.h as long as the destructor is not emitted. This matches
            // std::unique_ptr's behavior on forward-declared types.
            //
            // DeleterImpl itself is specialized in the corresponding module's header
            // and must be included to release an object. If not included, the compiler
            // will error that DeleterImpl<T> does not have a method Free.
            deleter_impl<T>::Free(ptr);
        }
    };
}

#define FXBRAIN_MAKE_DELETER(type, deleter)     \
  namespace  {                            \
  template <>                                     \
  struct deleter_impl<type> {                      \
    static void Free(type *ptr) { deleter(ptr); } \
  };                                              \
  }

namespace fxbrain
{
    struct scoped_socket
    {
        scoped_socket(int sock)
                :sock_(sock) { }

        ~scoped_socket()
        {
            closesocket(sock_);
        }

    private:
        const int sock_;
    };

    template<typename T>
    using UniquePtr = std::unique_ptr<T, deleter<T>>;
}

FXBRAIN_MAKE_DELETER(BIO, BIO_free)

namespace
{
    bool test_socket_connect()
    {
        const char* test_msg = "this is a test";
        int listening_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (listening_sock==-1) {
            return false;
        }
        fxbrain::scoped_socket listening_sock_closer(listening_sock);

        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        if (!inet_pton(AF_INET, "127.0.0.1", &sin.sin_addr)) {
            return false;
        }
        if (bind(listening_sock, (struct sockaddr*) &sin, sizeof(sin))!=0) {
            return false;
        }
        if (listen(listening_sock, 1)) {
            return false;
        }
        socklen_t sockaddr_len = sizeof(sin);
        if (getsockname(listening_sock, (struct sockaddr*) &sin, &sockaddr_len) ||
                sockaddr_len!=sizeof(sin)) {
            return false;
        }

        char hostname[80];
        BIO_snprintf(hostname, sizeof(hostname), "%s:%d", "127.0.0.1",
                ntohs(sin.sin_port));

        fxbrain::UniquePtr<BIO> bio(BIO_new_connect(hostname));
        if (!bio) {
            fprintf(stderr, "BIO_new_connect failed.\n");
            return false;
        }

        if (BIO_write(bio.get(), test_msg, sizeof(test_msg))!=
                sizeof(test_msg)) {
            fprintf(stderr, "BIO_write failed.\n");
            ERR_print_errors_fp(stderr);
            return false;
        }

        int sock = accept(listening_sock, (struct sockaddr*) &sin, &sockaddr_len);
        if (sock==-1) {
            return false;
        }

        fxbrain::scoped_socket sock_closer(sock);
        char buf[sizeof(test_msg)];
        if (recv(sock, buf, sizeof(buf), 0)!=sizeof(test_msg)) {
            return false;
        }
        if (memcmp(buf, test_msg, sizeof(test_msg))) {
            return false;
        }

        return true;
    }
}

union u_double
{
    double dbl;
    char data[sizeof(double)];
};

static void dump_double(union u_double d)
{
    int exp;
    long long mant;

    printf("64-bit float: sign: %d, ", (d.data[0] & 0x80) >> 7);
    exp = ((d.data[0] & 0x7F) << 4) | ((d.data[1] & 0xF0) >> 4);
    printf("expt: %4d (unbiassed %5d), ", exp, exp-1023);
    mant = ((((d.data[1] & 0x0F) << 8) | (d.data[2] & 0xFF)) << 8) | (d.data[3] & 0xFF);
    mant = (mant << 32) | ((((((d.data[4] & 0xFF) << 8) | (d.data[5] & 0xFF)) << 8) |
            (d.data[6] & 0xFF)) << 8) | (d.data[7] & 0xFF);
    printf("mant: %16lld (0x%013llX)\n", mant, mant);
}

int main()
{

    union u_double d;

    double a = 36.95*100;
    d.dbl = a;

    dump_double(d);

    std::cout << "Test socket connect : " << std::boolalpha << test_socket_connect() << std::endl;
}