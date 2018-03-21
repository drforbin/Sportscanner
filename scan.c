/*
    Port scanner code in c
*/


#define _WITH_DPRINTF

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <fcntl.h>
#include <string.h>

#define TEST 1 //TEST = 1 NOTEST = 0

int cidr_to_ip_and_mask(const char *, uint32_t *, uint32_t *);

int main( int argc , char *argv[] )
{

    uint32_t ip, mask, first_ip, final_ip;
    int sock, connect_return, valopt, silent_sw = 0, log_file_sw = 0, fd_log;
    struct sockaddr_in sock_address;
    char *sock_string_address,  *cidr;
    long fcntl_arg;
    socklen_t lon;
    struct timeval tv;
    fd_set myset;
    tv.tv_sec = 0;
    tv.tv_usec = 50000;

    optind = 2;
    for (;;) {
        int opt = getopt(argc, argv, "st:o:");
        if (opt == -1)
            break;
        switch (opt) {
            case 'o':
                log_file_sw = 1;
                if( (fd_log = open(optarg ,O_CREAT | O_WRONLY, 0644 )) == -1) {
                    perror("Error occured:");
                    exit(1);
                }
                break;
            case 's':
                silent_sw = 1;
                break;
            case 't':
                tv.tv_usec = atol( optarg ) * 1000;
                break;
            default:
                return 1;
        }
    }   

    cidr = argv[1]; 
    if (cidr_to_ip_and_mask(cidr, &ip, &mask) == -1) {
        printf("error in cidr call.\n");
        exit( 1 );
    }

    first_ip = ip & mask;
    final_ip = first_ip | ~mask;
    sock_address.sin_family = AF_INET;
    sock_address.sin_port = htons( 80 );

    #if TEST
    printf("Timeout microsec:%d\n", tv.tv_usec);
    sock_address.sin_addr.s_addr = htonl( first_ip );
    printf("first_ip:%s\n", inet_ntoa( sock_address.sin_addr ) );
    sock_address.sin_addr.s_addr = htonl( final_ip );
    printf("final_ip:%s\n\n", inet_ntoa( sock_address.sin_addr ) );
    #endif

    //Start the port scan loop
    for( uint32_t i = first_ip; i <= final_ip; i++){

        sock_address.sin_addr.s_addr =  htonl( i ); 
        sock_string_address = inet_ntoa( sock_address.sin_addr );

        //Create a socket of type internet
        if( ( sock = socket(AF_INET , SOCK_STREAM , 0 ) ) == -1 ){
            perror("socket error");
            exit( 1 );
        }

        //non-block
        fcntl_arg = fcntl(sock, F_GETFL, NULL);
        fcntl_arg |= O_NONBLOCK;
        fcntl(sock, F_SETFL, fcntl_arg);

        #if TEST
        printf("address is:%s\n",  sock_string_address );
        #endif

        //Connect using that socket and sockaddr structure
        connect_return = connect(sock, ( struct sockaddr * ) &sock_address, 
                        sizeof sock_address ); 
        if( ( connect_return == -1 ) && errno == EINPROGRESS ) {
            FD_ZERO( &myset );
            FD_SET(sock, &myset );
            if( select( sock+1, NULL, &myset, NULL, &tv ) == 0 ){
                close( sock );
                continue;
            }
            lon = sizeof( int );
            getsockopt( sock, SOL_SOCKET, SO_ERROR, (void*) &valopt, &lon);
            if( !( silent_sw == 1 ) )
                printf("Host is up:%s Reason:%s\n", sock_string_address, strerror( valopt ) );
            if( log_file_sw == 1 )
                dprintf(fd_log, "Host is up:%s Reason:%s\n", sock_string_address, strerror( valopt ) );
            close( sock );
        }
    }
    close( fd_log );
    if( !( silent_sw == 1 ) )
        printf("\nDone.\n");
    return 0;
}



int cidr_to_ip_and_mask(const char *cidr, uint32_t *ip, uint32_t *mask)
{
    uint8_t a, b, c, d, bits;
    if (sscanf(cidr, "%hhu.%hhu.%hhu.%hhu/%hhu", &a, &b, &c, &d, &bits) < 5) {
        return -1; /* didn't convert enough of CIDR */
    }
    if (bits > 32) {
        return -1; /* Invalid bit count */
    }
    *ip =
        (a << 24UL) |
        (b << 16UL) |
        (c << 8UL) |
        (d);
    *mask = (0xFFFFFFFFUL << (32 - bits)) & 0xFFFFFFFFUL;
}
