#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include <fcntl.h>
#include <string.h>

#include <iostream>
/*
Need to do this in order to keep the interface persistent.
   ip tuntap add dev tap0 mode tap

*/

int tuntap_open(const std::string& dev, int flags)
{
   struct ifreq ifr;
   int fd, err;

   /* Arguments taken by the function:
    *
    * char *dev: the name of an interface (or '\0'). MUST have enough
    *   space to hold the interface name if '\0' is passed
    * int flags: interface flags (eg, IFF_TUN etc.)
    */

   /* open the clone device */
   if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
      return fd;
   }

   /* preparation of the struct ifr, of type "struct ifreq" */
   memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = flags;   /* IFF_TUN or IFF_TAP, plus maybe IFF_NO_PI */

   strncpy(ifr.ifr_name, dev.c_str(), dev.size() + 1);

   /* try to create the device */
   // if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
   if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
      close(fd);
      return err;
   }
   std::cout << "Requested = " << dev << ", got " << ifr.ifr_name << std::endl;

   /* this is the special file descriptor that the caller will use to talk
    * with the virtual interface */
   return fd;
}

int main(void)
{
   tuntap_open("tap0", IFF_TAP | IFF_NO_PI);
   //NOTE: it will NOT work to pass miss-matching flags
   // tuntap_open("tap0", IFF_TUN | IFF_NO_PI);
   return 0;

}


