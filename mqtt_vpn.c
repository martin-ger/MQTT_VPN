/**************************************************************************
 * mqtt_vpn.c                                                             *
 *                                                                        *
 * A simple IPv4 tunnelling program using tun interfaces and MQTT.        * 
 *                                                                        *
 * Based on work from Davide Brini                                        *
 * (C) 2009 Davide Brini.                                                 *
 *                                                                        *
 * Uses the Paho MQTT C Client Library                                    *
 * https://www.eclipse.org/paho/files/mqttdoc/MQTTClient/html/index.html  *
 *                                                                        *
 * DISCLAIMER AND WARNING: this is all work in progress. The code is      *
 * ugly, the algorithms are naive, error checking and input validation    *
 * are very basic, and of course there can be bugs. If that's not enough, *
 * the program has not been thoroughly tested, so it might even fail at   *
 * the few simple things it should be supposed to do right.               *
 * Needless to say, I take no responsibility whatsoever for what the      *
 * program might do. The program has been written mostly for learning     *
 * purposes, and can be used in the hope that is useful, but everything   *
 * is to be taken "as is" and without any kind of warranty, implicit or   *
 * explicit. See the file LICENSE for further details.                    *
 *************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <time.h>

#include "MQTTClient.h"
#include "nacl/crypto_hash.h"
#include "nacl/crypto_secretbox.h"

/* MQTT related defs */
#define CLIENTID_PRE "MQTT_VPN_"
#define TOPIC_PRE "mqttip"
#define QOS 0
#define TIMEOUT 10000L

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000
#define CLIENT 0
#define SERVER 1
#define PORT 55555

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

#define HOST "fec2::22"
//#define ifreq_offsetof(x) offsetof(struct ifreq, x)

struct in6_ifreq
{
  struct in6_addr ifr6_addr;
  __u32 ifr6_prefixlen;
  unsigned int ifr6_ifindex;
};

MQTTClient client;
MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
char *receive_topic, *broadcast_topic;
#define N_ADDR_MAX 10
uint8_t n_addr=0;
char *addr_topic[N_ADDR_MAX];
u_char key[crypto_secretbox_KEYBYTES];
unsigned char key_set = 0;

char *if_addr = NULL;
char *broker = NULL;
char *cl_id = NULL;

int debug;
char *progname;
int tap_fd, net2tap = 0;

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
int tun_alloc(char *dev, int flags)
{

  struct ifreq ifr;
  int fd, err;

  if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
  {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev)
  {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0)
  {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, unsigned char *buf, int n)
{

  int nread;

  if ((nread = read(fd, buf, n)) < 0)
  {
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, unsigned char *buf, int n)
{

  int nwrite;

  if ((nwrite = write(fd, buf, n)) < 0)
  {
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts those into "buf".    *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, unsigned char *buf, int n)
{

  int nread, left = n;

  while (left > 0)
  {
    if ((nread = cread(fd, buf, left)) == 0)
    {
      return 0;
    }
    else
    {
      left -= nread;
      buf += nread;
    }
  }
  return n;
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...)
{

  va_list argp;

  if (debug)
  {
    va_start(argp, msg);
    vfprintf(stderr, msg, argp);
    va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...)
{

  va_list argp;

  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void)
{
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <if_name> -a <ip> -b <broker> [-m <netmask>] [-n <clientid>] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <if_name>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-a <ip>: IP address of interface to use (mandatory)\n");
  fprintf(stderr, "-b <broker>: Address of MQTT broker (like: tcp://broker.io:1883) (mandatory)\n");
  fprintf(stderr, "-u <username>: user of the MQTT broker\n");
  fprintf(stderr, "-p <password>: password of the MQTT broker user\n");
  fprintf(stderr, "-k <password>: preshared key for all clients of this VPN\n");
  fprintf(stderr, "-m <netmask>: Netmask of interface to use (default 255.255.255.0)\n");
  fprintf(stderr, "-6 <ip6>: IPv6 address of interface to use\n");
  fprintf(stderr, "-x <prefix>: prefix length of the IPv6 address (default 64)\n");
  fprintf(stderr, "-n <clientid>: ID of MQTT client (%s<random>)\n", CLIENTID_PRE);
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-t <ip>: IP address of a target to NAT\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}

/**************************************************************************
 * MQTT callback functions.                                               *
 **************************************************************************/

void delivered(void *context, MQTTClient_deliveryToken dt)
{
  fprintf(stderr, "Message with token value %d delivery confirmed\n", dt);
}

int msgarrvd(void *context, char *topicName, int topicLen, MQTTClient_message *message)
{
  int nwrite;
  unsigned int packet_len;
  unsigned char *packet_start;
  int packet_ok = 1;

  do_debug("Message arrived %d bytes on topic: %s\n", message->payloadlen, topicName);

  uint8_t i=0;
  while (i<n_addr && !(strncmp(topicName, addr_topic[i], topicLen) == 0))
  {
    ++i;
  }

  if (i<n_addr)
  {
    net2tap++;

    packet_start = message->payload;
    packet_len = message->payloadlen;
    unsigned char m[packet_len];

    if (key_set)
    {
      if ((packet_len <= crypto_secretbox_NONCEBYTES + crypto_secretbox_ZEROBYTES) ||
         (crypto_secretbox_open(m, packet_start + crypto_secretbox_NONCEBYTES, packet_len - crypto_secretbox_NONCEBYTES, packet_start, key) == -1))
      {
        do_debug("NET2TAP %lu: Decrypt Error\r\n", net2tap);
        packet_ok = 0;
      } else {
        packet_start = m + crypto_secretbox_ZEROBYTES;
        packet_len = packet_len - crypto_secretbox_NONCEBYTES - crypto_secretbox_ZEROBYTES;
      }
    }

    if (packet_ok)
    {
      /* write it into the tun/tap interface */
      if (packet_len <= 1500)
      {
        nwrite = cwrite(tap_fd, (unsigned char *)packet_start, packet_len);
        do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
      }
      else
      {
        do_debug("NET2TAP %lu: %d bytes too long to write the tap interface\n", net2tap, message->payloadlen);
      }
    }
  }

  MQTTClient_freeMessage(&message);
  MQTTClient_free(topicName);

  return 1;
}

void mqtt_if_add_reading_topic(const char* addr)
{
  // warning : silently discard address registration above N_ADDR_MAX
  if (n_addr<N_ADDR_MAX)
  {
    addr_topic[n_addr] = malloc(sizeof(TOPIC_PRE) + strlen(addr) + 2);
    sprintf(addr_topic[n_addr], "%s/%s", TOPIC_PRE, addr);
    n_addr++;
  }
}

void mqtt_if_subscribe()
{
  for (uint8_t i=0; i<n_addr; ++i)
  {
    do_debug("Subscribing to topic %s\n", addr_topic[i]);
    MQTTClient_subscribe(client, addr_topic[i], QOS);
  }
}

void mqttconnect()
{
  int rc;

  if ((rc = MQTTClient_connect(client, &conn_opts)) != MQTTCLIENT_SUCCESS)
  {
    fprintf(stderr, "Failed to connect, return code %d\n", rc);
    exit(-1);
  }
  do_debug("Successfully connected client %s to the MQTT broker %s\n", cl_id, broker);

  mqtt_if_add_reading_topic(if_addr);
  mqtt_if_add_reading_topic("255.255.255.255");
  mqtt_if_subscribe();

  fprintf(stderr, "MQTT VPN client %s on broker %s for ip address %s started\n", cl_id, broker, if_addr);
}
void connlost(void *context, char *cause)
{
  fprintf(stderr, "\nConnection lost\n");
  fprintf(stderr, "     cause: %s\n", cause);
  fprintf(stderr, "\nReconnecting...\n");
  mqttconnect();
}

int main(int argc, char *argv[])
{

  int option;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  char if_mask[20] = "255.255.255.0";
  char *if_addr6 = NULL;
  int pre6 = 64;
  int maxfd;
  uint16_t nread;
  unsigned char buffer[BUFSIZE];
  unsigned char plain_buf[BUFSIZE + crypto_secretbox_ZEROBYTES];
  unsigned char cypher_buf[BUFSIZE + crypto_secretbox_NONCEBYTES + crypto_secretbox_ZEROBYTES];
  int ip_fd, ip6_fd;
  unsigned long int tap2net = 0;
  struct ifreq ifr;
  struct sockaddr_in6 sai;
  struct in6_ifreq ifr6;
  unsigned char h[crypto_hash_BYTES];

  MQTTClient_SSLOptions ssl_opts = MQTTClient_SSLOptions_initializer;
  MQTTClient_message pubmsg = MQTTClient_message_initializer;
  MQTTClient_deliveryToken token;

  progname = argv[0];
  srand(time(NULL));

  /* Check command line options */
  while ((option = getopt(argc, argv, "i:a:m:k:6:x:b:u:p:n:t:hd")) > 0)
  {
    switch (option)
    {
    case 'd':
      debug = 1;
      break;
    case 'h':
      usage();
      break;
    case 'i':
      strncpy(if_name, optarg, IFNAMSIZ - 1);
      break;
    case 'a':
      if_addr = optarg;
      break;
    case 'k':
      crypto_hash(h, (unsigned char *)optarg, strlen(optarg));
      memcpy(key, h, crypto_secretbox_KEYBYTES);
      key_set = 1;
      break;
    case '6':
      if_addr6 = optarg;
      break;
    case 'x':
      pre6 = atoi(optarg);
      break;
    case 'b':
      broker = optarg;
      break;
    case 'u':
      conn_opts.username = optarg;
      break;
    case 'p':
      conn_opts.password = optarg;
      break;
    case 'n':
      cl_id = optarg;
      break;
    case 'm':
      strncpy(if_mask, optarg, sizeof(if_mask));
      if_addr[sizeof(if_mask) - 1] = '\0';
      break;
    case 't':
      mqtt_if_add_reading_topic(optarg);
      break;
    default:
      my_err("Unknown option %c\n", option);
      usage();
    }
  }

  argv += optind;
  argc -= optind;

  if (argc > 0)
  {
    my_err("Too many options!\n");
    usage();
  }

  if (*if_name == '\0')
  {
    my_err("Must specify interface name!\n");
    usage();
  }

  if (if_addr == NULL)
  {
    my_err("Must specify interface address!\n");
    usage();
  }

  if (broker == NULL)
  {
    my_err("Must specify broker address!\n");
    usage();
  }

  if (cl_id == NULL)
  {
    cl_id = malloc(sizeof(CLIENTID_PRE) + 20);
    sprintf(cl_id, "%s%u", CLIENTID_PRE, rand());
  }

  /* initialize tun/tap interface */
  if ((tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0)
  {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  }

  do_debug("Successfully connected to interface %s\n", if_name);

  if ((ip_fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0)
  {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  }

  strncpy(ifr.ifr_name, if_name, IFNAMSIZ);

  ifr.ifr_addr.sa_family = AF_INET;
  struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
  inet_pton(AF_INET, if_addr, &addr->sin_addr);
  if (ioctl(ip_fd, SIOCSIFADDR, &ifr) < 0)
  {
    my_err("Error setting IP addr to tun/tap interface %s!\n", if_name);
    exit(1);
  }

  inet_pton(AF_INET, if_mask, &addr->sin_addr);
  if (ioctl(ip_fd, SIOCSIFNETMASK, &ifr) < 0)
  {
    my_err("Error setting netmask to tun/tap interface %s!\n", if_name);
    exit(1);
  }

  if (if_addr6 != NULL)
  {
    ip6_fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP);

    memset(&sai, 0, sizeof(struct sockaddr));
    sai.sin6_family = AF_INET6;
    sai.sin6_port = 0;

    if (inet_pton(AF_INET6, if_addr6, (void *)&sai.sin6_addr) < 0)
    {
      my_err("Bad address %s\n", if_addr6);
      return (1);
    }
    memcpy((char *)&ifr6.ifr6_addr, (char *)&sai.sin6_addr, sizeof(struct in6_addr));

    if (ioctl(ip6_fd, SIOGIFINDEX, &ifr) < 0)
    {
      perror("SIOGIFINDEX");
    }
    ifr6.ifr6_ifindex = ifr.ifr_ifindex;
    ifr6.ifr6_prefixlen = pre6;
    if (ioctl(ip6_fd, SIOCSIFADDR, &ifr6) < 0)
    {
      perror("SIOCSIFADDR");
    }
  }

  if (ioctl(ip_fd, SIOCGIFFLAGS, &ifr) < 0)
  {
    my_err("Error reading tun/tap interface %s flags!\n", if_name);
    exit(1);
  }

  ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
  if (ioctl(ip_fd, SIOCSIFFLAGS, &ifr) < 0)
  {
    my_err("Error setting tun/tap interface %s up!\n", if_name);
    exit(1);
  }

  do_debug("Successfully initialized interface %s\n", if_name);

  MQTTClient_create(&client, broker, cl_id,
                    MQTTCLIENT_PERSISTENCE_NONE, NULL);
  conn_opts.keepAliveInterval = 20;
  conn_opts.cleansession = 1;

  MQTTClient_setCallbacks(client, NULL, connlost, msgarrvd, delivered);
  ssl_opts.verify = 0;
  ssl_opts.enableServerCertAuth = 0;
  conn_opts.ssl = &ssl_opts;

  mqttconnect();

  /* use select() to handle more than one descriptor at once */
  maxfd = tap_fd;

  while (1)
  {
    int ret;
    fd_set rd_set;

    FD_ZERO(&rd_set);
    FD_SET(tap_fd, &rd_set);

    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

    if (ret < 0 && errno == EINTR)
    {
      continue;
    }

    if (ret < 0)
    {
      perror("select()");
      exit(1);
    }

    if (FD_ISSET(tap_fd, &rd_set))
    {
      /* data from tun/tap: just read it and write it to the MQTT topic */
      char send_topic[sizeof(TOPIC_PRE) + 20];

      nread = cread(tap_fd, buffer, BUFSIZE);
      if ((buffer[0] & 0xf0) != 0x40 || nread < IP_HDR_LEN)
      {
        do_debug("Invalid IPv4 packet from tun if\n");
        continue;
      }

      tap2net++;
      do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);

      sprintf(send_topic, "%s/%u.%u.%u.%u", TOPIC_PRE, buffer[16], buffer[17], buffer[18], buffer[19]);
      pubmsg.qos = QOS;
      pubmsg.retained = 0;

      if (key_set)
      {
        do_debug("TAP2NET %lu: crypto_secretbox_NONCEBYTES: %d crypto_secretbox_ZEROBYTES: %d\n", tap2net, crypto_secretbox_NONCEBYTES, crypto_secretbox_ZEROBYTES);
        for (int i = 0; i < crypto_secretbox_NONCEBYTES; i++)
        {
          cypher_buf[i] = rand();
        }
        bzero(plain_buf, crypto_secretbox_ZEROBYTES);
        memcpy(plain_buf + crypto_secretbox_ZEROBYTES, buffer, nread);
        crypto_secretbox(cypher_buf + crypto_secretbox_NONCEBYTES, plain_buf, nread + crypto_secretbox_ZEROBYTES, cypher_buf, key);
        pubmsg.payload = cypher_buf;
        pubmsg.payloadlen = nread + crypto_secretbox_NONCEBYTES + crypto_secretbox_ZEROBYTES;
      }
      else
      {
        pubmsg.payload = buffer;
        pubmsg.payloadlen = nread;
      }

      MQTTClient_publishMessage(client, send_topic, &pubmsg, &token);

      do_debug("TAP2NET %lu: Written %d bytes to topic %s\n", tap2net, pubmsg.payloadlen, send_topic);
    }
  }

  return (0);
}
