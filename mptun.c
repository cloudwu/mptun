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

#define MAX_ADDRESS 16
#define BASE_COUNT 64
#define MAX_COUNT 16384
/* buffer for reading , must be >= 1500 */
#define BUFF_SIZE 2000   
#define IP_SIZE 128

// todo: support ipv6
typedef struct sockaddr_in SOCKADDR;
typedef struct in_addr INADDR;

struct tundev {
	int port;
	int tunfd;
	int remote_n;
	int local_n;
	SOCKADDR remote[MAX_ADDRESS];
	INADDR local[MAX_ADDRESS];
	int localfd[MAX_ADDRESS];
	int remote_count[MAX_ADDRESS];
	int local_count[MAX_ADDRESS];
};

static int
tun_alloc(char *dev) {
	struct ifreq ifr;
	int fd, err;

	if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
		perror("Opening /dev/net/tun");
		return fd;
	}

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
		perror("ioctl(TUNSETIFF)");
		close(fd);
		return err;
	}

	strcpy(dev, ifr.ifr_name);

	return fd;
}

static int
inet_bind(INADDR *addr, int port) {
	int reuse = 1;
	SOCKADDR address;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		return fd;
	}
	address.sin_family = AF_INET;
	address.sin_addr = *addr;
	address.sin_port = htons(port);

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&reuse, sizeof(int)) ==-1) {
		close(fd);
		return -1;
	}

	if (bind(fd, (struct sockaddr*)&address, sizeof(address)) != 0) {
		perror("bind");
		close(fd);
		return -1;
	}

	return fd;
}

static void
usage(void) {
	fprintf(stderr,
		"Usage:\n"
		"\t-i <ifacename>: Name of interface to use (for example: tun0)\n"
		"\t-v <vpnlocalIP> : specify vpn address (for example: 10.0.0.1)\n"
		"\t-t <vpnremoteIP> : specify vpn P-t-P address (for example: 10.0.0.2)\n"
		"\t-r <remoteIP> : specify remote address, it can specify multi times. (or zero, if you run as server) \n"
		"\t-l <localIP> : specify local address, it can specify multi times. (or zero, if you run as server) \n"
		"\t-p <port> : specify port for tunnel\n"
	);
	exit(1);
}

// forward ip packet from internet to tun , and return peer address 
static int
inet_to_tun(int inetfd, int tunfd, SOCKADDR *sa) {
	char buf[BUFF_SIZE];
	ssize_t n;
	for (;;) {
		socklen_t addrlen = sizeof(*sa);
		n = recvfrom(inetfd, buf, BUFF_SIZE, 0,(struct sockaddr *)sa, &addrlen);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			else {
				perror("recvfrom");
				exit(1);
				// fail
				return 0;
			}
		} else {
			break;
		}
	}
	char tmp[1024];
	inet_ntop(AF_INET, &sa->sin_addr, tmp, sizeof(tmp));

	printf("Read %d bytes from inet %d %s:%d\n", (int)n, inetfd, tmp, ntohs(sa->sin_port));
	for (;;) {
		int ret = write(tunfd, buf, n);
		if (ret < 0) {
			if (errno == EINTR) {
				continue;
			}
			else {
				perror("write tun");
				exit(1);
				return 0;
			}
		} else {
			break;
		}
	}
	printf("Write %d bytes to tun %d\n", (int)n, tunfd);

	// succ
	return 1;
}

static void
drop_tun(int tunfd) {
	char buf[BUFF_SIZE];
	ssize_t n;
	for (;;) {
		n = read(tunfd, buf, BUFF_SIZE);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			else {
				perror("drop");
				exit(1);
				return;
			}
		} else {
			break;
		}
	}
	printf("drop %d bytes\n", (int)n);
}

// forward ip packet from tun to internet with address
static void
tun_to_inet(int tunfd, int inetfd, SOCKADDR *addr) {
	char buf[BUFF_SIZE];
	ssize_t n;
	for (;;) {
		n = read(tunfd, buf, BUFF_SIZE);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			else {
				perror("read tun");
				exit(1);
				return;
			}
		} else {
			break;
		}
	}
	printf("Read %d bytes from tun %d\n", (int)n, tunfd);

	for (;;) {
		int ret = sendto(inetfd, buf, n, 0, (struct sockaddr *)addr, sizeof(SOCKADDR));
		if (ret < 0 && errno == EINTR) {
			continue;
		} else {
			break;
		}
	}

	char tmp[1024];
	inet_ntop(AF_INET, &addr->sin_addr, tmp, sizeof(tmp));

	printf("Write %d bytes to inet %d %s:%d\n", (int)n, inetfd, tmp, ntohs(addr->sin_port));
}

static int
choose_local(struct tundev *tdev, fd_set *set) {
	int i;
	int t = 0;
	int r;
	if (tdev->local_n == 1) {
		return 0;
	}
	for (i=0;i<tdev->local_n;i++) {
		if (FD_ISSET(tdev->localfd[i], set)) {
			t += BASE_COUNT + tdev->local_count[i];
		}
	}
	if (t == 0)
		return 0;
	r = random() % t;
	t = 0;
	for (i=0;i<tdev->local_n;i++) {
		if (FD_ISSET(tdev->localfd[i], set)) {
			t += BASE_COUNT + tdev->local_count[i];
			if (r < t) {
				return i;
			}
		}
	}
	return 0;
}

static int
choose_remote(struct tundev *tdev) {
	int i;
	int t = 0;
	int r;
	if (tdev->remote_n <= 1)
		return 0;
	for (i=0;i<tdev->remote_n;i++) {
		t += BASE_COUNT + tdev->remote_count[i];
	}
	r = random() % t;
	t = 0;
	for (i=0;i<tdev->remote_n;i++) {
		t += BASE_COUNT + tdev->remote_count[i];
		if (r < t) {
			return i;
		}
	}
	return 0;
}

static void
add_remote(struct tundev *tdev, SOCKADDR *addr) {
	int i;
	int mincount = MAX_COUNT;
	int minidx = -1;
	for (i=0;i<tdev->remote_n;i++) {
		if (memcmp(addr, &tdev->remote[i], sizeof(*addr))==0) {
			if (++tdev->remote_count[i] > MAX_COUNT) {
				int j;
				for (j=0;j<tdev->remote_n;i++) {
					tdev->remote_count[i] /= 2;
				}
			}
			return;
		} else if (tdev->remote_count[i] < mincount) {
			mincount = tdev->remote_count[i];
			minidx = i;
		}
	}
	if (tdev->remote_n < MAX_ADDRESS) {
		i = tdev->remote_n++;
	} else {
		i = minidx;
	}
	tdev->remote[i] = *addr;
	tdev->remote_count[i] = 0;
}

static void
forwarding(struct tundev *tdev, int maxrd, fd_set *rdset, int maxwt, fd_set *wtset) {
	int i;
	fd_set rd,wt;

	// read
	rd = *rdset;
	for (;;) {
		int ret = select(maxrd, &rd, NULL, NULL, NULL);
		if (ret < 0) {
			if (errno == EINTR) {
				continue;
			}
			perror("select read");
			exit(1);
		} else {
			break;
		}
	}

	for (i=0;i<tdev->local_n;i++) {
		if (FD_ISSET(tdev->localfd[i], &rd)) {
			SOCKADDR addr;
			// forward ip packet of inet to tun
			if (++tdev->local_count[i] > MAX_COUNT) {
				int j;
				for (j=0;j<tdev->local_n;j++) {
					tdev->local_count[j] /= 2;
				}
			}
			if (inet_to_tun(tdev->localfd[i], tdev->tunfd, &addr)) {
				add_remote(tdev, &addr);
			}
		}
	}

	if (FD_ISSET(tdev->tunfd, &rd)) {
		// forward ip packet of tun to inet
		wt = *wtset;
		for (;;) {
			int ret = select(maxwt, NULL, &wt, NULL, NULL);
			if (ret < 0) {
				if (errno == EINTR) {
					continue;
				}
				perror("select write");
				exit(1);
			} else {
				break;
			}
		}
		if (tdev->remote_n == 0) {
			drop_tun(tdev->tunfd);
		} else {
			tun_to_inet(tdev->tunfd, 
				tdev->localfd[choose_local(tdev, &wt)],
				&tdev->remote[choose_remote(tdev)]);
		}
	}
}

static void
start(struct tundev *tdev) {
	int i;
	int maxrd_fd = tdev->tunfd;
	int maxwt_fd = -1;
	fd_set rdset, wtset;
	FD_ZERO(&rdset);
	FD_ZERO(&wtset);
	FD_SET(tdev->tunfd, &rdset);
	for (i=0;i<tdev->local_n;i++) {
		FD_SET(tdev->localfd[i], &rdset);
		FD_SET(tdev->localfd[i], &wtset);
		if (tdev->localfd[i] > maxrd_fd)
			maxrd_fd = tdev->localfd[i];
		if (tdev->localfd[i] > maxwt_fd)
			maxwt_fd = tdev->localfd[i];
	}

	for (;;) {
		forwarding(tdev, maxrd_fd+1, &rdset, maxwt_fd+1, &wtset);
	}
}

static void
ifconfig(const char * ifname, const char * va, const char *pa) {
	char cmd[1024];
	snprintf(cmd, sizeof(cmd), "ifconfig %s %s netmask 255.255.255.255 pointopoint %s",
		ifname, va, pa);
	if (system(cmd) < 0) {
		perror(cmd);
		exit(1);
	}
}

int
main(int argc, char *argv[]) {
	int i;
	int option;
	char ifname[IFNAMSIZ] = "";
	char vpnaddress[IP_SIZE] = "";
	char ptpaddress[IP_SIZE] = "";
	struct tundev tdev;
	memset(&tdev, 0, sizeof(tdev));

	while ((option = getopt(argc, argv, "i:v:t:r:l:p:")) > 0) {
		INADDR addr;
		switch(option) {
		case 'i':
			strncpy(ifname,optarg,IFNAMSIZ-1);
			break;
		case 'v':
			strncpy(vpnaddress,optarg,IP_SIZE-1);
			break;
		case 't':
			strncpy(ptpaddress,optarg,IP_SIZE-1);
			break;
		case 'p':
			tdev.port = strtol(optarg, NULL, 0); 
			break;
		case 'l':
		case 'r':
			if (inet_pton(AF_INET, optarg, &addr) <= 0) {
				fprintf(stderr, "Invalid ip : %s\n", optarg);
				return 1;
			}
			if (option == 'l') {
				if (tdev.local_n >= MAX_ADDRESS) {
					fprintf(stderr, "Too many local ip\n");
					return 1;
				}
				tdev.local[tdev.local_n++] = addr;
			} else {
				SOCKADDR *sa = &tdev.remote[tdev.remote_n];
				if (tdev.remote_n >= MAX_ADDRESS) {
					fprintf(stderr, "Too many remote ip\n");
					return 1;
				}
				++tdev.remote_n;
				sa->sin_addr = addr;
			}
			break;
		default:
			usage();
			break;
		}
	}
	if (tdev.port == 0 || ifname[0] == '\0' || vpnaddress[0] == '\0' || ptpaddress[0] == '\0') {
		usage();
		return 1;
	}

	if ((tdev.tunfd = tun_alloc(ifname)) < 0) {
		return 1;
	}

	ifconfig(ifname, vpnaddress, ptpaddress);

	if (tdev.local_n == 0) {
		INADDR *addr = &tdev.local[tdev.local_n++];
		addr->s_addr = htonl(INADDR_ANY);
	}

	for (i=0;i<tdev.local_n;i++) {
		int fd = inet_bind(&tdev.local[i], tdev.port);
		if (fd < 0) {
			// no need to close tdev.localfd[], because exit 1
			return 1;
		}
		tdev.localfd[i] = fd;
	}

	for (i=0;i<MAX_ADDRESS;i++) {
		tdev.remote[i].sin_family = AF_INET;
		tdev.remote[i].sin_port = htons(tdev.port);
	}

	start(&tdev);

	return 0;
}
