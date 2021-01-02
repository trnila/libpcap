#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "pcap-int.h"
#include "pcap-usb-linux.h"
#include "pcap/usb.h"

#include "extract.h"

#ifdef NEED_STRERROR_H
#include "strerror.h"
#endif

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <dirent.h>
#include <byteswap.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/utsname.h>

#define VEC_SIZE 32

struct pcap_rpmsg {
  char *mmap_buf;
  size_t mmap_buflen;
};

struct rpmsg_header {
  uint32_t src;
  uint32_t dst;
  uint32_t reserved;
  uint16_t length;
  uint16_t flags;
};

struct rpmsg_mon_header {
  uint64_t timestamp;
  uint32_t interface;
  uint16_t vq;
  uint16_t res;
  struct rpmsg_header hdr;
};

struct mon_bin_mfetch {
	int32_t *offvec;   /* Vector of events fetched */
	int32_t nfetch;    /* Number of events to fetch (out: fetched) */
	int32_t nflush;    /* Number of events to flush */
};

#define MON_IOC_MAGIC 0x92

#define MON_IOCX_MFETCH _IOWR(MON_IOC_MAGIC, 7, struct mon_bin_mfetch)
#define MON_IOCH_MFLUSH _IO(MON_IOC_MAGIC, 8)

static int
rpmsg_read_mmap(pcap_t *handle, int max_packets _U_, pcap_handler callback, u_char *user) {
	struct pcap_rpmsg *handlep = handle->priv;
	struct mon_bin_mfetch fetch;
	int32_t vec[VEC_SIZE];
	struct pcap_pkthdr pkth;
	struct rpmsg_mon_header* hdr;
	int nflush = 0;
	int packets = 0;
	u_int clen, max_clen;

	max_clen = handle->snapshot - sizeof(pcap_usb_header_mmapped);

	for (;;) {
		int i, ret;
		int limit = max_packets - packets;
		if (limit <= 0)
			limit = VEC_SIZE;
		if (limit > VEC_SIZE)
			limit = VEC_SIZE;

		/* try to fetch as many events as possible*/
		fetch.offvec = vec;
		fetch.nfetch = limit;
		fetch.nflush = nflush;
		/* ignore interrupt system call errors */
		do {
			ret = ioctl(handle->fd, MON_IOCX_MFETCH, &fetch);
			if (handle->break_loop)
			{
				handle->break_loop = 0;
				return -2;
			}
		} while ((ret == -1) && (errno == EINTR));
		if (ret < 0)
		{
			if (errno == EAGAIN)
				return 0;	/* no data there */

			pcap_fmt_errmsg_for_errno(handle->errbuf,
			    PCAP_ERRBUF_SIZE, errno, "Can't mfetch fd %d",
			    handle->fd);
			return -1;
		}

		/* keep track of processed events, we will flush them later */
		nflush = fetch.nfetch;
		for (i=0; i<fetch.nfetch; ++i) {
			/* discard filler */
			hdr = (struct rpmsg_mon_header*) &handlep->mmap_buf[vec[i]];
      pkth.caplen = pkth.len = hdr->hdr.length + sizeof(struct rpmsg_mon_header);;
      pkth.ts.tv_sec = hdr->timestamp / 1000000000UL;
      pkth.ts.tv_usec = hdr->timestamp % 1000000000UL;

			if (handle->fcode.bf_insns == NULL ||
			    pcap_filter(handle->fcode.bf_insns, (u_char*) hdr,
			      pkth.len, pkth.caplen)) {
//				handlep->packets_read++;
				callback(user, &pkth, (u_char*) hdr);
				packets++;
			}
		}

		/* with max_packets specifying "unlimited" we stop afer the first chunk*/
		if (PACKET_COUNT_IS_UNLIMITED(max_packets) || (packets == max_packets))
			break;
	}

	/* flush pending events*/
	if (ioctl(handle->fd, MON_IOCH_MFLUSH, nflush) == -1) {
		pcap_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "Can't mflush fd %d", handle->fd);
		return -1;
	}
	return packets;
}

static int
rpmsg_read(pcap_t *handle, int max_packets _U_, pcap_handler callback, u_char *user) {
  int read_ret;
  int count = 0;
  struct rpmsg_mon_header *header = handle->buffer;
  char *p;

  while(1)
  {
		if (handle->break_loop)
		{
			handle->break_loop = 0;
			return PCAP_ERROR_BREAK;
		}
		read_ret = read(handle->fd, handle->buffer, handle->bufsize);
    if(read_ret < 0) {
      if(errno == EAGAIN) {
        return 0;
      }
      pcap_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
          errno, "Can't read from fd %d", handle->fd);
      return -1;
    }

    header = handle->buffer;

    struct pcap_pkthdr pkth;
    pkth.ts.tv_sec = header->timestamp / 1000000000UL;
    pkth.ts.tv_usec = header->timestamp % 1000000000UL;
    pkth.caplen = pkth.len = header->hdr.length + sizeof(struct rpmsg_mon_header);

    callback(user, &pkth, handle->buffer);
    count++;
  }

  return count;
}

static int rpmsg_activate(pcap_t* handle) {
	struct pcap_rpmsg *priv = handle->priv;
	if (handle->snapshot <= 0 || handle->snapshot > MAXIMUM_SNAPLEN)
		handle->snapshot = MAXIMUM_SNAPLEN;
	handle->setfilter_op = install_bpf_program; /* no kernel filtering */
  handle->fd = open("/dev/rpmsgmon0", O_RDWR);
  if(handle->fd < 0) {
    perror("open: ");
    exit(1);
  }
  handle->linktype = DLT_RPMSG;
	handle->bufsize = handle->snapshot;
	handle->offset = 0;
  handle->selectable_fd = handle->fd;
  handle->read_op = rpmsg_read;
	handle->set_datalink_op = NULL;	/* can't change data link type */
	handle->getnonblock_op = pcap_getnonblock_fd;
	handle->setnonblock_op = pcap_setnonblock_fd;
	handle->buffer = malloc(handle->bufsize);

  // TODO: buffer size!
  priv->mmap_buflen = 1024 * 1024 * 1024;
  priv->mmap_buf = mmap(0, priv->mmap_buflen, PROT_READ, MAP_SHARED, handle->fd, 0);
  if(priv->mmap_buf == MAP_FAILED) {
    perror("map failed\n");
  }
  handle->read_op = rpmsg_read_mmap;

	if (!handle->buffer) {
		pcap_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "malloc");
		close(handle->fd);
		return PCAP_ERROR;
	}
  printf("activate\n");
  return 0;
}

int rpmsg_findalldevs(pcap_if_list_t *devlistp, char *err_str) {
  printf("findall\n");
  if (add_dev(devlistp, "rpmsg0",
      PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE,
      "RPMSG traffic", err_str) == NULL) {
    return -1;
  }
  return 0;
}
pcap_t *rpmsg_create(const char *device, char *ebuf, int *is_ours) {
  printf("create %s\n", device);
	pcap_t *p;
	p = PCAP_CREATE_COMMON(ebuf, struct pcap_rpmsg);
	if (p == NULL)
		return (NULL);

	p->activate_op = rpmsg_activate;
  *is_ours = 1;
  printf("OK\n");
  return p;
}

