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

struct pcap_rpmsg {
  int fd;
};

struct rpmsg_header {
  uint32_t src;
  uint32_t dst;
  uint32_t reserved;
  uint16_t length;
  uint16_t flags;
};

static int
rpmsg_read(pcap_t *handle, int max_packets _U_, pcap_handler callback, u_char *user) {
  int read_ret;
  struct rpmsg_header *header = handle->buffer;

	do {
		read_ret = read(handle->fd, handle->buffer, 4096);
		if (handle->break_loop)
		{
			handle->break_loop = 0;
			return -2;
		}
	} while ((read_ret == -1) && (errno == EINTR));
	if (read_ret < 0)
	{
		if (errno == EAGAIN)
			return 0;	/* no data there */

		pcap_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "Can't read from fd %d", handle->fd);
		return -1;
	}

	struct pcap_pkthdr pkth;
  pkth.ts.tv_sec = 1;
  pkth.ts.tv_usec = 0;
  pkth.caplen = pkth.len = header->length + sizeof(struct rpmsg_header);
  callback(user, &pkth, handle->buffer);
  return 1;
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

