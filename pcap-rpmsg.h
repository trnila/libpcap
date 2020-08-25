int rpmsg_findalldevs(pcap_if_list_t *devlistp, char *err_str);
pcap_t *rpmsg_create(const char *device, char *ebuf, int *is_ours);

