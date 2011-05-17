/*
 * This is a reverse-engineered driver for mobile WiMAX (802.16e) devices
 * based on GCT Semiconductor GDM7213 & GDM7205 chip.
 * Copyright (�) 2010 Yaroslav Levandovsky <leyarx@gmail.com>
 *
 * Based on  madWiMAX driver writed by Alexander Gordeev
 * Copyright (C) 2008-2009 Alexander Gordeev <lasaine@lvk.cs.msu.su>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>  //typedef
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h> // for mkdir
#include <sys/time.h>
#include <sys/wait.h>

#include <libusb-1.0/libusb.h>

//#include "config.h"
#include "logging.h"
#include "protocol.h"
#include "wimax.h"
#include "tap_dev.h"

#include "eap_auth.h"

#include <glib.h>
#include <dbus/dbus-glib.h>

#include <openssl/sha.h>
#include <openssl/aes.h>
#include "zlib.h"
/* variables for the command-line parameters */

static int daemonize = 0;
//static int diode_on = 1;
//static int detach_dvd = 0;
//static char *ssid = "@yota.ru";

struct timeval start_sec, curr_sec; // get link status every second

#define QUOTE(name) #name
#define STR(macro) QUOTE(macro)

#define CONF_DIR STR(CONFDIR)

//static char *event_script = SYSCONFDIR "/event.sh";
static char *event_script = CONF_DIR"/event.sh";

static FILE *logfile = NULL;

#define MATCH_BY_LIST		0
#define MATCH_BY_VID_PID	1
#define MATCH_BY_BUS_DEV	2

//static int match_method = MATCH_BY_LIST;

/* for matching by list...
typedef struct usb_device_id_t {
	unsigned short vendorID;
	unsigned short productID;
	unsigned short targetVID;
	unsigned short targetPID;
} usb_device_id_t; */

/* list of all known devices 
static usb_device_id_t wimax_dev_ids[] = {
	{ 0x04e8, 0x6761 },
	{ 0x04e9, 0x6761 },
	{ 0x04e8, 0x6731 },
	{ 0x04e8, 0x6780 },
};*/

/* for other methods of matching... 
static union {
	struct {
		unsigned short vid;
		unsigned short pid;
	};
	struct {
		unsigned int bus;
		unsigned int dev;
	};
} match_params;*/

/* USB-related parameters */
#ifdef GDM7205
	#define IF_MODEM		0	// 0 - для модема комстар	GDM7205
#else
	#define IF_MODEM		1	//1 - для модема фрештел	GDM7213
#endif

#define IF_DVD			0

#define EP_IN			(130 | LIBUSB_ENDPOINT_IN)
#define EP_OUT			(1 | LIBUSB_ENDPOINT_OUT)

#define MAX_PACKET_LEN		0x4000

/* information collector */
static struct wimax_dev_status wd_status;

//char *wimax_states[] = {"INIT", "SYNC", "NEGO", "NORMAL", "SLEEP", "IDLE", "HHO", "FBSS", "RESET", "RESERVED", "UNDEFINED", "BE", "NRTPS", "RTPS", "ERTPS", "UGS", "INITIAL_RNG", "BASIC", "PRIMARY", "SECONDARY", "MULTICAST", "NORMAL_MULTICAST", "SLEEP_MULTICAST", "IDLE_MULTICAST", "FRAG_BROADCAST", "BROADCAST", "MANAGEMENT", "TRANSPORT"};

/* libusb stuff */
static struct libusb_context *ctx = NULL;
static struct libusb_device_handle *devh = NULL;
static struct libusb_transfer *req_transfer = NULL;
static int kernel_driver_active = 0;

static unsigned char read_buffer[MAX_PACKET_LEN];

static int tap_fd = -1;
static char tap_dev[20] = "wimax%d";
static int tap_if_up = 0;

static nfds_t nfds;
static struct pollfd* fds = NULL;

//static int extract_cert(int *id, unsigned char *buf, int *len);

//static int first_nego_flag = 0;
static int device_disconnected = 0;

static void exit_release_resources(int code);
static void dbus_conn_info_send(int signal_code);
static void dbus_sig_info_send(void);
static void dbus_dev_info_send(void);
static void dbus_bsid_info_send(void);

#define CHECK_NEGATIVE(x) {if((r = (x)) < 0) return r;}
#define CHECK_DISCONNECTED(x) {if((r = (x)) == LIBUSB_ERROR_NO_DEVICE) exit_release_resources(0);}

int dbus_use = 0;

DBusGConnection *dbus_connection;
GError *dbus_error;
DBusGProxy *dbus_proxy;
/*
static struct libusb_device_handle* find_wimax_device(void)
{
	struct libusb_device **devs;
	struct libusb_device *found = NULL;
	struct libusb_device *dev;
	struct libusb_device_handle *handle = NULL;
	int i = 0;
	int r;

	if (libusb_get_device_list(ctx, &devs) < 0)
		return NULL;

	while (!found && (dev = devs[i++]) != NULL) {
		struct libusb_device_descriptor desc;
		unsigned int j = 0;
		unsigned short dev_vid, dev_pid;

		r = libusb_get_device_descriptor(dev, &desc);
		if (r < 0) {
			continue;
		}
		dev_vid = libusb_le16_to_cpu(desc.idVendor);
		dev_pid = libusb_le16_to_cpu(desc.idProduct);
		wmlog_msg(1, "Bus %03d Device %03d: ID %04x:%04x", libusb_get_bus_number(dev), libusb_get_device_address(dev), dev_vid, dev_pid);
		switch (match_method) {
			case MATCH_BY_LIST: {
				for (j = 0; j < sizeof(wimax_dev_ids) / sizeof(usb_device_id_t); j++) {
					if (dev_vid == wimax_dev_ids[j].vendorID && dev_pid == wimax_dev_ids[j].productID) {
						found = dev;
						break;
					}
				}
				break;
			}
			case MATCH_BY_VID_PID: {
				if (dev_vid == match_params.vid && dev_pid == match_params.pid) {
					found = dev;
				}
				break;
			}
			case MATCH_BY_BUS_DEV: {
				if (libusb_get_bus_number(dev) == match_params.bus && libusb_get_device_address(dev) == match_params.dev) {
					found = dev;
				}
				break;
			}
		}
	}

	if (found) {
		r = libusb_open(found, &handle);
		if (r < 0)
			handle = NULL;
	}

	libusb_free_device_list(devs, 1);
	return handle;
}
*/

// ***Edited by fanboy*** 
static struct libusb_device_handle* find_wimax_device(void)
{
	struct libusb_device_handle *handle = NULL;
	int r;
	//Switch modem the same as in usb_modeswitch
	handle = libusb_open_device_with_vid_pid(NULL, 0x1076, 0x7f40);
	if (handle != 0 ){
		
		if (libusb_kernel_driver_active(handle, IF_MODEM) == 1)
		{
			r = libusb_detach_kernel_driver(handle, IF_MODEM);
			if (r < 0){
				wmlog_msg(1, "Kernel driver detaching (error %d)\n", r);
			} else {
				wmlog_msg(1, "Kernel driver deteched!\n");
			}
		}	
	
		r = libusb_claim_interface(handle,IF_MODEM);

		if (r < 0) {
			wmlog_msg(1, "Claim Interface problems (error %d)\n", r);
		}
		else
		{
			wmlog_msg(1, "Innterface claimed\n");	

			r = libusb_control_transfer(handle, 0xa1, 0xa0, 0, IF_MODEM, read_buffer, 1, 1000);
			wmlog_msg(1, "Sending Control message (result %d - %s)\n", r, r ? "bad" : "ok");

			libusb_release_interface(handle, IF_MODEM);

			libusb_close(handle);
		}
	}

	int retry = 0;
	do
	{
		sleep(1); // Wait while device switching
		handle = libusb_open_device_with_vid_pid(NULL, 0x1076, 0x7f00);
	}
	while (retry++ < 5 && !handle);

	if (handle) wmlog_msg(2, "Device switched after %d retries.\n", retry);
	else  wmlog_msg(1, "Device not switched after %d retries.\n", retry);

	return handle;
}

static int set_data(unsigned char* data, int size)
{
	int r;
	int transferred;

	wmlog_dumphexasc(3, data, size, "Bulk write:");

	r = libusb_bulk_transfer(devh, EP_OUT, data, size, &transferred, 0);
	if (r < 0) {
		wmlog_msg(1, "bulk write error %d", r);
		if (r == LIBUSB_ERROR_NO_DEVICE) {
			if (dbus_use) dbus_conn_info_send(1);
			exit_release_resources(0);
		}
		return r;
	}
	if (transferred < size) {
		wmlog_msg(1, "short write (%d)", r);
		return -1;
	}
	return r;
}

void eap_server_rx(unsigned char *data, int data_len) // Sent data from peer to server
{
	unsigned char req_data[MAX_PACKET_LEN];
	int len;
	
	len = fill_eap_server_rx_req(req_data, data, data_len);
	set_data(req_data, len);
}

void eap_key(unsigned char *data, int data_len)
{
	unsigned char req_data[MAX_PACKET_LEN];
	int len;

	len = fill_eap_key_req(req_data, data, data_len);
	set_data(req_data, len);	
}

static void cb_req(struct libusb_transfer *transfer)
{
	if (transfer->status != LIBUSB_TRANSFER_COMPLETED) {
		wmlog_msg(1, "async bulk read error %d", transfer->status);
		if (transfer->status == LIBUSB_TRANSFER_NO_DEVICE) {
			device_disconnected = 1;
			return;
		}
	} else {
		wmlog_dumphexasc(3, transfer->buffer, transfer->actual_length, "Async read:");
		process_response(&wd_status, transfer->buffer, transfer->actual_length);
	}
	if (libusb_submit_transfer(req_transfer) < 0) {
		wmlog_msg(1, "async read transfer sumbit failed");
	}
}

/* get link_status *//*
int get_link_status()
{
	return wd_status.link_status;
}*/

/* set close-on-exec flag on the file descriptor */
int set_coe(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFD);
	if (flags == -1)
	{
		wmlog_msg(1, "failed to set close-on-exec flag on fd %d", fd);
		return -1;
	}
	flags |= FD_CLOEXEC;
	if (fcntl(fd, F_SETFD, flags) == -1)
	{
		wmlog_msg(1, "failed to set close-on-exec flag on fd %d", fd);
		return -1;
	}

	return 0;
}

/* run specified script */
static int raise_event(char *event)
{
	int pid = fork();

	if(pid < 0) { /* error */
		return -1;
	} else if (pid > 0) { /* parent */
		return pid;
	} else { /* child */
		char *args[] = {event_script, event, tap_dev, NULL};
		char *env[1] = {NULL};
		/* run the program */
		execve(args[0], args, env);
		exit(1);
	}
}

/* brings interface up and runs a user-supplied script */
static int if_create()
{
	tap_fd = tap_open(tap_dev);
	if (tap_fd < 0) {
		wmlog_msg(0, "failed to allocate tap interface");
		wmlog_msg(0,
				"You should have TUN/TAP driver compiled in the kernel or as a kernel module.\n"
				"If 'modprobe tun' doesn't help then recompile your kernel.");
		exit_release_resources(1);
	}
	tap_set_hwaddr(tap_fd, tap_dev, wd_status.mac);
	tap_set_mtu(tap_fd, tap_dev, 1386);
	set_coe(tap_fd);
	wmlog_msg(0, "Allocated tap interface: %s", tap_dev);
	wmlog_msg(2, "Starting if-create script...");
	raise_event("if-create");
	return 0;
}

/* brings interface up and runs a user-supplied script */
static int if_up()
{
	tap_bring_up(tap_fd, tap_dev);
	wmlog_msg(2, "Starting if-up script...");
	raise_event("if-up");
	tap_if_up = 1;
	if (dbus_use) {
		dbus_conn_info_send(4);
		dbus_bsid_info_send();
	}
	return 0;
}

/* brings interface down and runs a user-supplied script */
static int if_down()
{
	if (!tap_if_up) return 0;
	tap_if_up = 0;
	wmlog_msg(2, "Starting if-down script...");
	raise_event("if-down");
	tap_bring_down(tap_fd, tap_dev);
	return 0;
}

/* brings interface down and runs a user-supplied script */
static int if_release()
{
	wmlog_msg(2, "Starting if-release script...");
	raise_event("if-release");
	tap_close(tap_fd, tap_dev);
	return 0;
}

/* set link_status *//*
void set_link_status(int link_status)
{
	wd_status.info_updated |= WDS_LINK_STATUS;

	if (wd_status.link_status == link_status) return;

	if (wd_status.link_status < 2 && link_status == 2) {
		if_up();
	}
	if (wd_status.link_status == 2 && link_status < 2) {
		if_down();
	}
	if (link_status == 1) {
		first_nego_flag = 1;
	}

	wd_status.link_status = link_status;
}*/

/* get state *//*
int get_state()
{
	return wd_status.state;
}*/

/* set state *//*
void set_state(int state)
{
	wd_status.state = state;
	wd_status.info_updated |= WDS_STATE;
	if (state >= 1 && state <= 3 && wd_status.link_status != (state - 1)) {
		set_link_status(state - 1);
	}
}*/

static int alloc_transfers(void)
{
	req_transfer = libusb_alloc_transfer(0);
	if (!req_transfer)
		return -ENOMEM;

	libusb_fill_bulk_transfer(req_transfer, devh, EP_IN, read_buffer,
		sizeof(read_buffer), cb_req, NULL, 0);

	return 0;
}

int write_netif(const void *buf, int count)
{
	return tap_write(tap_fd, buf, count);
}

static int read_tap()
{
	unsigned char buf[MAX_PACKET_LEN];
	int hlen = get_header_len();
	int r;
	int len;

	r = tap_read(tap_fd, buf + hlen, MAX_PACKET_LEN - hlen);

	if (r < 0)
	{
		wmlog_msg(1, "Error while reading from TAP interface");
		return r;
	}

	if (r == 0)
	{
		return 0;
	}

	len = fill_data_packet_header(buf, r);
	wmlog_dumphexasc(4, buf, len, "Outgoing packet:");
	r = set_data(buf, len);

	return r;
}

static int process_events_once(int timeout)
{
	struct timeval tv = {0, 0};
	int r;
	int libusb_delay;
	int delay;
	unsigned int i;
	char process_libusb = 0;

	r = libusb_get_next_timeout(ctx, &tv);
	if (r == 1 && tv.tv_sec == 0 && tv.tv_usec == 0)
	{
		r = libusb_handle_events_timeout(ctx, &tv);
	}

	delay = libusb_delay = tv.tv_sec * 1000 + tv.tv_usec;
	if (delay <= 0 || delay > timeout)
	{
		delay = timeout;
	}

	CHECK_NEGATIVE(poll(fds, nfds, delay));

	process_libusb = (r == 0 && delay == libusb_delay);

	for (i = 0; i < nfds; ++i)
	{
		if (fds[i].fd == tap_fd) {
			if (fds[i].revents)
			{
				CHECK_NEGATIVE(read_tap());
			}
			continue;
		}
		process_libusb |= fds[i].revents;
	}

	if (process_libusb)
	{
		struct timeval tv = {.tv_sec = 0, .tv_usec = 0};
		CHECK_NEGATIVE(libusb_handle_events_timeout(ctx, &tv));
	}

	return 0;
}

/* handle events until timeout is reached or all of the events in event_mask happen */
static int process_events_by_mask(int timeout, unsigned int event_mask)
{
	struct timeval start, curr;
	int r;
	int delay = timeout;

	CHECK_NEGATIVE(gettimeofday(&start, NULL));

	wd_status.info_updated &= ~event_mask;
	
	while ((event_mask == 0 || (wd_status.info_updated & event_mask) != event_mask) && delay >= 0) {
		long a;
		
		CHECK_NEGATIVE(process_events_once(delay));

		if (device_disconnected) {
			if (dbus_use) dbus_conn_info_send(1);
			exit_release_resources(0);
		}

		CHECK_NEGATIVE(gettimeofday(&curr, NULL));

		a = (curr.tv_sec - start.tv_sec) * 1000 + (curr.tv_usec - start.tv_usec) / 1000;
		delay = timeout - a;
	}

	wd_status.info_updated &= ~event_mask;

	return (delay > 0) ? delay : 0;
}

int alloc_fds()
{
	int i;
	const struct libusb_pollfd **usb_fds = libusb_get_pollfds(ctx);

	if (!usb_fds)
	{
		return -1;
	}

	nfds = 0;
	while (usb_fds[nfds])
	{
		nfds++;
	}
	if (tap_fd != -1) {
		nfds++;
	}

	if(fds != NULL) {
		free(fds);
	}

	fds = (struct pollfd*)calloc(nfds, sizeof(struct pollfd));
	for (i = 0; usb_fds[i]; ++i)
	{
		fds[i].fd = usb_fds[i]->fd;
		fds[i].events = usb_fds[i]->events;
		set_coe(usb_fds[i]->fd);
	}
	if (tap_fd != -1) {
		fds[i].fd = tap_fd;
		fds[i].events = POLLIN;
		fds[i].revents = 0;
	}

	free(usb_fds);

	return 0;
}

void cb_add_pollfd(int fd, short events, void *user_data)
{
	alloc_fds();
}

void cb_remove_pollfd(int fd, void *user_data)
{
	alloc_fds();
}

void AES_cbc_decrypt(uint8_t *shakey, uint8_t *inbuf, uint8_t *outbuf)
{
	unsigned char iv[16] = {0x43,0x6c,0x61,0x72,0x6b,0x4a,0x4a,0x61,0x6e,0x67,0x00,0x00,0x00,0x00,0x00,0x00}; //ClarkJJang

	AES_KEY aeskey;	

	AES_set_decrypt_key(shakey, 24*8, &aeskey); //192

	AES_cbc_encrypt(inbuf, outbuf, 16, &aeskey, iv, AES_DECRYPT);
}

static int extract_cert(int id, unsigned char *buf, int len, char *path)
{
	int r, i;
	int dec_buf_len, gz_len;
	char gz_path[0x100], pem_path[0x100];
	uint8_t key_sha[0x18];
	uint8_t dec_buf[len], gz_buf[MAX_PACKET_LEN];
	FILE *fp;
	voidp gz;
	
	memset(key_sha,0x00,sizeof(key_sha));
	memset(dec_buf,0x00,sizeof(dec_buf));
	
	r = mkdir(path,S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (r)
	{
		if (errno != 17)
			return errno;
	}
	

	SHA1(wd_status.mac, 6, key_sha);

	for (i = 0; i < (len / 16); i++)
		AES_cbc_decrypt(key_sha, buf + 16 * i, dec_buf + 16 * i);	
	dec_buf_len = (dec_buf[0] << 24) + (dec_buf[1] << 16) + (dec_buf[2] << 8) + dec_buf[3];
	wmlog_msg(2, "Decrypted cert %d size is %d bytes.", id, dec_buf_len);
	
	sprintf(gz_path,"%s/0%d.gz", path, id);
	fp=fopen((char *)gz_path, "wb");
	if (fp == NULL)
		return errno;
	fwrite(dec_buf + 4, 1, dec_buf_len, fp);
	fclose(fp);

	gz = gzopen(gz_path, "rb"); 
	if (gz == NULL)
		return errno;
	gz_len = gzread(gz, gz_buf, sizeof(gz_buf));
	gzclose(gz);
	remove(gz_path);
	
	wmlog_msg(2, "Extracted cert %d size is %d bytes.", id, gz_len);

	if(id == 1)
	{
		sprintf(pem_path, "%s/client_cert.pem", path);

		fp=fopen((char *)pem_path, "wb");
		if (fp == NULL)
			return errno;
		fwrite(gz_buf,1,gz_len,fp);
		fclose(fp);			
	}
	else
	{
		sprintf(pem_path, "%s/root_ca.pem", path);
		
		fp=fopen((char *)pem_path, "ab");
		if (fp == NULL)
			return errno;
		fwrite(gz_buf,1,gz_len,fp);
		fclose(fp);
	}
	
	return 0;
}

static int init(void)
{
	unsigned char req_data[MAX_PACKET_LEN], cert_buf[MAX_PACKET_LEN];
	char path[0x100];
	int len, cert_buf_len, cert_id, cert_len;
	int r;

	alloc_transfers();

	wmlog_msg(2, "Continuous async read start...");
	CHECK_DISCONNECTED(libusb_submit_transfer(req_transfer));


	len = fill_debug_req(req_data);  //mode normal or test
	set_data(req_data, len);
		


	len = fill_string_info_req(req_data);
	set_data(req_data, len);

	process_events_by_mask(500, WDS_CHIP | WDS_FIRMWARE);
	
	wmlog_msg(1, "Chip info: %s", wd_status.chip);
	wmlog_msg(1, "Firmware info: %s", wd_status.firmware);

	len = fill_mac_req(req_data);
	set_data(req_data, len);

	process_events_by_mask(500, WDS_MAC);

	wmlog_msg(1, "MAC: %02x:%02x:%02x:%02x:%02x:%02x", wd_status.mac[0], wd_status.mac[1], wd_status.mac[2], wd_status.mac[3], wd_status.mac[4], wd_status.mac[5]);
	sprintf(path,CONF_DIR"/%02x%02x%02x%02x%02x%02x", wd_status.mac[0], wd_status.mac[1], \
												wd_status.mac[2], wd_status.mac[3], wd_status.mac[4], wd_status.mac[5]);
	

	eap_ca_path = (char *)malloc(strlen(path)+13);
	sprintf(eap_ca_path,"%s/root_ca.pem",path);
	
	eap_client_cert = (char *)malloc(strlen(path)+17);
	sprintf(eap_client_cert,"%s/client_cert.pem",path);
	
	if (dbus_use) dbus_dev_info_send();

	
	len = fill_rf_on_req(req_data);
	set_data(req_data, len);

	process_events_by_mask(20000, WDS_RF_STATE);

	wmlog_msg(2, "RF ON.");
	
	memset(wd_status.cert,0xff,6);
	cert_buf_len = 0;
	
	
	//wd_status.cert[1] <= 0x06
	while(1)
	{
		cert_id = wd_status.cert[1];

		if(wd_status.cert[1] == 0x06 && wd_status.cert[2] == 0xff)
			break;
		len = fill_get_cert_req(req_data, &wd_status);
		if(len == 0)
			break;
		set_data(req_data, len);
		process_events_by_mask(2000, WDS_CERT);
		
		cert_len = (wd_status.cert_buf[0] << 8) + wd_status.cert_buf[1];
		
		
		if ((cert_id == wd_status.cert[1] && wd_status.cert[2] != 0xff) || (cert_id != wd_status.cert[1] && cert_len > 0))
		{
			memcpy(cert_buf+cert_buf_len,wd_status.cert_buf+2,cert_len);
			cert_buf_len += cert_len;
		}
		else if (cert_id == wd_status.cert[1] && cert_buf_len > 0)
		{
			if (!(cert_buf_len % 16))
			{
				r = extract_cert(cert_id, cert_buf, cert_buf_len, path);
				if(r)
					wmlog_msg(1, "Error: \"%s\" while extracting cert %d.",strerror(r),cert_id);
				else
				{
					wmlog_msg(1, "Cert %d extracted successfully",cert_id);
				}
			}
			else
				wmlog_msg(1, "Bad cert size %d bytes.",cert_buf_len);
			
			memset(wd_status.cert_buf,0x00,sizeof(wd_status.cert_buf));	
			cert_buf_len = 0;
		}
	}
	return 0;
}

static int scan_loop(void)
{
	unsigned char req_data[MAX_PACKET_LEN];
	int len;
	int r;
	
	while (1)
	{
		if (wd_status.link_status == 0) {

			if_down();

			len = fill_auth_on_req(req_data);
			set_data(req_data, len);

			if (dbus_use) dbus_conn_info_send(5);
			wmlog_msg(0, "Search network...");		
			len = fill_find_network_req(req_data, &wd_status);
			set_data(req_data, len);

			while (process_events_by_mask(60000, WDS_LINK_STATUS) < 0) {;}
			
			if (wd_status.link_status == 0) {
				if (dbus_use) dbus_conn_info_send(6);
				wmlog_msg(0, "Network not found.");
			} else {
				if (dbus_use) dbus_conn_info_send(7);
				wmlog_msg(0, "Network found.");
					wd_status.link_status = 0;
								
				len = fill_connect_req(req_data, &wd_status);
				set_data(req_data, len);

				while (process_events_by_mask(100000, WDS_LINK_STATUS) < 0) {;}
				
				if (wd_status.link_status == 0) {
					if (dbus_use) dbus_conn_info_send(8);
					wmlog_msg(0, "Connection error.");
				} else {
					wmlog_msg(0, "Connected to Network.");
					
					wd_status.auth_info = 0; //if more then one BS found.
					r = 1;
					while (	1 ){
					
						//while (process_events_by_mask(10000, WDS_AUTH_STATE) < 0) {;}
						process_events_by_mask(5000, WDS_AUTH_STATE);
						wmlog_msg(2, "Auth_state: %06x",wd_status.auth_state);
						
						if (wd_status.auth_state == 0x0001ff ||
							wd_status.auth_state == 0x0100ff ||
							wd_status.auth_state == 0x0101ff ||
							wd_status.auth_state == 0x0200ff ||
							wd_status.auth_state == 0x0300ff ||
							wd_status.auth_state == 0x0301ff ||
							wd_status.auth_state == 0x0400ff ||
							wd_status.auth_state == 0x0401ff){
							process_events_by_mask(3000, WDS_LINK_STATUS);
							//process_events_by_mask(3000, WDS_LINK_STATUS);
							break;
						}

						
						if (wd_status.auth_state == 0x020000){
							if (dbus_use) dbus_conn_info_send(9);
							wmlog_msg(0, "Start Authentication.");
							
							if (eap_peer_init()< 0)
								wmlog_msg(0, "EAP Peer init error.");
							
								wd_status.info_updated = WDS_NONE;
								r = 1;
								
							while( r > 0)
							{
								while (process_events_by_mask(1500, WDS_EAP) < 0) {;}
								//process_events_by_mask(1500, WDS_EAP);
								r = eap_peer_step();
								//wmlog_msg(0, "\nr = %d\n",r);
							}
							eap_peer_deinit();
						}
						
						if (wd_status.auth_state == 0x0201ff){
							if (dbus_use) dbus_conn_info_send(10);
							if (wd_status.auth_info == 0){
								wmlog_msg(0, "Authentication Failed. Renewing Authentication.");
							}
							else {
								wmlog_msg(0, "Authentication Failed.");
								break;
							}
							
						}

						if (wd_status.auth_state == 0x020100){

							wmlog_msg(0, "Authentication Succeed.");
								
							//process_events_by_mask(1000, WDS_LINK_STATUS);	
								
							//process_events_by_mask(500, WDS_OTHER);
							
						}
						
						if (wd_status.auth_state == 0x040100){
							
							if_up();
							process_events_by_mask(2000, WDS_LINK_STATUS);	
							process_events_by_mask(2000, WDS_LINK_STATUS);
							break;
							
						}
					}
				}
			}
				
		} 
		else { 

				len = fill_connection_params_req(req_data);
				set_data(req_data, len);

				process_events_by_mask(500, WDS_RSSI1 | WDS_CINR1 | WDS_RSSI2 | WDS_CINR2 | WDS_TXPWR | WDS_FREQ);

				wmlog_msg(1, "RSSI1: %d   CINR1: %d   TX Power: %d   Frequency: %d", 
								wd_status.rssi1, wd_status.cinr1, wd_status.txpwr, wd_status.freq);
				wmlog_msg(1, "RSSI2: %d   CINR2: %d", 
								wd_status.rssi2, wd_status.cinr2);

				if (dbus_use) dbus_sig_info_send();
			
				process_events_by_mask(5000, WDS_LINK_STATUS);
		}
	}

	return 0;
}

/* print usage information */
void usage(const char *progname)
{
	printf("Usage: %s [options]\n", progname);
	printf("Options:\n");
	printf("      --login=                Login\n");	
	printf("      --pass=                 Password\n");
	printf("      --nai=                  Outer NAI (default:mac@freshtel.com.ua)\n");
	printf("      --eap-type=             EAP Type: 3 - TLS, 5 - MSCHAPV2 (default: 5)\n");
	printf("  -v, --verbose               increase the log level\n");
	printf("  -q, --quiet                 switch off logging\n");
	printf("  -d, --daemonize             daemonize after startup\n");
	printf("  -l, --log-file=FILE         write log to the FILE instead of the other\n");
	printf("                              methods\n");
	//printf("      --device=VID:PID        specify the USB device by VID:PID\n");
	//printf("      --exact-device=BUS/DEV  specify the exact USB bus/device (use with care!)\n");
	printf("  -V, --version               print the version number\n");
	printf("      --nspid=                specify NSPID, a friendly name that identifies a\n");
	printf("                              particular 802.16e wireless Network\n");
	printf("                              Service Provider (Freshtel NSPID: 000032)\n");
	printf("  -e, --event-script=FILE     specify path to the event script\n");
	printf("      --with-dbus             Run with dbus support\n");
	printf("  -h, --help                  display this help\n");
}

/* print version */
void version()
{
	printf("%s %s\n", "GCTwimax", get_wimax_version());
	//printf("%s %s\n", PACKAGE_NAME, get_madwimax_version());
}

static void parse_args(int argc, char **argv)
{
	while (1)
	{
		int c;
		/* getopt_long stores the option index here. */
		int option_index = 0;
		static struct option long_options[] =
		{
			{"login",		required_argument,		0, 4},
			{"pass",		required_argument,		0, 5},
			{"nai",		required_argument,		0, 6},
			{"eap-type",		required_argument,		0, 8},
			{"verbose",		no_argument,		0, 'v'},
			{"quiet",		no_argument,		0, 'q'},
			{"daemonize",		no_argument,		0, 'd'},
			{"log-file",		required_argument,	0, 'l'},
			//{"device",		required_argument,	0, 1},
			//{"exact-device",	required_argument,	0, 2},
			{"version",		no_argument,		0, 'V'},
			{"nspid",		required_argument,	0, 3},
			{"event-script",	required_argument,	0, 'e'},
			{"with-dbus",		no_argument,	0, 7},
			{"help",		no_argument,		0, 'h'},
			{0, 0, 0, 0}
		};

		//c = getopt_long(argc, argv, "vqdl:Ve:h", long_options, &option_index);
		c = getopt_long(argc, argv, "vqdl:Ve:h", long_options, &option_index);
		/* detect the end of the options. */
		if (c == -1)
			break;

		switch (c)
		{
			case 4: {
					if (strlen(optarg) != 0) {
						eap_login = optarg;
						break;
					}

					printf("Please set login\n");
					exit(1);
					break;
				}
			case 5: {
					if (strlen(optarg) != 0) {
						eap_pass = optarg;
						break;
					}

					printf("Please set password\n");
					exit(1);
					break;
				}
			case 6: {
					if (strlen(optarg) != 0) {
						eap_outer_nai = optarg;
						break;
					}
					printf("Please set Outer NAI\n");
					exit(1);
					break;
				}
			case 'v': {
					inc_wmlog_level();
					break;
				}
			case 'q': {
					set_wmlog_level(-1);
					break;
				}
			case 'd': {
					daemonize = 1;
					break;
				}
			case 'l': {
					logfile = fopen(optarg, "a");
					if (logfile == NULL) {
						fprintf(stderr, "Error opening log file '%s': ", optarg);
						perror(NULL);
						exit(1);
					}
					break;
				}
			case 'V': {
					version();
					exit(0);
					break;
				}
			case 'h': {
					usage(argv[0]);
					exit(0);
					break;
				}
	/*		case 1: {
					char *delim = strchr(optarg, ':');

					if (delim != NULL) {
						unsigned long int vid, pid;
						char *c1, *c2;

						*delim = 0;

						vid = strtoul(optarg, &c1, 16);
						pid = strtoul(delim + 1, &c2, 16);
						if (!*c1 && !*c2 && vid < 0x10000 && pid < 0x10000) {
							match_method = MATCH_BY_VID_PID;
							match_params.vid = vid;
							match_params.pid = pid;
							break;
						}
					}

					fprintf(stderr, "Error parsing VID:PID combination.\n");
					exit(1);
					break;
				}
			case 2: {
					char *delim = strchr(optarg, '/');

					if (delim != NULL) {
						unsigned long int bus, dev;
						char *c1, *c2;

						*delim = 0;

						bus = strtoul(optarg, &c1, 10);
						dev = strtoul(delim + 1, &c2, 10);
						if (!*c1 && !*c2) {
							match_method = MATCH_BY_BUS_DEV;
							match_params.bus = bus;
							match_params.dev = dev;
							break;
						}
					}

					fprintf(stderr, "Error parsing BUS/DEV combination.\n");
					exit(1);
					break;
				}*/
			case 3: {
					if (strtol(optarg, NULL, 16)<=0xFFFFFF) {
						wd_status.nspid = strtol(optarg, NULL, 16);
					} else {
						fprintf(stderr, "Bad NSPID\n");
						exit(1);						
					}
					break;
				}
			case 'e': {
					event_script = optarg;
					break;
				}
			case '?': {
					/* getopt_long already printed an error message. */
					usage(argv[0]);
					exit(1);
					break;
				}
			case 7: {
				dbus_use = 1;
				break;
				}
			case 8: {
				if(strtol(optarg, NULL, 10) >= 3 && strtol(optarg, NULL, 10) <= 5 )
					eap_type = strtol(optarg, NULL, 10);
				else {
					fprintf(stderr, "Bad EAP Type\n");
					exit(1);						
				}
				break;
				}
			default: {
					exit(1);
				}
		}
	}
}

static void exit_release_resources(int code)
{	
//Rewrite this part!!!!!!!
	if(wd_status.rf_state == 0){
	unsigned char req_data[MAX_PACKET_LEN];
	int len;
	wmlog_msg(2, "RF OFF.");
	len = fill_rf_off_req(req_data);
	set_data(req_data, len);
	process_events_by_mask(2000, WDS_RF_STATE);
	}
	
	remove(eap_ca_path); //Delete this
	remove(eap_client_cert);
	
	if(tap_fd >= 0) {
		if_down();
		while (wait(NULL) > 0) {}
		if_release();
		while (wait(NULL) > 0) {}
	}
	if(ctx != NULL) {
		if(req_transfer != NULL) {
			libusb_cancel_transfer(req_transfer);
			libusb_free_transfer(req_transfer);
		}
		libusb_set_pollfd_notifiers(ctx, NULL, NULL, NULL);
		if(fds != NULL) {
			free(fds);
		}
		if(devh != NULL) {
			libusb_release_interface(devh, 0);
			if (kernel_driver_active)
				libusb_attach_kernel_driver(devh, 0);
			libusb_unlock_events(ctx);
			libusb_close(devh);
		}
		libusb_exit(ctx);
	}
	if(logfile != NULL) {
		fclose(logfile);
	}
	if (dbus_use) {
		dbus_g_proxy_call_no_reply(dbus_proxy,
					"ErrorAndDisconnect",
					G_TYPE_INVALID);
		g_object_unref(dbus_proxy);
		dbus_g_connection_unref(dbus_connection);
	}
	exit(code);
}

static void sighandler_exit(int signum) {
	exit_release_resources(0);
}

static void sighandler_wait_child(int signum) {
	int status;
	wait3(&status, WNOHANG, NULL);
	wmlog_msg(2, "Child exited with status %d", status);
}

////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////

static void dbus_dev_info_send(void) {
	char mac[18];
	snprintf(mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x", wd_status.mac[0], wd_status.mac[1], wd_status.mac[2],
							wd_status.mac[3], wd_status.mac[4], wd_status.mac[5]);
	dbus_g_proxy_call_no_reply(dbus_proxy,
				"SendDeviceInfo",
				G_TYPE_STRING, wd_status.chip,
				G_TYPE_STRING, wd_status.firmware,
				G_TYPE_STRING, mac,
				G_TYPE_INVALID);
}

static void dbus_sig_info_send(void) {
	dbus_g_proxy_call_no_reply(dbus_proxy,
				"SendSignalInfo",
				G_TYPE_INT, wd_status.rssi1,
				G_TYPE_INT, wd_status.rssi2,
				G_TYPE_INT, wd_status.cinr1,
				G_TYPE_INT, wd_status.cinr2,
				G_TYPE_UINT, wd_status.txpwr,
				G_TYPE_UINT, wd_status.freq,
				G_TYPE_INVALID);
}

static void dbus_bsid_info_send(void) {
	char bsid[18];
	snprintf(bsid, 18, "%02x:%02x:%02x:%02x:%02x:%02x", wd_status.bsid[0], wd_status.bsid[1], wd_status.bsid[2],
							wd_status.bsid[3], wd_status.bsid[4], wd_status.bsid[5]);
	dbus_g_proxy_call_no_reply(dbus_proxy, "SendBsidInfo", G_TYPE_STRING, bsid, G_TYPE_INVALID);
}

/*
 * Signal codes:
 * 1  - Device not found
 * 2  - Device found
 * 3  - Error init driver
 * 4  - Receive ip-address (event script)
 * 5  - Search network
 * 6  - Network not found
 * 7  - Network found
 * 8  - Connection error
 * 9  - Start Authentication
 * 10 - Authentication Failed
 */
static void dbus_conn_info_send(int signal_code) {
	dbus_g_proxy_call_no_reply(dbus_proxy, "SendConnectionInfo", G_TYPE_INT, signal_code, G_TYPE_INVALID);
}

////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////


int main(int argc, char **argv)
{
	struct sigaction sigact;
	int r = 1;
	wmlog_msg(2,"IF %d\n",IF_MODEM);
	wmlog_msg(2,"Dir  %s\n",CONF_DIR);
	//Freshtel NSPID
	wd_status.nspid = 0x000032;

	parse_args(argc, argv);

	if (dbus_use) {
		g_type_init();
		dbus_error = NULL;
		dbus_connection = dbus_g_bus_get(DBUS_BUS_SYSTEM, &dbus_error);
		if (dbus_connection == NULL) {
			wmlog_msg(0, "Ошибка соединения с D-BUS: %s\n", dbus_error->message);
			g_error_free(dbus_error);
			return 1;
		}
		dbus_proxy = dbus_g_proxy_new_for_name(dbus_connection,
						"ua.org.yarx.Daemon",
						"/ua/org/yarx/Daemon",
						"ua.org.yarx.Daemon");
		if (!dbus_proxy) {
			wmlog_msg(0, "Ошибка создания прокси объекта dbus для ua.org.yarx.Daemon: %s\n", dbus_error->message);
			return 1;
		}
	}

	sigact.sa_handler = sighandler_exit;
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = 0;
	sigaction(SIGINT, &sigact, NULL);
	sigaction(SIGTERM, &sigact, NULL);
	sigaction(SIGQUIT, &sigact, NULL);
	sigact.sa_handler = sighandler_wait_child;
	sigaction(SIGCHLD, &sigact, NULL);

	if (logfile != NULL) {
		set_wmlogger(argv[0], WMLOGGER_FILE, logfile);
	} else if (daemonize || dbus_use) {
		set_wmlogger(argv[0], WMLOGGER_SYSLOG, NULL);
	} else {
		set_wmlogger(argv[0], WMLOGGER_FILE, stderr);
	}

	if (daemonize) {
		wmlog_msg(0, "Demon");
		CHECK_NEGATIVE(daemon(0, 0));
	}
		
	wd_status.rf_state = 1;  // RF OFF
		
	r = libusb_init(&ctx);
	if (r < 0) {
		if (dbus_use) dbus_conn_info_send(1);
		wmlog_msg(0, "failed to initialise libusb");
		exit_release_resources(1);
	}

	devh = find_wimax_device();
	if (devh == NULL) {
		if (dbus_use) dbus_conn_info_send(1);
		wmlog_msg(0, "Could not find/open device");
		exit_release_resources(1);
	}

	if (dbus_use) dbus_conn_info_send(2);
	wmlog_msg(0, "Device found");
/*
	if (detach_dvd && libusb_kernel_driver_active(devh, IF_DVD) == 1) {
		r = libusb_detach_kernel_driver(devh, IF_DVD);
		if (r < 0) {
			wmlog_msg(0, "kernel driver detach error %d", r);
		} else {
			wmlog_msg(0, "detached pseudo-DVD kernel driver");
		}
	}
*/
	if (libusb_kernel_driver_active(devh, IF_DVD) == 1) {
		kernel_driver_active = 1;
		r = libusb_detach_kernel_driver(devh, IF_DVD);
		if (r < 0) {
			wmlog_msg(0, "kernel driver detach error %d", r);
		} else {
			wmlog_msg(0, "detached modem kernel driver");
		}
	}

	r = libusb_claim_interface(devh, 0);
	if (r < 0) {
		if (dbus_use) dbus_conn_info_send(1);
		wmlog_msg(0, "Claim usb interface error %d", r);
		exit_release_resources(1);
	}
	wmlog_msg(0, "Claimed interface");

	alloc_fds();
	libusb_set_pollfd_notifiers(ctx, cb_add_pollfd, cb_remove_pollfd, NULL);
	
	r = init();
	if (r < 0) {
		if (dbus_use) dbus_conn_info_send(3);
		wmlog_msg(0, "init error %d", r);
		exit_release_resources(1);
	}

	if_create();
	cb_add_pollfd(tap_fd, POLLIN, NULL);

	r = scan_loop();
	if (r < 0) {
		if (dbus_use) dbus_conn_info_send(3);
		wmlog_msg(0, "scan_loop error %d", r);
		exit_release_resources(1);
	}

	exit_release_resources(0);
	return 0;
}

