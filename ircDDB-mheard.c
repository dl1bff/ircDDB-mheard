/*

ircDDB-mheard

Copyright (C) 2010   Michael Dirska, DL1BFF (dl1bff@mdx.de)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <syslog.h>
#include <errno.h>

#include <unistd.h>

#include "libutil.h"

#include "dstar_dv.h"


#define SYSLOG_PROGRAM_NAME "ircddbmhd"

struct dstar_header
{
  char dstar_id[4];
  u_short dstar_pkt_num;
  u_char dstar_rs_flag;
  u_char dstar_pkt_type;
#define DSTAR_PKT_TYPE_DD   0x11
#define DSTAR_PKT_TYPE_DV   0x12
#define DSTAR_PKT_TYPE_MODULE_HEARD   0x21
#define DSTAR_PKT_TYPE_NOP   0x00
  u_short dstar_data_len;
};

struct dstar_dv_header
{
  u_char dv_unknown1;
  u_char dv_unknown2;
  u_char dv_unknown3;
  u_char dv_module;
  u_short dv_stream_id;
};

struct dstar_dv_data
{
  u_char dv_voice[9];
  u_char dv_slowdata[3];
};

struct dstar_dv_rf_header
{
  u_char flags[3];
  char rpt2_callsign[8];
  char rpt1_callsign[8];
  char your_callsign[8];
  char my_callsign[8];
  char my_callsign_ext[4];
  u_char checksum[2];
};


struct dstar_module_heard
{
  char my_callsign[8];
  char rpt1_callsign[8];
};

struct dstar_mheard_info
{
  u_char flags[3];
  char rpt2_callsign[8];
  char rpt1_callsign[8];
  char your_callsign[8];
  char my_callsign[8];
  char my_callsign_ext[4];
  char info_type;
  char tx_msg[20];
};

struct dstar_stream_info
{
  int sd_type;
  int stream_id;
  int stream_counter;
  int mheard_info_timer;
  int mheard_info_valid;
  int dstar_dv_errs;
  int dstar_dv_silent;
};

#define MAX_MODULE_ID 4

static struct dstar_mheard_info mheard_info[MAX_MODULE_ID];
static struct dstar_stream_info stream_info[MAX_MODULE_ID];
static char autolearn_letters[MAX_MODULE_ID];

/* time to wait for tx msg:  MHEARD_INFO_TIMER * SELECT_TIMEOUT */
#define MHEARD_INFO_TIMEOUT 10
#define SELECT_TIMEOUT	  100000


static int udp_socket;



const char * module_letters;

const char dtmf_chars[16] = "147*2580369#ABCD";


static void flush_mheard_data_module(int i)
{
  if (stream_info[i].mheard_info_timer > 0)
  {
    struct dstar_mheard_info * mh = mheard_info + i;


    int packet_len = sizeof (struct dstar_mheard_info);

    if (memcmp( mh->tx_msg, "                    ", 20) == 0)
    {
      packet_len -= 20;  // don't transmit empty tx_msg
    }

    int r = send( udp_socket, mh, packet_len, 0);

    if (r != packet_len)
    {
      syslog(LOG_WARNING, "send didn't work, retval=%d", r);
    }

    stream_info[i].mheard_info_timer = 0;
  }
}

static void flush_mheard_data()
{
  int i;

  for (i=0; i < MAX_MODULE_ID; i++)
  {
    int t = stream_info[i].mheard_info_timer;

    if (t > 0)
    {
      if (t == 1)
      {
	flush_mheard_data_module(i);
      }

      stream_info[i].mheard_info_timer = t - 1;
    }
  }
}


static void process_module_heard( const u_char * data, int len )
{
  if (len != (sizeof (struct dstar_module_heard)))
  {
    return;
  }

  const struct dstar_module_heard * mh = (struct dstar_module_heard *) data;


  // if (mh->rpt1_callsign[7] == 'S')
  // {
  //   return;
  // }

  int module = 0;
  int found = 0;

  int i;

  for (i=0; i < 3; i++)
  {
    if (module_letters[i] == mh->rpt1_callsign[7])
    {
      found = 1;
      break;
    }
  }

  if (found)
  {
    for (i=0; i < MAX_MODULE_ID; i++)
    {
      if (autolearn_letters[i] == mh->rpt1_callsign[7])
      {
	module = i;
	break;
      }
    }
  }

  struct dstar_stream_info * si = stream_info + module;


  if (si->mheard_info_timer > 0)
  {
    flush_mheard_data_module( module );
  }


  memset( &mheard_info[module], ' ', sizeof (struct dstar_mheard_info));
  mheard_info[module].flags[0] = 0xFF;
  mheard_info[module].flags[1] = 0xFF;
  mheard_info[module].flags[2] = 0xFF;

  memcpy ( &mheard_info[module].my_callsign, mh->my_callsign, sizeof (mh->my_callsign));
  memcpy ( &mheard_info[module].rpt1_callsign, mh->rpt1_callsign, sizeof (mh->rpt1_callsign));

  si->mheard_info_timer = MHEARD_INFO_TIMEOUT;

}




static void process_dv_data ( const u_char * data, int len )
{
 
  if (len < ((sizeof (struct dstar_dv_header)) + 1))
  {
    return;
  }

  const struct dstar_dv_header * dh = (struct dstar_dv_header *) data;

  u_char dv_type = * (data + (sizeof (struct dstar_dv_header)));

  const u_char * d = data + (sizeof (struct dstar_dv_header)) + 1;

  u_short dv_stream_id = ntohs(dh->dv_stream_id);

  if (dh->dv_module >= MAX_MODULE_ID)
  {
    return;
  }

  struct dstar_stream_info * si = stream_info + dh->dv_module;


  if (dv_stream_id != si->stream_id)
  {
    si->stream_id = dv_stream_id;
    si->stream_counter = 0;
    si->dstar_dv_errs = 0;
    si->dstar_dv_silent = 0;
  }


  if (si->stream_counter == 30) // the tx_msg should have been received by now
  {
    flush_mheard_data_module( dh->dv_module );
  }


  if (dv_type & 0x80) // header
  {
    si->sd_type = 0x00;


    if (len < ((sizeof (struct dstar_dv_header)) + 1 + (sizeof (struct dstar_dv_rf_header))))
    {
      return;
    }

    const struct dstar_dv_rf_header * rh = (struct dstar_dv_rf_header *) d;

    if ((dv_type & 0x20) == 0)  // CRC OK
    {
      struct dstar_mheard_info * mh = mheard_info + dh->dv_module;

      memcpy (mh->my_callsign, rh->my_callsign, sizeof mh->my_callsign);
      memcpy (mh->my_callsign_ext, rh->my_callsign_ext, sizeof mh->my_callsign_ext);
      memcpy (mh->your_callsign, rh->your_callsign, sizeof mh->your_callsign);
      memcpy (mh->rpt1_callsign, rh->rpt1_callsign, sizeof mh->rpt1_callsign);
      memcpy (mh->rpt2_callsign, rh->rpt2_callsign, sizeof mh->rpt2_callsign);
      memcpy (mh->flags, rh->flags, sizeof mh->flags);

      memset (mh->tx_msg, ' ', sizeof mh->tx_msg);
      mh->info_type = ' ';

      si->mheard_info_timer = MHEARD_INFO_TIMEOUT;
      si->mheard_info_valid = 1;

      int found = 0;
      int i;

      for (i=0; i < 3; i++)
      {
	if (module_letters[i] == rh->rpt1_callsign[7])
	{
	  found = 1;
	  break;
	}
      }

      if (found)
      {
	autolearn_letters[ dh->dv_module ] = rh->rpt1_callsign[7];
      }

    }
    else
    {
      si->mheard_info_valid = 0;
    }

  }
  else
  {
    if (len < ((sizeof (struct dstar_dv_header)) + 1 + (sizeof (struct dstar_dv_data))))
    {
      return;
    }

    if (dv_type & 0x40) // end flag received
    {
      flush_mheard_data_module( dh->dv_module );

      if ( (si->stream_counter > 10 )
	  && (si->mheard_info_valid))
      {
	char buf[20];
	int percent_silent = (si->dstar_dv_silent * 100) / si->stream_counter;
	int permille_ber = (si->dstar_dv_errs * 125) / (si->stream_counter * 6);
	sprintf (buf, "%04x%02x%02x", si->stream_counter, percent_silent,
	  permille_ber);
	if (strlen(buf) == 8)
	{
	  struct dstar_mheard_info * mh = mheard_info + dh->dv_module;
	  memset (mh->tx_msg, ' ', sizeof mh->tx_msg);
	  mh->info_type = 'S';
	  memcpy( mh->tx_msg, buf, 8 );
	  si->mheard_info_timer = 1;
	  flush_mheard_data_module( dh->dv_module );
	}
      }

      si->stream_counter = 0;
    }
    else
    {
      int data_pos = dv_type & 0x1F;

      const struct dstar_dv_data * dd = (struct dstar_dv_data *) d;

      int data[3];
      int errs = dstar_dv_decode( dd->dv_voice, data );

      if (data[0] == 0xf85) // silence frame
      {
	si->dstar_dv_silent ++;
      }

      if ((data[0] & 0x0ffc) == 0xfc0) // DTMF tone
      {
	int dtmf = (data[0] & 0x03) | ((data[2] & 0x60) >> 3);
	syslog(LOG_INFO, "DTMF '%c'", dtmf_chars[dtmf] );
      }


      si->dstar_dv_errs += errs;
      si->stream_counter ++ ;

      int sd[3];

      sd[0] = dd->dv_slowdata[0] ^ 0x70;
      sd[1] = dd->dv_slowdata[1] ^ 0x4f;
      sd[2] = dd->dv_slowdata[2] ^ 0x93;

      if ((sd[0] == 0x25) && (sd[1] == 0x1a) && (sd[2] == 0xc6))
      {
	// DSTAR end flag
	flush_mheard_data_module( dh->dv_module );
      }
      else if (data_pos == 0)
      {
	/*
	if ((sd[0] != 0x25) || (sd[1] != 0x62) || (sd[2] != 0x85))
	{
	  printf("SYNC_ERROR ");
	}
	printf ("SYNC %02x %02x %02x", sd[0], sd[1], sd[2]);
	*/

      }
      else
      {
	int s_len = 0;
	int * s_ptr = sd;

	if ((data_pos & 0x01) == 0x01)
	{
	  si->sd_type = sd[0];
	  s_len = sd[0] & 0x07;
	  if (s_len > 5)
	  {
	    s_len = 5;
	  }


	  if (s_len > 2)
	  {
	    s_len = 2; // print 2 bytes in from this packet
	  }

	  s_ptr ++; // first byte is type byte, skip it
	}
	else
	{
	  s_len = si->sd_type & 0x07;
	  if (s_len > 5)
	  {
	    s_len = 5;
	  }

	  if (s_len > 2)
	  {
	    s_len -= 2; // 2 bytes printed in previous packet
	  }
	  else
	  {
	    s_len = 0;
	  }

	}

	switch (si->sd_type & 0xF0)
	{
	  
	  case 0x30:
	    // printf ("User Data: ");
	    break;

	  case 0x40:
	    if ((data_pos & 0x01) == 0x01)
	    {
	      s_len = 2;
	      mheard_info[dh->dv_module].tx_msg[(si->sd_type & 0x03) * 5] = sd[1];
	      mheard_info[dh->dv_module].tx_msg[(si->sd_type & 0x03) * 5 +1] = sd[2];
	    }
	    else
	    {
	      s_len = 3;
	      mheard_info[dh->dv_module].tx_msg[(si->sd_type & 0x03) * 5 +2] = sd[0];
	      mheard_info[dh->dv_module].tx_msg[(si->sd_type & 0x03) * 5 +3] = sd[1];
	      mheard_info[dh->dv_module].tx_msg[(si->sd_type & 0x03) * 5 +4] = sd[2];
	    }
	    break;

	  case 0x50:
	    //printf ("RF-Header: " );
	    break;

	  case 0x60:
	    //printf ("NOP");
	    s_len = 0;
	    break;

	  case 0xC0:
	    //printf ("Code Squelch: " );
	    break;

	  default:
	    //printf ("UNKNOWN %02x: ", sd_type[dh->dv_module]);
	    break;
	}

      }

    }
  }
}

static void process_packet ( const u_char * packet, int len )
{
  const struct ethhdr * eh = (struct ethhdr *) packet;

  if (ntohs(eh->h_proto) != ETH_P_IP)
  {
    // printf ("unknown eth proto %d\n", ntohs(eh->h_proto));
    return;
  }

  const struct iphdr * ih = (struct iphdr *) (packet + (sizeof (struct ethhdr)));

  if (ih->protocol != IPPROTO_UDP)
  {
    // printf ("unknown ip proto %d\n", ih->protocol);
    return;
  }

  const struct udphdr * uh = (struct udphdr *) (packet +
    (sizeof (struct ethhdr)) + (sizeof (struct iphdr)));

  int udp_len = ntohs(uh->len);


  if ((udp_len + (sizeof (struct ethhdr)) + (sizeof (struct iphdr))) > len)
  {
    // printf ("unexpected packet len %d %d\n", len, udp_len);
    return;
  }



  const struct dstar_header * dh = (struct dstar_header *) (packet + ((sizeof (struct ethhdr))
        + (sizeof (struct iphdr)) + (sizeof (struct udphdr))));

  if (strncmp("DSTR", dh->dstar_id, 4) != 0)
  {
    // printf ("not a DSTR header\n");
    return;
  }

  unsigned short dstar_data_len = ntohs(dh->dstar_data_len);

  if ((dstar_data_len + (sizeof(struct dstar_header))) != (udp_len - (sizeof (struct udphdr))))
  {
    // printf ("unexpected dstar packet len %d %d %lu %lu\n", dstar_data_len, udp_len,
    //  (sizeof(struct dstar_header)) , (sizeof (struct udphdr)) );
    return;
  }

  if (dh->dstar_rs_flag != 0x73)
  {
    return;
  }

  const u_char * dstar_data = (u_char *) (packet + ((sizeof (struct ethhdr))
          + (sizeof (struct iphdr)) + (sizeof (struct udphdr))) + sizeof (struct dstar_header));


  switch (dh->dstar_pkt_type)
  {
    case DSTAR_PKT_TYPE_DV:
      process_dv_data (dstar_data, dstar_data_len);
      break;

    case DSTAR_PKT_TYPE_DD:
      break;

    case DSTAR_PKT_TYPE_MODULE_HEARD:
      process_module_heard(dstar_data, dstar_data_len);
      break;


    case DSTAR_PKT_TYPE_NOP:
      // printf("NOP");
      break;

    default:
      // printf ("dstar type %02x unknown", dh->dstar_pkt_type);
      break;
  }


}


static void usage(const char * a)
{
  fprintf (stderr, "Usage: %s -f <pcap-file> <module letters> <udp port> <pcap rules>\n"
	"Usage: %s -i <ethX> <module letters> <udp port> <pcap rules> [<pid file>]\n", a, a);
}




int main(int argc, char *argv[])
{

  if ((argc < 6) || (argc > 7))
  {
    usage(argv[0]);
    return 1;
  }


  openlog (SYSLOG_PROGRAM_NAME, LOG_PID, LOG_DAEMON);

  pcap_t *handle;

  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  struct pcap_pkthdr * header;
  const u_char *packet;

  int udp_port;

  udp_port = atoi(argv[4]);

  if ((udp_port < 1) || (udp_port > 65534))
  {
    fprintf(stderr, "UDP port out of range: %d\n", udp_port);
    usage(argv[0]);
    return 2;
  }

  udp_socket = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

  if (udp_socket < 0)
  {
    fprintf(stderr, "could not open socket\n");
    return 2;
  }

  struct sockaddr_in bind_addr;

  bind_addr.sin_family = AF_INET;
  bind_addr.sin_port = 0;
  bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  if (bind( udp_socket, (struct sockaddr *) & bind_addr, sizeof bind_addr ) != 0)
  {
    fprintf(stderr, "could not bind socket\n");
    return 2;
  }

  struct sockaddr_in dest_addr;

  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons(udp_port);
  dest_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  if (connect( udp_socket, (struct sockaddr *) & dest_addr, sizeof dest_addr ) != 0)
  {
    fprintf(stderr, "could not set destination address\n");
    return 2;
  }

  module_letters = argv[3];

  if (strlen(module_letters) != 3)
  {
    fprintf(stderr, "module_letters string must have 3 characters; default: 'ABC'\n");
    usage(argv[0]);
    return 2;
  }


  if (strcmp("-f", argv[1]) == 0)
  {
    handle = pcap_open_offline(argv[2], errbuf);

    if (handle == NULL)
    {
      fprintf(stderr, "Couldn't open pcap file %s: %s\n", argv[2], errbuf);
      usage(argv[0]);
      return 2;
    }
  }
  else if (strcmp("-i", argv[1]) == 0)
  {
#define PKT_BUFSIZ 2000 
    handle = pcap_open_live(argv[2], PKT_BUFSIZ, 1, 500, errbuf);

    if (handle == NULL)
    {
      fprintf(stderr, "Couldn't open device %s: %s\n", argv[2], errbuf);
      usage(argv[0]);
      return 2;
    }
  }
  else
  {
    usage(argv[0]);
    return 3;
  }


  if (pcap_compile(handle, &fp, argv[5], 0, 0) == -1)
  {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", argv[5], pcap_geterr(handle));
    usage(argv[0]);
    return 4;
  }

  if (pcap_setfilter(handle, &fp) == -1)
  {
    fprintf(stderr, "Couldn't install filter %s: %s\n", argv[5], pcap_geterr(handle));
    usage(argv[0]);
    return 5;
  }

  int fd = pcap_get_selectable_fd(handle);

  if (fd < 0)
  {
    fprintf(stderr, "Couldn't get file descriptor for select\n");
    return 6;
  }

  const char * pidfile_name = NULL;

  if (argc == 7)
  {
    pidfile_name = argv[6];
  }

  struct pidfh * pfh = NULL;

  if (pidfile_name != NULL)
  {
    pid_t otherpid;

    pfh = pidfile_open(pidfile_name, 0600, &otherpid);

    if (pfh == NULL)
    {
      if (errno == EEXIST)
      {
        fprintf(stderr, "daemon already running, pid=%d\n", otherpid);
      }
      else
      {
	fprintf(stderr, "cannot open or create pid file\n");
	perror("pidfile_open");
      }
      return 7;
    }

    if (daemon(0, 0) != 0)
    {
      fprintf(stderr, "cannot daemonize\n");
      perror("daemon");
      pidfile_remove(pfh);
      return 8;
    }
  }

  if (pfh != NULL)
  {
    pidfile_write(pfh);
  }

  dstar_dv_init();

  int i;
  for (i=0; i < MAX_MODULE_ID; i++)
  {
    autolearn_letters[i] = ' ';
  }

  syslog(LOG_INFO, "start");

  int count = 0;

  while(1)
  {
    fd_set rfds;
    struct timeval tv;
    int retval;

    tv.tv_sec = 0;
    tv.tv_usec = SELECT_TIMEOUT;

    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);

    retval = select(fd + 1, &rfds, NULL, NULL, &tv);

    if (retval < 0)
    {
      syslog(LOG_ERR, "select failed, stop (errno=%d)", errno);
      break;
    }

    if (retval == 0)
    {
      flush_mheard_data();
      count = 0;
      continue;
    }

    count ++;

    if (count > 10)
    {
      flush_mheard_data();
      count = 0;
    }

    int res = pcap_next_ex( handle, &header, &packet);

    if (res != 1)
    {
      if (res == -2)
      {
	break;
      }

      syslog(LOG_NOTICE, "pcap_next_ex: %d", res);
      continue;
    }
    process_packet(packet, header->len);

  }
  pcap_close(handle);
  if (pfh != NULL)
  {
    pidfile_remove(pfh);
  }
  syslog(LOG_INFO, "stop");
  return 0;
}


