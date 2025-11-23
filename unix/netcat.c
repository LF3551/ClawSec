
#include <unistd.h>    // close, sleep, dup2, execl, read, write
#include <stdlib.h>    // exit, malloc, free, alarm
#include <string.h>    // strcpy, strncpy, memset, memcpy, strcmp, strcasecmp
#include <stdio.h>     // printf, fprintf, perror, sprintf
#include <stdarg.h>    // если будут новые объявления varargs
#include "generic.h"		/* same as with L5, skey, etc */
#include "farm9crypt.h"
#define HAVE_BIND             /* ASSUMPTION -- seems to work everywhere! */
#define HAVE_HELP             /* undefine if you dont want the help text */
/* #define ANAL */            /* if you want case-sensitive DNS matching */

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#else
#include <malloc.h>
#endif
#ifdef HAVE_SELECT_H		/* random SV variants need this */
#include <sys/select.h>
#endif

/* have to do this *before* including types.h. xxx: Linux still has it wrong */
#ifdef FD_SETSIZE		/* should be in types.h, butcha never know. */
#undef FD_SETSIZE		/* if we ever need more than 16 active */
#endif				/* fd's, something is horribly wrong! */
#define FD_SETSIZE 16		/* <-- this'll give us a long anyways, wtf */
#include <sys/types.h>		/* *now* do it.  Sigh, this is broken */
#ifdef HAVE_RANDOM		/* aficionados of ?rand48() should realize */
#define SRAND srandom		/* that this doesn't need *strong* random */
#define RAND random		/* numbers just to mix up port numbers!! */
#else
#define SRAND srand
#define RAND rand
#endif /* HAVE_RANDOM */

/* includes: */
#include <sys/time.h>		/* timeval, time_t */
#include <time.h>		/* time() */
#include <setjmp.h>		/* jmp_buf et al */
#include <sys/socket.h>		/* basics, SO_ and AF_ defs, sockaddr, ... */
#include <netinet/in.h>		/* sockaddr_in, htons, in_addr */
#include <netinet/in_systm.h>	/* misc crud that netinet/ip.h references */
#include <netinet/ip.h>		/* IPOPT_LSRR, header stuff */
#include <netdb.h>		/* hostent, gethostby*, getservby* */
#include <arpa/inet.h>		/* inet_ntoa */
#include <stdio.h>
#include <string.h>		/* strcpy, strchr, yadda yadda */
#include <errno.h>
#include <signal.h>
#include <fcntl.h>		/* O_WRONLY et al */

#ifdef LINUX
#include <resolv.h>
#endif

/* ANSI color codes for chat mode */
#define COLOR_RESET   "\033[0m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_CYAN    "\033[36m"

/* handy stuff: */
#define SA struct sockaddr	/* socket overgeneralization braindeath */
#define SAI struct sockaddr_in	/* ... whoever came up with this model */
#define IA struct in_addr	/* ... should be taken out and shot, */
				/* ... not that TLI is any better.  sigh.. */
#define SLEAZE_PORT 31337	/* for UDP-scan RTT trick, change if ya want */
#define USHORT unsigned short	/* use these for options an' stuff */
#define BIGSIZ 8192		/* big buffers */
#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif
#ifdef MAXHOSTNAMELEN
#undef MAXHOSTNAMELEN		/* might be too small on aix, so fix it */
#endif
#define MAXHOSTNAMELEN 256
#define MAXKEYSIZE 32

struct host_poop {
  char name[MAXHOSTNAMELEN];	/* dns name */
  char addrs[8][24];		/* ascii-format IP addresses */
  struct in_addr iaddrs[8];	/* real addresses: in_addr.s_addr: ulong */
};
#define HINF struct host_poop

struct port_poop {
  char name [64];		/* name in /etc/services */
  char anum [8];		/* ascii-format number */
  USHORT num;			/* real host-order number */
};
#define PINF struct port_poop

/* globals: */
jmp_buf jbuf;			/* timer crud */
int jval = 0;			/* timer crud */
int netfd = -1;
int ofd = 0;			/* hexdump output fd */
static char unknown[] = "(UNKNOWN)";
static char p_tcp[] = "tcp";	/* for getservby* */
static char p_udp[] = "udp";
#ifdef HAVE_BIND
extern int h_errno;
/* stolen almost wholesale from bsd herror.c */
static char * h_errs[] = {
  "Error 0",				/* but we *don't* use this */
  "Unknown host",			/* 1 HOST_NOT_FOUND */
  "Host name lookup failure",		/* 2 TRY_AGAIN */
  "Unknown server error",		/* 3 NO_RECOVERY */
  "No address associated with name",	/* 4 NO_ADDRESS */
};
#else
int h_errno;			/* just so we *do* have it available */
#endif /* HAVE_BIND */
int gatesidx = 0;		/* LSRR hop count */
int gatesptr = 4;		/* initial LSRR pointer, settable */
USHORT Single = 1;		/* zero if scanning */
unsigned int insaved = 0;	/* stdin-buffer size for multi-mode */
unsigned int wrote_out = 0;	/* total stdout bytes */
unsigned int wrote_net = 0;	/* total net bytes */
static char wrote_txt[] = " sent %d, rcvd %d";
static char hexnibs[20] = "0123456789abcdef  ";

/* will malloc up the following globals: */
struct timeval * timer1 = NULL;
struct timeval * timer2 = NULL;
SAI * lclend = NULL;		/* sockaddr_in structs */
SAI * remend = NULL;
HINF ** gates = NULL;		/* LSRR hop hostpoop */
char * optbuf = NULL;		/* LSRR or sockopts */
char * bigbuf_in;		/* data buffers */
char * bigbuf_net;
fd_set * ding1;			/* for select loop */
fd_set * ding2;
PINF * portpoop = NULL;		/* for getportpoop / getservby* */
unsigned char * stage = NULL;	/* hexdump line buffer */

/* global cmd flags: */
USHORT o_alla = 0;
unsigned int o_interval = 0;
USHORT o_listen = 0;
USHORT o_nflag = 0;
USHORT o_wfile = 0;
USHORT o_random = 0;
USHORT o_udpmode = 0;
USHORT o_verbose = 0;
unsigned int o_wait = 0;
USHORT o_zero = 0;
/* o_tn in optional section */

/* Function prototypes */
#ifdef HAVE_HELP
void helpme(void);
#endif

/* Debug macro: squirt whatever message and sleep a bit so we can see it go
   by.  need to call like Debug ((stuff)) [with no ; ] so macro args match!
   Beware: writes to stdOUT... */
#ifdef DEBUG
#define Debug(x) printf x; printf ("\n"); fflush (stdout); sleep (1);
#else
#define Debug(x)	/* nil... */
#endif


void holler(char *str, char *p1, char *p2, char *p3, char *p4, char *p5, char *p6)
{
  if (o_verbose) {
    fprintf (stderr, str, p1, p2, p3, p4, p5, p6);
#ifdef HAVE_BIND
    if (h_errno) {		/* if host-lookup variety of error ... */
      if (h_errno > 4)		/* oh no you don't, either */
	fprintf (stderr, "preposterous h_errno: %d", h_errno);
      else
	fprintf (stderr, "%s", h_errs[h_errno]);
      h_errno = 0;				/* and reset for next call */
    }
#endif
    if (errno) {		/* this gives funny-looking messages, but */
      perror (" ");		/* it's more portable than sys_errlist[]... */
    } else			/* xxx: do something better?  */
      fprintf (stderr, "\n");
    fflush (stderr);
  }
} /* holler */

/* bail :
   error-exit handler, callable from anywhere */
void bail(char *str, char *p1, char *p2, char *p3, char *p4, char *p5, char *p6)
{
  o_verbose = 1;
  holler(str, p1, p2, p3, p4, p5, p6);
  close(netfd);
  sleep(1);
  exit(1);
}


/* catch :
   no-brainer interrupt handler */
void catch ()
{
  errno = 0;
  if (o_verbose > 1)		/* normally we don't care */
    bail(wrote_txt, (char *) (intptr_t) wrote_net, (char *) (intptr_t) wrote_out, NULL, NULL, NULL, NULL);
  bail(" punt!", NULL, NULL, NULL, NULL, NULL, NULL);
}

/* timeout and other signal handling cruft */
void tmtravel ()
{
  signal (SIGALRM, SIG_IGN);
  alarm (0);
  if (jval == 0)
    bail("spurious timer interrupt!", NULL, NULL, NULL, NULL, NULL, NULL);
  longjmp (jbuf, jval);
}

/* arm :
   set the timer.  Zero secs arg means unarm */
void arm(unsigned int num, unsigned int secs)
{
  if (secs == 0) { /* reset */
    signal (SIGALRM, SIG_IGN);
    alarm (0);
    jval = 0;
  } else { /* set */
    signal (SIGALRM, tmtravel);
    alarm (secs);
    jval = num;
  }
}


char *Hmalloc(unsigned int size)
{
  unsigned int s = (size + 4) & 0xfffffffc;	/* 4GB?! */
  char *p = malloc(s);
  if (p != NULL)
    memset(p, 0, s);
  else
    bail("Hmalloc %d failed", (char *)(intptr_t)s, NULL, NULL, NULL, NULL, NULL);
  return p;
}


unsigned int findline(char *buf, unsigned int siz)
{
  register char *p;
  register int x;
  if (!buf)
    return 0;
  if (siz > BIGSIZ)
    return 0;
  x = siz;
  for (p = buf; x > 0; x--) {
    if (*p == '\n') {
      x = (int)(p - buf);
      x++;
      Debug(("findline returning %d", x))
      return x;
    }
    p++;
  }
  Debug(("findline returning whole thing: %d", siz))
  return siz;
}


int comparehosts(HINF *poop, struct hostent *hp)
{
  errno = 0;
  h_errno = 0;
#ifdef ANAL
  if (strcmp(poop->name, hp->h_name) != 0) {
#else
  if (strcasecmp(poop->name, hp->h_name) != 0) {
#endif
    holler("DNS fwd/rev mismatch: %s != %s", poop->name, hp->h_name, NULL, NULL, NULL, NULL);
    return 1;
  }
  return 0;
}


HINF *gethostpoop(char *name, USHORT numeric)
{
  struct hostent *hostent;
  struct in_addr iaddr;
  register HINF *poop = NULL;
  register int x;

  errno = 0;
  h_errno = 0;
  if (name)
    poop = (HINF *)Hmalloc(sizeof(HINF));
  if (!poop)
    bail("gethostpoop fuxored", NULL, NULL, NULL, NULL, NULL, NULL);
  strcpy(poop->name, unknown);

  iaddr.s_addr = inet_addr(name);

  if (iaddr.s_addr == INADDR_NONE) {
    if (numeric)
      bail("Can't parse %s as an IP address", name, NULL, NULL, NULL, NULL, NULL);
    hostent = gethostbyname(name);
    if (!hostent)
      bail("%s: forward host lookup failed: ", name, NULL, NULL, NULL, NULL, NULL);
    strncpy(poop->name, hostent->h_name, MAXHOSTNAMELEN - 2);
    for (x = 0; hostent->h_addr_list[x] && (x < 8); x++) {
      memcpy(&poop->iaddrs[x], hostent->h_addr_list[x], sizeof(IA));
      strncpy(poop->addrs[x], inet_ntoa(poop->iaddrs[x]), sizeof(poop->addrs[0]) - 1);
      poop->addrs[x][sizeof(poop->addrs[0]) - 1] = '\0';
    }
    if (!o_verbose)
      return poop;
    for (x = 0; poop->iaddrs[x].s_addr && (x < 8); x++) {
      hostent = gethostbyaddr((char *)&poop->iaddrs[x], sizeof(IA), AF_INET);
      if ((!hostent) || (!hostent->h_name))
        holler("Warning: inverse host lookup failed for %s: ", poop->addrs[x], NULL, NULL, NULL, NULL, NULL);
      else
        (void)comparehosts(poop, hostent);
    }
  } else {
    memcpy(poop->iaddrs, &iaddr, sizeof(IA));
    strncpy(poop->addrs[0], inet_ntoa(iaddr), sizeof(poop->addrs[0]) - 1);
    poop->addrs[0][sizeof(poop->addrs[0]) - 1] = '\0';
    if (numeric)
      return poop;
    if (!o_verbose)
      return poop;
    hostent = gethostbyaddr((char *)&iaddr, sizeof(IA), AF_INET);
    if (!hostent)
      holler("%s: inverse host lookup failed: ", name, NULL, NULL, NULL, NULL, NULL);
    else {
      strncpy(poop->name, hostent->h_name, MAXHOSTNAMELEN - 2);
      hostent = gethostbyname(poop->name);
      if ((!hostent) || (!hostent->h_addr_list[0]))
        holler("Warning: forward host lookup failed for %s: ", poop->name, NULL, NULL, NULL, NULL, NULL);
      else
        (void)comparehosts(poop, hostent);
    }
  }
  h_errno = 0;
  return poop;
}



USHORT getportpoop(char *pstring, unsigned int pnum)
{

  struct servent * servent;
  register int x;
  register int y;
  char * whichp = p_tcp;
  if (o_udpmode)
    whichp = p_udp;
  portpoop->name[0] = '?';		/* fast preload */
  portpoop->name[1] = '\0';

/* case 1: reverse-lookup of a number; placed first since this case is much
   more frequent if we're scanning */
  if (pnum) {
    if (pstring)			/* one or the other, pleeze */
      return (0);
    x = pnum;
    if (o_nflag)			/* go faster, skip getservbyblah */
      goto gp_finish;
    y = htons (x);			/* gotta do this -- see Fig.1 below */
    servent = getservbyport (y, whichp);
    if (servent) {
      y = ntohs (servent->s_port);
      if (x != y)			/* "never happen" */
	holler("Warning: port-bynum mismatch, %d != %d", (char *)(intptr_t)x, (char *)(intptr_t)y, NULL, NULL, NULL, NULL);
      strncpy (portpoop->name, servent->s_name, sizeof (portpoop->name));
    } /* if servent */
    goto gp_finish;
  } /* if pnum */


  if (pstring) {
    if (pnum)				/* one or the other, pleeze */
      return (0);
    x = atoi (pstring);
    if (x)
      return (getportpoop (NULL, x));	/* recurse for numeric-string-arg */
    if (o_nflag)			/* can't use names! */
      return (0);
    servent = getservbyname (pstring, whichp);
    if (servent) {
      strncpy (portpoop->name, servent->s_name, sizeof (portpoop->name));
      x = ntohs (servent->s_port);
      goto gp_finish;
    } /* if servent */
  } /* if pstring */

  return (0);				/* catches any problems so far */

/* Obligatory netdb.h-inspired rant: servent.s_port is supposed to be an int.
   Despite this, we still have to treat it as a short when copying it around.
   Not only that, but we have to convert it *back* into net order for
   getservbyport to work.  Manpages generally aren't clear on all this, but
   there are plenty of examples in which it is just quietly done.  More BSD
   lossage... since everything getserv* ever deals with is local to our own
   host, why bother with all this network-order/host-order crap at all?!
   That should be saved for when we want to actually plug the port[s] into
   some real network calls -- and guess what, we have to *re*-convert at that
   point as well.  Fuckheads. */

gp_finish:
/* Fall here whether or not we have a valid servent at this point, with
   x containing our [host-order and therefore useful, dammit] port number */
  sprintf (portpoop->anum, "%d", x);	/* always load any numeric specs! */
  portpoop->num = (x & 0xffff);		/* ushort, remember... */
  return (portpoop->num);
} /* getportpoop */

/* nextport :
   Come up with the next port to try, be it random or whatever.  "block" is
   a ptr to randports array, whose bytes [so far] carry these meanings:
	0	ignore
	1	to be tested
	2	tested [which is set as we find them here]
   returns a USHORT random port, or 0 if all the t-b-t ones are used up. */
USHORT nextport(char *block)
{

  register unsigned int x;
  register unsigned int y;

  y = 70000;			/* high safety count for rnd-tries */
  while (y > 0) {
    x = (RAND() & 0xffff);
    if (block[x] == 1) {	/* try to find a not-done one... */
      block[x] = 2;
      break;
    }
    x = 0;			/* bummer. */
    y--;
  } /* while y */
  if (x)
    return (x);

  y = 65535;			/* no random one, try linear downsearch */
  while (y > 0) {		/* if they're all used, we *must* be sure! */
    if (block[y] == 1) {
      block[y] = 2;
      break;
    }
    y--;
  } /* while y */
  if (y)
    return (y);			/* at least one left */

  return (0);			/* no more left! */
} /* nextport */


void loadports(char *block, USHORT lo, USHORT hi)
{
  USHORT x;

  if (!block)
    bail("loadports: no block?!", NULL, NULL, NULL, NULL, NULL, NULL);

  if ((!lo) || (!hi)) {
    char slo[16], shi[16];
    sprintf(slo, "%d", lo);
    sprintf(shi, "%d", hi);
    bail("loadports: bogus values %s, %s", slo, shi, NULL, NULL, NULL, NULL);
  }

  x = hi;
  while (lo <= x) {
    block[x] = 1;
    x--;
  }
}


#ifdef GAPING_SECURITY_HOLE
char * pr00gie = NULL;			/* global ptr to -e arg */

/* doexec :
   fiddle all the file descriptors around, and hand off to another prog.  Sort
   of like a one-off "poor man's inetd".  This is the only section of code
   that would be security-critical, which is why it's ifdefed out by default.
   Use at your own hairy risk; if you leave shells lying around behind open
   listening ports you deserve to lose!! */
void doexec(int fd)
{
  register char * p;

  dup2 (fd, 0);				/* the precise order of fiddlage */
  close (fd);				/* is apparently crucial; this is */
  dup2 (0, 1);				/* swiped directly out of "inetd". */
  dup2 (0, 2);
  p = strrchr (pr00gie, '/');		/* shorter argv[0] */
  if (p)
    p++;
  else
    p = pr00gie;
Debug (("gonna exec %s as %s...", pr00gie, p))
  execl (pr00gie, p, NULL);
  bail("exec %s failed", pr00gie, NULL, NULL, NULL, NULL, NULL);
} /* doexec */
#endif /* GAPING_SECURITY_HOLE */

/* doconnect :
   do all the socket stuff, and return an fd for one of
	an open outbound TCP connection
	a UDP stub-socket thingie
   with appropriate socket options set up if we wanted source-routing, or
	an unconnected TCP or UDP socket to listen on.
   Examines various global o_blah flags to figure out what-all to do. */
int doconnect(IA *rad, USHORT rp, IA *lad, USHORT lp)
{
  register int nnetfd;
  register int rr;
  int x, y;
  errno = 0;

/* grab a socket; set opts */
newskt:
  if (o_udpmode)
    nnetfd = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  else
    nnetfd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (nnetfd < 0)
    bail("Can't get socket", NULL, NULL, NULL, NULL, NULL, NULL);
  if (nnetfd == 0)		/* if stdin was closed this might *be* 0, */
    goto newskt;		/* so grab another.  See text for why... */
  x = 1;
  rr = setsockopt (nnetfd, SOL_SOCKET, SO_REUSEADDR, &x, sizeof (x));
  if (rr == -1)
    holler("nnetfd reuseaddr failed", NULL, NULL, NULL, NULL, NULL, NULL);
#ifdef SO_REUSEPORT	/* doesnt exist everywhere... */
  rr = setsockopt (nnetfd, SOL_SOCKET, SO_REUSEPORT, &x, sizeof (x));
  if (rr == -1)
    holler("nnetfd reuseport failed", NULL, NULL, NULL, NULL, NULL, NULL);
#endif
#if 0
/* If you want to screw with RCVBUF/SNDBUF, do it here.  Liudvikas Bukys at
   Rochester sent this example, which would involve YET MORE options and is
   just archived here in case you want to mess with it.  o_xxxbuf are global
   integers set in main() getopt loop, and check for rr == 0 afterward. */
  rr = setsockopt(nnetfd, SOL_SOCKET, SO_RCVBUF, &o_rcvbuf, sizeof o_rcvbuf);
  rr = setsockopt(nnetfd, SOL_SOCKET, SO_SNDBUF, &o_sndbuf, sizeof o_sndbuf);
#endif
  
  /* fill in all the right sockaddr crud */
    lclend->sin_family = AF_INET;

/* fill in all the right sockaddr crud */
  lclend->sin_family = AF_INET;
  remend->sin_family = AF_INET;

/* if lad/lp, do appropriate binding */
  if (lad)
    memcpy (&lclend->sin_addr.s_addr, lad, sizeof (IA));
  if (lp)
    lclend->sin_port = htons (lp);
  rr = 0;
  if (lad || lp) {
    x = (int) lp;
/* try a few times for the local bind, a la ftp-data-port... */
    for (y = 4; y > 0; y--) {
      rr = bind (nnetfd, (SA *)lclend, sizeof (SA));
      if (rr == 0)
	break;
      if (errno != EADDRINUSE)
	break;
      else {
	holler("retrying local %s:%d", inet_ntoa(lclend->sin_addr), (char *)(intptr_t)lp, NULL, NULL, NULL, NULL);
	sleep (2);
	errno = 0;			/* clear from sleep */
      } /* if EADDRINUSE */
    } /* for y counter */
  } /* if lad or lp */
  if (rr)
    bail("Can't grab %s:%d with bind", inet_ntoa(lclend->sin_addr), (char *)(intptr_t)lp, NULL, NULL, NULL, NULL);


  if (o_listen)
    return (nnetfd);			/* thanks, that's all for today */

  memcpy (&remend->sin_addr.s_addr, rad, sizeof (IA));
  remend->sin_port = htons (rp);


  if (gatesidx) {		/* if we wanted any srcrt hops ... */
/* don't even bother compiling if we can't do IP options here! */
#ifdef IP_OPTIONS
    if (! optbuf) {		/* and don't already *have* a srcrt set */
      char * opp;		/* then do all this setup hair */
      optbuf = Hmalloc (48);
      opp = optbuf;
      *opp++ = (unsigned char)IPOPT_LSRR;

      *opp++ = (char)
	(((gatesidx + 1) * sizeof (IA)) + 3) & 0xff;		/* length */
      *opp++ = gatesptr;					/* pointer */
/* opp now points at first hop addr -- insert the intermediate gateways */
      for ( x = 0; x < gatesidx; x++) {
	memcpy (opp, gates[x]->iaddrs, sizeof (IA));
	opp += sizeof (IA);
      }
/* and tack the final destination on the end [needed!] */
      memcpy (opp, rad, sizeof (IA));
      opp += sizeof (IA);
      *opp = IPOPT_NOP;			/* alignment filler */
    } /* if empty optbuf */
/* calculate length of whole option mess, which is (3 + [hops] + [final] + 1),
   and apply it [have to do this every time through, of course] */
    x = ((gatesidx + 1) * sizeof (IA)) + 4;
    rr = setsockopt (nnetfd, IPPROTO_IP, IP_OPTIONS, optbuf, x);
    if (rr == -1)
      bail("srcrt setsockopt fuxored", NULL, NULL, NULL, NULL, NULL, NULL);
#else /* IP_OPTIONS */
    holler ("Warning: source routing unavailable on this machine, ignoring");
#endif /* IP_OPTIONS*/
  } /* if gatesidx */

/* wrap connect inside a timer, and hit it */
  arm (1, o_wait);
  if (setjmp (jbuf) == 0) {
    rr = connect (nnetfd, (SA *)remend, sizeof (SA));
  } else {				/* setjmp: connect failed... */
    rr = -1;
    errno = ETIMEDOUT;			/* fake it */
  }
  arm (0, 0);
  if (rr == 0)
    return (nnetfd);
  close (nnetfd);			/* clean up junked socket FD!! */
  return (-1);
} /* doconnect */


int dolisten(IA *rad, USHORT rp, IA *lad, USHORT lp)
{
  register int nnetfd;
  register int rr;
  HINF * whozis = NULL;
  char * cp;
  USHORT z;
  errno = 0;

/* Pass everything off to doconnect, who in o_listen mode just gets a socket */
  nnetfd = doconnect (rad, rp, lad, lp);
  if (nnetfd <= 0)
    return (-1);
  if (o_udpmode) {			/* apparently UDP can listen ON */
    if (! lp)				/* "port 0",  but that's not useful */
      bail("UDP listen needs -p arg", NULL, NULL, NULL, NULL, NULL, NULL);
  } else {
    rr = listen (nnetfd, 1);		/* gotta listen() before we can get */
    if (rr < 0)				/* our local random port.  sheesh. */
      bail("local listen fuxored", NULL, NULL, NULL, NULL, NULL, NULL);
  }


  if (o_verbose) {
    socklen_t slen;
    slen = sizeof(SA);
    rr = getsockname(nnetfd, (SA *)lclend, &slen);

    if (rr < 0)
      holler("local getsockname failed", NULL, NULL, NULL, NULL, NULL, NULL);
    strcpy (bigbuf_net, "listening on [");	/* buffer reuse... */
    if (lclend->sin_addr.s_addr)
      strcat (bigbuf_net, inet_ntoa (lclend->sin_addr));
    else
      strcat (bigbuf_net, "any");
    strcat (bigbuf_net, "] %d ...");
    z = ntohs (lclend->sin_port);
    holler(bigbuf_net, (char *)(intptr_t)z, NULL, NULL, NULL, NULL, NULL);
  } /* verbose -- whew!! */

/* UDP is a speeeeecial case -- we have to do I/O *and* get the calling
   party's particulars all at once, listen() and accept() don't apply.
   At least in the BSD universe, however, recvfrom/PEEK is enough to tell
   us something came in, and we can set things up so straight read/write
   actually does work after all.  Yow.  YMMV on strange platforms!  */
  if (o_udpmode) {
    socklen_t x;
    x = sizeof (SA);		/* retval for recvfrom */
    arm (2, o_wait);		/* might as well timeout this, too */
    if (setjmp (jbuf) == 0) {	/* do timeout for initial connect */
      rr = recvfrom		/* and here we block... */
	(nnetfd, bigbuf_net, BIGSIZ, MSG_PEEK, (SA *) remend, &x);
Debug (("dolisten/recvfrom ding, rr = %d, netbuf %s ", rr, bigbuf_net))
    } else
      goto dol_tmo;		/* timeout */
    arm (0, 0);
/* I'm not completely clear on how this works -- BSD seems to make UDP
   just magically work in a connect()ed context, but we'll undoubtedly run
   into systems this deal doesn't work on.  For now, we apparently have to
   issue a connect() on our just-tickled socket so we can write() back.
   Again, why the fuck doesn't it just get filled in and taken care of?!
   This hack is anything but optimal.  Basically, if you want your listener
   to also be able to send data back, you need this connect() line, which
   also has the side effect that now anything from a different source or even a
   different port on the other end won't show up and will cause ICMP errors.
   I guess that's what they meant by "connect".
   Let's try to remember what the "U" is *really* for, eh? */
    rr = connect (nnetfd, (SA *)remend, sizeof (SA));
    goto whoisit;
  } /* o_udpmode */

/* fall here for TCP */
socklen_t x;
  x = sizeof (SA);		/* retval for accept */
  arm (2, o_wait);		/* wrap this in a timer, too; 0 = forever */
  if (setjmp (jbuf) == 0) {
    rr = accept (nnetfd, (SA *)remend, &x);
  } else
    goto dol_tmo;		/* timeout */
  arm (0, 0);
  close (nnetfd);		/* dump the old socket */
  nnetfd = rr;			/* here's our new one */

whoisit:
  if (rr < 0)
    goto dol_err;		/* bail out if any errors so far */

/* If we can, look for any IP options.  Useful for testing the receiving end of
   such things, and is a good exercise in dealing with it.  We do this before
   the connect message, to ensure that the connect msg is uniformly the LAST
   thing to emerge after all the intervening crud.  Doesn't work for UDP on
   any machines I've tested, but feel free to surprise me. */
#ifdef IP_OPTIONS
  if (! o_verbose)			/* if we wont see it, we dont care */
    goto dol_noop;
  optbuf = Hmalloc (40);
  x = 40;
  rr = getsockopt (nnetfd, IPPROTO_IP, IP_OPTIONS, optbuf, &x);
  if (rr < 0)
    holler("getsockopt failed", NULL, NULL, NULL, NULL, NULL, NULL);
Debug (("ipoptions ret len %d", x))
  if (x) {				/* we've got options, lessee em... */
    unsigned char * q = (unsigned char *) optbuf;
    char * p = bigbuf_net;		/* local variables, yuk! */
    char * pp = &bigbuf_net[128];	/* get random space farther out... */
    memset (bigbuf_net, 0, 256);	/* clear it all first */
    while (x > 0) {
	sprintf (pp, "%2.2x ", *q);	/* clumsy, but works: turn into hex */
	strcat (p, pp);			/* and build the final string */
	q++; p++;
	x--;
    }
    holler("IP options: %s", bigbuf_net, NULL, NULL, NULL, NULL, NULL);

  } /* if x, i.e. any options */
dol_noop:
#endif /* IP_OPTIONS */

/* find out what address the connection was *to* on our end, in case we're
   doing a listen-on-any on a multihomed machine.  This allows one to
   offer different services via different alias addresses, such as the
   "virtual web site" hack. */
  memset (bigbuf_net, 0, 64);
  cp = &bigbuf_net[32];
  x = sizeof (SA);
  rr = getsockname (nnetfd, (SA *) lclend, &x);
  if (rr < 0)
    holler("post-rcv getsockname failed", NULL, NULL, NULL, NULL, NULL, NULL);
  strcpy (cp, inet_ntoa (lclend->sin_addr));

/* now check out who it is.  We don't care about mismatched DNS names here,
   but any ADDR and PORT we specified had better fucking well match the caller.
   Converting from addr to inet_ntoa and back again is a bit of a kludge, but
   gethostpoop wants a string and there's much gnarlier code out there already,
   so I don't feel bad.
   The *real* question is why BFD sockets wasn't designed to allow listens for
   connections *from* specific hosts/ports, instead of requiring the caller to
   accept the connection and then reject undesireable ones by closing.  In
   other words, we need a TCP MSG_PEEK. */
  z = ntohs (remend->sin_port);
  strcpy (bigbuf_net, inet_ntoa (remend->sin_addr));
  whozis = gethostpoop (bigbuf_net, o_nflag);
  errno = 0;
  x = 0;				/* use as a flag... */
  if (rad)	/* xxx: fix to go down the *list* if we have one? */
    if (memcmp (rad, whozis->iaddrs, sizeof (SA)))
      x = 1;
  if (rp)
    if (z != rp)
      x = 1;
  if (x)					/* guilty! */
    bail("invalid connection to [%s] from %s [%s] %d",
    cp, whozis->name, whozis->addrs[0], (char *)(intptr_t)z, NULL, NULL);


  holler("connect to [%s] from %s [%s] %d",
    cp, whozis->name, whozis->addrs[0], (char *)(intptr_t)z, NULL, NULL);


  return (nnetfd);				/* open! */

dol_tmo:
  errno = ETIMEDOUT;			/* fake it */
dol_err:
  close (nnetfd);
  return (-1);
} /* dolisten */

/* udptest :
   fire a couple of packets at a UDP target port, just to see if it's really
   there.  On BSD kernels, ICMP host/port-unreachable errors get delivered to
   our socket as ECONNREFUSED write errors.  On SV kernels, we lose; we'll have
   to collect and analyze raw ICMP ourselves a la satan's probe_udp_ports
   backend.  Guess where one could swipe the appropriate code from...

   Use the time delay between writes if given, otherwise use the "tcp ping"
   trick for getting the RTT.  [I got that idea from pluvius, and warped it.]
   Return either the original fd, or clean up and return -1. */
int udptest(int fd, IA *where)
{
  register int rr;

  rr = write (fd, bigbuf_in, 1);
  if (rr != 1)
    holler("udptest first write failed?! errno %d", (char *)(intptr_t)errno, NULL, NULL, NULL, NULL, NULL);

  if (o_wait)
    sleep (o_wait);
  else {
/* use the tcp-ping trick: try connecting to a normally refused port, which
   causes us to block for the time that SYN gets there and RST gets back.
   Not completely reliable, but it *does* mostly work. */
    o_udpmode = 0;			/* so doconnect does TCP this time */
/* Set a temporary connect timeout, so packet filtration doesnt cause
   us to hang forever, and hit it */
    o_wait = 5;				/* enough that we'll notice?? */
    rr = doconnect (where, SLEAZE_PORT, 0, 0);
    if (rr > 0)
      close (rr);			/* in case it *did* open */
    o_wait = 0;				/* reset it */
    o_udpmode++;			/* we *are* still doing UDP, right? */
  } /* if o_wait */
  errno = 0;				/* clear from sleep */
  rr = write (fd, bigbuf_in, 1);
  if (rr == 1)				/* if write error, no UDP listener */
    return (fd);
  close (fd);				/* use it or lose it! */
  return (-1);
} /* udptest */


void oprint(int which, char *buf, int n)
{
  int bc;			/* in buffer count */
  int obc;			/* current "global" offset */
  int soc;			/* stage write count */
  register unsigned char * p;	/* main buf ptr; m.b. unsigned here */
  register unsigned char * op;	/* out hexdump ptr */
  register unsigned char * a;	/* out asc-dump ptr */
  register int x;
  register unsigned int y;

  if (! ofd)
    bail("oprint called with no open fd?!", NULL, NULL, NULL, NULL, NULL, NULL);

  if (n == 0)
    return;

  op = stage;
  if (which) {
    *op = '<';
    obc = wrote_out;		/* use the globals! */
  } else {
    *op = '>';
    obc = wrote_net;
  }
  op++;				/* preload "direction" */
  *op = ' ';
  p = (unsigned char *) buf;
  bc = n;
  stage[59] = '#';		/* preload separator */
  stage[60] = ' ';

  while (bc) {			/* for chunk-o-data ... */
    x = 16;
    soc = 78;			/* len of whole formatted line */
    if (bc < x) {
      soc = soc - 16 + bc;	/* fiddle for however much is left */
      x = (bc * 3) + 11;	/* 2 digits + space per, after D & offset */
      op = &stage[x];
      x = 16 - bc;
      while (x) {
	*op++ = ' ';		/* preload filler spaces */
	*op++ = ' ';
	*op++ = ' ';
	x--;
      }
      x = bc;			/* re-fix current linecount */
    } /* if bc < x */

    bc -= x;			/* fix wrt current line size */
    sprintf((char *)&stage[2], "%8.8x ", obc);

    obc += x;			/* fix current offset */
    op = &stage[11];		/* where hex starts */
    a = &stage[61];		/* where ascii starts */

    while (x) {			/* for line of dump, however long ... */
      y = (int)(*p >> 4);	/* hi half */
      *op = hexnibs[y];
      op++;
      y = (int)(*p & 0x0f);	/* lo half */
      *op = hexnibs[y];
      op++;
      *op = ' ';
      op++;
      if ((*p > 31) && (*p < 127))
	*a = *p;		/* printing */
      else
	*a = '.';		/* nonprinting, loose def */
      a++;
      p++;
      x--;
    } /* while x */
    *a = '\n';			/* finish the line */
    x = write (ofd, stage, soc);
    if (x < 0)
      bail("ofd write err", NULL, NULL, NULL, NULL, NULL, NULL);
  } /* while bc */
} /* oprint */

#ifdef TELNET
USHORT o_tn = 0;		/* global -t option */

/* atelnet :
   Answer anything that looks like telnet negotiation with don't/won't.
   This doesn't modify any data buffers, update the global output count,
   or show up in a hexdump -- it just shits into the outgoing stream.
   Idea and codebase from Mudge@l0pht.com. */
void atelnet (buf, size)
  unsigned char * buf;		/* has to be unsigned here! */
  unsigned int size;
{
  static unsigned char obuf [4];  /* tiny thing to build responses into */
  register int x;
  register unsigned char y;
  register unsigned char * p;

  y = 0;
  p = buf;
  x = size;
  while (x > 0) {
    if (*p != 255)			/* IAC? */
      goto notiac;
    obuf[0] = 255;
    p++; x--;
    if ((*p == 251) || (*p == 252))	/* WILL or WONT */
      y = 254;				/* -> DONT */
    if ((*p == 253) || (*p == 254))	/* DO or DONT */
      y = 252;				/* -> WONT */
    if (y) {
      obuf[1] = y;
      p++; x--;
      obuf[2] = *p;			/* copy actual option byte */
      (void) write (netfd, obuf, 3);
/* if one wanted to bump wrote_net or do a hexdump line, here's the place */
      y = 0;
    } /* if y */
notiac:
    p++; x--;
  } /* while x */
} /* atelnet */
#endif /* TELNET */

/* print_chat_message :
   Print message with timestamp and sender label for chat mode */
void print_chat_message(const char *sender_label, const char *color, 
                        const char *msg, int len)
{
  time_t now;
  struct tm *tm_info;
  char timestamp[20];
  int i;
  
  /* Get current time */
  time(&now);
  tm_info = localtime(&now);
  strftime(timestamp, sizeof(timestamp), "%H:%M:%S", tm_info);
  
  /* Print with color and timestamp */
  fprintf(stdout, "%s[%s %s]%s ", color, timestamp, sender_label, COLOR_RESET);
  
  /* Print message, handling line by line */
  for (i = 0; i < len; i++) {
    putchar(msg[i]);
    /* If newline and not last char, add prefix for next line */
    if (msg[i] == '\n' && i < len - 1) {
      fprintf(stdout, "%s[%s %s]%s ", color, timestamp, sender_label, COLOR_RESET);
    }
  }
  
  /* Ensure newline at end if not present */
  if (len > 0 && msg[len-1] != '\n') {
    putchar('\n');
  }
  
  fflush(stdout);
}

/* readwrite :
   handle stdin/stdout/network I/O.  Bwahaha!! -- the select loop from hell.
   In this instance, return what might become our exit status. */
int readwrite(int fd)
{

  register int rr;
  register char * zp;		/* stdin buf ptr */
  register char * np;		/* net-in buf ptr */
  unsigned int rzleft;
  unsigned int rnleft;
  USHORT netretry;		/* net-read retry counter */
  USHORT wretry;		/* net-write sanity counter */
  USHORT wfirst;		/* one-shot flag to skip first net read */

/* if you don't have all this FD_* macro hair in sys/types.h, you'll have to
   either find it or do your own bit-bashing: *ding1 |= (1 << fd), etc... */
  if (fd > FD_SETSIZE) {
    holler("Preposterous fd value %d", (char *)(intptr_t)fd, NULL, NULL, NULL, NULL, NULL);

    return (1);
  }
  FD_SET (fd, ding1);		/* global: the net is open */
  netretry = 2;
  wfirst = 0;
  rzleft = rnleft = 0;
  if (insaved) {
    rzleft = insaved;		/* preload multi-mode fakeouts */
    zp = bigbuf_in;
    wfirst = 1;
    if (Single)			/* if not scanning, this is a one-off first */
      insaved = 0;		/* buffer left over from argv construction, */
    else {
      FD_CLR (0, ding1);	/* OR we've already got our repeat chunk, */
      close (0);		/* so we won't need any more stdin */
    } /* Single */
  } /* insaved */
  if (o_interval)
    sleep (o_interval);		/* pause *before* sending stuff, too */
  errno = 0;			/* clear from sleep, close, whatever */

/* and now the big ol' select shoveling loop ... */
  while (FD_ISSET (fd, ding1)) {	/* i.e. till the *net* closes! */
    wretry = 8200;			/* more than we'll ever hafta write */
    if (wfirst) {			/* any saved stdin buffer? */
      wfirst = 0;			/* clear flag for the duration */
      goto shovel;			/* and go handle it first */
    }
    *ding2 = *ding1;			/* FD_COPY ain't portable... */
/* some systems, notably linux, crap into their select timers on return, so
   we create a expendable copy and give *that* to select.  *Fuck* me ... */
    if (timer1)
      memcpy (timer2, timer1, sizeof (struct timeval));
    rr = select (16, ding2, 0, 0, timer2);	/* here it is, kiddies */
    if (rr < 0) {
	if (errno != EINTR) {		/* might have gotten ^Zed, etc ?*/
	  holler("select fuxored", NULL, NULL, NULL, NULL, NULL, NULL);

	  close (fd);
	  return (1);
	}
    } /* select fuckup */
/* if we have a timeout AND stdin is closed AND we haven't heard anything
   from the net during that time, assume it's dead and close it too. */
    if (rr == 0) {
	if (! FD_ISSET (0, ding1))
	  netretry--;			/* we actually try a coupla times. */
	if (! netretry) {
	  if (o_verbose > 1)		/* normally we don't care */
	    holler("net timeout", NULL, NULL, NULL, NULL, NULL, NULL);

	  close (fd);
	  return (0);			/* not an error! */
	}
    } /* select timeout */
/* xxx: should we check the exception fds too?  The read fds seem to give
   us the right info, and none of the examples I found bothered. */

/* Ding!!  Something arrived, go check all the incoming hoppers, net first */
    if (FD_ISSET (fd, ding2)) {		/* net: ding! */
	/*rr = read (fd, bigbuf_net, BIGSIZ);*/
	rr = farm9crypt_read (fd, bigbuf_net, BIGSIZ);
	if (rr <= 0) {
	  FD_CLR (fd, ding1);		/* net closed, we'll finish up... */
	  rzleft = 0;			/* can't write anymore: broken pipe */
	  /* Print transfer statistics if in file transfer mode */
	  if (!isatty(1) && o_verbose) {
	    fprintf(stderr, "\n[Transfer complete] Received %u bytes\n", wrote_out);
	  }
	} else {
	  rnleft = rr;
	  np = bigbuf_net;
#ifdef TELNET
	  if (o_tn)
	    atelnet (np, rr);		/* fake out telnet stuff */
#endif /* TELNET */
	} /* if rr */
Debug (("got %d from the net, errno %d", rr, errno))
    } /* net:ding */

/* if we're in "slowly" mode there's probably still stuff in the stdin
   buffer, so don't read unless we really need MORE INPUT!  MORE INPUT! */
    if (rzleft)
	goto shovel;

/* okay, suck more stdin */
    if (FD_ISSET (0, ding2)) {		/* stdin: ding! */
	rr = read (0, bigbuf_in, BIGSIZ);
/* Considered making reads here smaller for UDP mode, but 8192-byte
   mobygrams are kinda fun and exercise the reassembler. */
	if (rr <= 0) {			/* at end, or fukt, or ... */
	  FD_CLR (0, ding1);		/* disable and close stdin */
	  close (0);
	  /* In file transfer mode, close connection after stdin EOF */
	  if (!isatty(0) || !pr00gie) {  /* stdin redirected = file transfer */
	    /* Print transfer statistics to stderr in verbose mode */
	    if (o_verbose) {
	      fprintf(stderr, "\n[Transfer complete] Sent %u bytes\n", wrote_net);
	    }
	    /* Give time for data to flush, then close */
	    sleep(1);
	    close(fd);
	    return (0);
	  }
	} else {
	  rzleft = rr;
	  zp = bigbuf_in;
/* special case for multi-mode -- we'll want to send this one buffer to every
   open TCP port or every UDP attempt, so save its size and clean up stdin */
	  if (! Single) {		/* we might be scanning... */
	    insaved = rr;		/* save len */
	    FD_CLR (0, ding1);		/* disable further junk from stdin */
	    close (0);			/* really, I mean it */
	  } /* Single */
	} /* if rr/read */
    } /* stdin:ding */

shovel:
/* now that we've dingdonged all our thingdings, send off the results.
   Geez, why does this look an awful lot like the big loop in "rsh"? ...
   not sure if the order of this matters, but write net -> stdout first. */

/* sanity check.  Works because they're both unsigned... */
    if ((rzleft > 8200) || (rnleft > 8200)) {
	holler("Bogus buffers: %d, %d", (char *)(intptr_t)rzleft, (char *)(intptr_t)rnleft, NULL, NULL, NULL, NULL);

	rzleft = rnleft = 0;
    }
/* net write retries sometimes happen on UDP connections */
    if (! wretry) {			/* is something hung? */
	holler("too many output retries", NULL, NULL, NULL, NULL, NULL, NULL);

	return (1);
    }
    if (rnleft) {
	/* Received from network - print with timestamp only in server chat mode */
	/* Chat mode = listen mode AND both terminals AND no execute mode */
	if (o_listen && !pr00gie && isatty(0) && isatty(1)) {
	  print_chat_message("Remote", COLOR_CYAN, np, rnleft);
	  np += rnleft;
	  wrote_out += rnleft;
	  rnleft = 0;
	} else {
	  /* Client mode, execute mode, or file transfer - write raw output */
	  rr = write (1, np, rnleft);
	  if (rr > 0) {
	    if (o_wfile)
	      oprint (1, np, rr);		/* log the stdout */
	    np += rr;			/* fix up ptrs and whatnot */
	    rnleft -= rr;		/* will get sanity-checked above */
	    wrote_out += rr;		/* global count */
	  }
	}
Debug (("wrote %d to stdout, errno %d", rr, errno))
    } /* rnleft */
    if (rzleft) {
	if (o_interval)			/* in "slowly" mode ?? */
	  rr = findline (zp, rzleft);
	else
	  rr = rzleft;
	
	/* Print local message with timestamp only in server chat mode */
	if (o_listen && !pr00gie && isatty(0) && isatty(1)) {
	  print_chat_message("You", COLOR_GREEN, zp, rr);
	}
	
	/*rr = write (fd, zp, rr);*/	/* one line, or the whole buffer */
	rr = farm9crypt_write (fd, zp, rr);	/* one line, or the whole buffer */
 
	if (rr > 0) {
	  if (o_wfile)
	    oprint (0, zp, rr);		/* log what got sent */
	  zp += rr;
	  rzleft -= rr;
	  wrote_net += rr;		/* global count */
	}
Debug (("wrote %d to net, errno %d", rr, errno))
    } /* rzleft */
    if (o_interval) {			/* cycle between slow lines, or ... */
	sleep (o_interval);
	errno = 0;			/* clear from sleep */
	continue;			/* ...with hairy select loop... */
    }
    if ((rzleft) || (rnleft)) {		/* shovel that shit till they ain't */
	wretry--;			/* none left, and get another load */
	goto shovel;
    }
  } /* while ding1:netfd is open */

/* XXX: maybe want a more graceful shutdown() here, or screw around with
   linger times??  I suspect that I don't need to since I'm always doing
   blocking reads and writes and my own manual "last ditch" efforts to read
   the net again after a timeout.  I haven't seen any screwups yet, but it's
   not like my test network is particularly busy... */
  close (fd);
  return (0);
} /* readwrite */

/* main :
   now we pull it all together... */
int main(int argc, char **argv)
{

#ifndef HAVE_GETOPT
  extern char * optarg;
  extern int optind, optopt;
#endif
  register int x;
  register char *cp;
  HINF * gp;
  HINF * whereto = NULL;
  HINF * wherefrom = NULL;
  IA * ouraddr = NULL;
  IA * themaddr = NULL;
  USHORT o_lport = 0;
  USHORT ourport = 0;
  USHORT loport = 0;		/* for scanning stuff */
  USHORT hiport = 0;
  USHORT curport = 0;
  char * randports = NULL;
  char * crypt_key_f9 = NULL;
  char keystr[32];
  
#ifdef HAVE_BIND
/* can *you* say "cc -yaddayadda netcat.c -lresolv -l44bsd" on SunLOSs? */
/* res_init(); */  /* Not needed on modern systems, causes link errors on macOS */
#endif
/* I was in this barbershop quartet in Skokie IL ... */
/* round up the usual suspects, i.e. malloc up all the stuff we need */
  lclend = (SAI *) Hmalloc (sizeof (SA));
  remend = (SAI *) Hmalloc (sizeof (SA));
  bigbuf_in = Hmalloc (BIGSIZ);
  bigbuf_net = Hmalloc (BIGSIZ);
  ding1 = (fd_set *) Hmalloc (sizeof (fd_set));
  ding2 = (fd_set *) Hmalloc (sizeof (fd_set));
  portpoop = (PINF *) Hmalloc (sizeof (PINF));

  errno = 0;
  gatesptr = 4;
  h_errno = 0;

/* catch a signal or two for cleanup */
  signal (SIGINT, catch);
  signal (SIGQUIT, catch);
  signal (SIGTERM, catch);
/* and suppress others... */
#ifdef SIGURG
  signal (SIGURG, SIG_IGN);
#endif
#ifdef SIGPIPE
  signal (SIGPIPE, SIG_IGN);		/* important! */
#endif

/* if no args given at all, get 'em from stdin, construct an argv, and hand
   anything left over to readwrite(). */
  if (argc == 1) {
    cp = argv[0];
    argv = (char **) Hmalloc (128 * sizeof (char *));	/* XXX: 128? */
    argv[0] = cp;			/* leave old prog name intact */
    cp = Hmalloc (BIGSIZ);
    argv[1] = cp;			/* head of new arg block */
    fprintf (stderr, "Cmd line: ");
    fflush (stderr);		/* I dont care if it's unbuffered or not! */
    insaved = read (0, cp, BIGSIZ);	/* we're gonna fake fgets() here */
    if (insaved <= 0)
      bail("wrong", NULL, NULL, NULL, NULL, NULL, NULL);
    x = findline (cp, insaved);
    if (x)
      insaved -= x;		/* remaining chunk size to be sent */
    if (insaved)		/* which might be zero... */
      memcpy (bigbuf_in, &cp[x], insaved);
    cp = strchr (argv[1], '\n');
    if (cp)
      *cp = '\0';
    cp = strchr (argv[1], '\r');	/* look for ^M too */
    if (cp)
      *cp = '\0';

/* find and stash pointers to remaining new "args" */
    cp = argv[1];
    cp++;				/* skip past first char */
    x = 2;				/* we know argv 0 and 1 already */
    for (; *cp != '\0'; cp++) {
      if (*cp == ' ') {
	*cp = '\0';			/* smash all spaces */
	continue;
      } else {
	if (*(cp-1) == '\0') {
	  argv[x] = cp;
	  x++;
	}
      } /* if space */
    } /* for cp */
    argc = x;
  } /* if no args given */

/* If your shitbox doesn't have getopt, step into the nineties already. */
/* optarg, optind = next-argv-component [i.e. flag arg]; optopt = last-char */
  while ((x = getopt (argc, argv, "ae:g:G:hi:k:lno:p:rs:tuvw:z")) != EOF) {
/* Debug (("in go: x now %c, optarg %x optind %d", x, optarg, optind)) */
    switch (x) {
      case 'a':
	bail("all-A-records NIY", NULL, NULL, NULL, NULL, NULL, NULL);
	o_alla++; break;
#ifdef GAPING_SECURITY_HOLE
      case 'e':				/* prog to exec */
	pr00gie = optarg;
	break;
#endif
      case 'k':
	if (!optarg || strlen(optarg) == 0) {
	  bail("Error: -k requires a non-empty password", NULL, NULL, NULL, NULL, NULL, NULL);
	}
	if (strlen(optarg) < 8) {
	  holler("Warning: Password should be at least 8 characters for security", NULL, NULL, NULL, NULL, NULL, NULL);
	}
	strncpy(keystr, optarg, sizeof(keystr) - 1);
	keystr[sizeof(keystr) - 1] = '\0';
	crypt_key_f9 = keystr;
	/* Initialize with PBKDF2 key derivation */
	if (farm9crypt_init_password(crypt_key_f9, strlen(crypt_key_f9)) != 0) {
	  bail("Encryption initialization failed", NULL, NULL, NULL, NULL, NULL, NULL);
	}
	break;

      case 'G':				/* srcrt gateways pointer val */
	x = atoi (optarg);
	if ((x) && (x == (x & 0x1c)))	/* mask off bits of fukt values */
	  gatesptr = x;
	else
	  bail("invalid hop pointer %d, must be multiple of 4 <= 28", (char *)(intptr_t)x, NULL, NULL, NULL, NULL, NULL);
	break;
      case 'g':				/* srcroute hop[s] */
	if (gatesidx > 8)
	  bail("too many -g hops", NULL, NULL, NULL, NULL, NULL, NULL);
	if (gates == NULL)		/* eat this, Billy-boy */
	  gates = (HINF **) Hmalloc (sizeof (HINF *) * 10);
	gp = gethostpoop (optarg, o_nflag);
	if (gp)
	  gates[gatesidx] = gp;
	gatesidx++;
	break;
      case 'h':
	errno = 0;
#ifdef HAVE_HELP
	helpme();			/* exits by itself */
#else
	bail("no help available, dork -- RTFS", NULL, NULL, NULL, NULL, NULL, NULL);
#endif
      case 'i':				/* line-interval time */
	o_interval = atoi (optarg) & 0xffff;
	if (! o_interval)
	  bail("invalid interval time %s", optarg, NULL, NULL, NULL, NULL, NULL);
	break;
      case 'l':				/* listen mode */
	o_listen++; break;
      case 'n':				/* numeric-only, no DNS lookups */
	o_nflag++; break;
      case 'o':				/* hexdump log */
	stage = (unsigned char *) optarg;
	o_wfile++; break;
      case 'p':				/* local source port */
	o_lport = getportpoop (optarg, 0);
	if (o_lport == 0)
	  bail("invalid local port %s", optarg, NULL, NULL, NULL, NULL, NULL);
	break;
      case 'r':				/* randomize various things */
	o_random++; break;
      case 's':				/* local source address */
/* do a full lookup [since everything else goes through the same mill],
   unless -n was previously specified.  In fact, careful placement of -n can
   be useful, so we'll still pass o_nflag here instead of forcing numeric.  */
	wherefrom = gethostpoop (optarg, o_nflag);
	ouraddr = &wherefrom->iaddrs[0];
	break;
#ifdef TELNET
      case 't':				/* do telnet fakeout */
	o_tn++; break;
#endif /* TELNET */
      case 'u':				/* use UDP */
	o_udpmode++; break;
      case 'v':				/* verbose */
	o_verbose++; break;
      case 'w':				/* wait time */
	o_wait = atoi (optarg);
	if (o_wait <= 0)
	  bail ("invalid wait-time %s", optarg, NULL, NULL, NULL, NULL, NULL);
	timer1 = (struct timeval *) Hmalloc (sizeof (struct timeval));
	timer2 = (struct timeval *) Hmalloc (sizeof (struct timeval));
	timer1->tv_sec = o_wait;	/* we need two.  see readwrite()... */
	break;
      case 'z':				/* little or no data xfer */
	o_zero++;
	break;
      default:
	errno = 0;
	bail ("nc -h for help", NULL, NULL, NULL, NULL, NULL, NULL);
    } /* switch x */
  } /* while getopt */

/* other misc initialization */

/* CRITICAL: Encryption key MUST be provided via -k option */
if (!crypt_key_f9 || farm9crypt_initialized() == 0) {
	fprintf(stderr, "\n");
	fprintf(stderr, "ERROR: Encryption password required!\n");
	fprintf(stderr, "Usage: %s -k <password> [other options]\n\n", argv[0]);
	fprintf(stderr, "Security recommendations:\n");
	fprintf(stderr, "  - Use a strong password (at least 12 characters)\n");
	fprintf(stderr, "  - Mix uppercase, lowercase, numbers, and symbols\n");
	fprintf(stderr, "  - Both endpoints must use the SAME password\n");
	fprintf(stderr, "  - Consider using a password manager\n\n");
	bail("Encryption not initialized - use -k option", NULL, NULL, NULL, NULL, NULL, NULL);
}
  
Debug (("fd_set size %d", sizeof (*ding1)))	/* how big *is* it? */
  FD_SET (0, ding1);			/* stdin *is* initially open */
  if (o_random) {
    SRAND (time (0));
    randports = Hmalloc (65536);	/* big flag array for ports */
  }
#ifdef GAPING_SECURITY_HOLE
  if (pr00gie) {
    close (0);				/* won't need stdin */
    o_wfile = 0;			/* -o with -e is meaningless! */
    ofd = 0;
  }
#endif /* G_S_H */
  if (o_wfile) {
    ofd = open ((const char *)stage, O_WRONLY | O_CREAT | O_TRUNC, 0664);
    if (ofd <= 0)			/* must be > extant 0/1/2 */
      bail("can't open %s", (char *)stage, NULL, NULL, NULL, NULL, NULL);
    stage = (unsigned char *) Hmalloc (100);
  }

/* optind is now index of first non -x arg */
Debug (("after go: x now %c, optarg %x optind %d", x, optarg, optind))
/* Debug (("optind up to %d at host-arg %s", optind, argv[optind])) */
/* gonna only use first addr of host-list, like our IQ was normal; if you wanna
   get fancy with addresses, look up the list yourself and plug 'em in for now.
   unless we finally implement -a, that is. */
  if (argv[optind])
    whereto = gethostpoop (argv[optind], o_nflag);
  if (whereto)
    themaddr = &whereto->iaddrs[0];
  if (themaddr)
    optind++;				/* skip past valid host lookup */
  errno = 0;
  h_errno = 0;

/* Handle listen mode here, and exit afterward.  Only does one connect;
   this is arguably the right thing to do.  A "persistent listen-and-fork"
   mode a la inetd has been thought about, but not implemented.  A tiny
   wrapper script can handle such things... */
  if (o_listen) {
    curport = 0;			/* rem port *can* be zero here... */
    if (argv[optind]) {			/* any rem-port-arg? */
      curport = getportpoop (argv[optind], 0);
      if (curport == 0)			/* if given, demand correctness */
	bail("invalid port %s", argv[optind], NULL, NULL, NULL, NULL, NULL);
    } /* if port-arg */
    netfd = dolisten (themaddr, curport, ouraddr, o_lport);
/* dolisten does its own connect reporting, so we don't holler anything here */
    if (netfd > 0) {
#ifdef GAPING_SECURITY_HOLE
      if (pr00gie) {			/* -e given? */
	/* Create pipes for encrypted communication with child process */
	int pipe_to_child[2], pipe_from_child[2];
	pid_t child_pid;
	
	if (pipe(pipe_to_child) < 0 || pipe(pipe_from_child) < 0)
	  bail("pipe creation failed", NULL, NULL, NULL, NULL, NULL, NULL);
	
	child_pid = fork();
	if (child_pid < 0)
	  bail("fork failed", NULL, NULL, NULL, NULL, NULL, NULL);
	
	if (child_pid == 0) {
	  /* Child process: redirect pipes to stdin/stdout and exec */
	  close(pipe_to_child[1]);    /* close write end of input pipe */
	  close(pipe_from_child[0]);  /* close read end of output pipe */
	  close(netfd);               /* child doesn't need the socket */
	  
	  dup2(pipe_to_child[0], 0);  /* stdin from parent */
	  dup2(pipe_from_child[1], 1); /* stdout to parent */
	  dup2(pipe_from_child[1], 2); /* stderr to parent */
	  
	  close(pipe_to_child[0]);
	  close(pipe_from_child[1]);
	  
	  /* Now exec the program */
	  {
	    register char * p;
	    p = strrchr(pr00gie, '/');
	    if (p)
	      p++;
	    else
	      p = pr00gie;
	    execl(pr00gie, p, NULL);
	    bail("exec %s failed", pr00gie, NULL, NULL, NULL, NULL, NULL);
	  }
	}
	
	/* Parent process: close unused pipe ends and relay data */
	close(pipe_to_child[0]);   /* close read end of input pipe */
	close(pipe_from_child[1]); /* close write end of output pipe */
	
	/* Now relay between network (encrypted) and child (plain) */
	{
	  fd_set readfds;
	  int maxfd = (netfd > pipe_from_child[0]) ? netfd : pipe_from_child[0];
	  int rr;
	  char buf[BIGSIZ];
	  
	  maxfd++;
	  while (1) {
	    FD_ZERO(&readfds);
	    FD_SET(netfd, &readfds);
	    FD_SET(pipe_from_child[0], &readfds);
	    
	    rr = select(maxfd, &readfds, NULL, NULL, NULL);
	    if (rr < 0) {
	      if (errno == EINTR) continue;
	      break;
	    }
	    
	    /* Data from network (encrypted) -> decrypt and send to child */
	    if (FD_ISSET(netfd, &readfds)) {
	      rr = farm9crypt_read(netfd, buf, BIGSIZ);
	      if (rr <= 0) break;
	      if (write(pipe_to_child[1], buf, rr) != rr) break;
	    }
	    
	    /* Data from child (plain) -> encrypt and send to network */
	    if (FD_ISSET(pipe_from_child[0], &readfds)) {
	      rr = read(pipe_from_child[0], buf, BIGSIZ);
	      if (rr <= 0) break;
	      if (farm9crypt_write(netfd, buf, rr) != rr) break;
	    }
	  }
	  
	  close(pipe_to_child[1]);
	  close(pipe_from_child[0]);
	  close(netfd);
	  exit(0);
	}
      }
#endif /* GAPING_SECURITY_HOLE */
      x = readwrite (netfd);		/* it even works with UDP! */
      if (o_verbose > 1)		/* normally we don't care */
	holler (wrote_txt, (char *)(intptr_t)wrote_net, (char *)(intptr_t)wrote_out, NULL, NULL, NULL, NULL);
      exit (x);				/* "pack out yer trash" */
    } else /* if no netfd */
      bail ("no connection", NULL, NULL, NULL, NULL, NULL, NULL);
  } /* o_listen */

/* fall thru to outbound connects.  Now we're more picky about args... */
  if (! themaddr)
    bail ("no destination", NULL, NULL, NULL, NULL, NULL, NULL);
  if (argv[optind] == NULL)
    bail ("no port[s] to connect to", NULL, NULL, NULL, NULL, NULL, NULL);
  if (argv[optind + 1])		/* look ahead: any more port args given? */
    Single = 0;				/* multi-mode, case A */
  ourport = o_lport;			/* which can be 0 */

  while (argv[optind]) {
    hiport = loport = 0;
    cp = strchr (argv[optind], '-');	/* nn-mm range? */
    if (cp) {
      *cp = '\0';
      cp++;
      hiport = getportpoop (cp, 0);
      if (hiport == 0)
	bail ("invalid port %s", cp, NULL, NULL, NULL, NULL, NULL);
    } /* if found a dash */
    loport = getportpoop (argv[optind], 0);
    if (loport == 0)
      bail ("invalid port %s", argv[optind], NULL, NULL, NULL, NULL, NULL);
    if (hiport > loport) {		/* was it genuinely a range? */
      Single = 0;			/* multi-mode, case B */
      curport = hiport;			/* start high by default */
      if (o_random) {			/* maybe populate the random array */
	loadports (randports, loport, hiport);
	curport = nextport (randports);
      }
    } else			/* not a range, including args like "25-25" */
      curport = loport;
Debug (("Single %d, curport %d", Single, curport))

/* Now start connecting to these things.  curport is already preloaded. */
    while (loport <= curport) {
      if ((! o_lport) && (o_random)) {	/* -p overrides random local-port */
	ourport = (RAND() & 0xffff);	/* random local-bind -- well above */
	if (ourport < 8192)		/* resv and any likely listeners??? */
	  ourport += 8192;		/* if it *still* conflicts, use -s. */
      }
      curport = getportpoop (NULL, curport);
      netfd = doconnect (themaddr, curport, ouraddr, ourport);
Debug (("netfd %d from port %d to port %d", netfd, ourport, curport))
      if (netfd > 0)
	if (o_zero && o_udpmode)	/* if UDP scanning... */
	  netfd = udptest (netfd, themaddr);
      if (netfd > 0) {			/* Yow, are we OPEN YET?! */
	x = 0;				/* pre-exit status */
	holler ("%s [%s] %d (%s) open",
	  whereto->name, whereto->addrs[0], (char *)(intptr_t)curport, portpoop->name, NULL, NULL);
#ifdef GAPING_SECURITY_HOLE
	if (pr00gie)			/* exec is valid for outbound, too */
	  doexec (netfd);
#endif /* GAPING_SECURITY_HOLE */
	if (! o_zero)
	  x = readwrite (netfd);	/* go shovel shit */
      } else { /* no netfd... */
	x = 1;				/* preload exit status for later */
/* if we're scanning at a "one -v" verbosity level, don't print refusals.
   Give it another -v if you want to see everything. */
	if ((Single || (o_verbose > 1)) || (errno != ECONNREFUSED))
	  holler ("%s [%s] %d (%s)",
	    whereto->name, whereto->addrs[0], (char *)(intptr_t)curport, portpoop->name, NULL, NULL);
      } /* if netfd */
      close (netfd);			/* just in case we didn't already */
      if (o_interval)
	sleep (o_interval);		/* if -i, delay between ports too */
      if (o_random)
	curport = nextport (randports);
      else
	curport--;			/* just decrement... */
    } /* while curport within current range */
    optind++;
  } /* while remaining port-args -- end of big argv-ports loop*/

  errno = 0;
  if (o_verbose > 1)		/* normally we don't care */
    holler (wrote_txt, (char *)(intptr_t)wrote_net, (char *)(intptr_t)wrote_out, NULL, NULL, NULL, NULL);
  
  /* Clean up encryption resources */
  farm9crypt_cleanup();
  
  if (Single)
    exit (x);			/* give us status on one connection */
  exit (0);			/* otherwise, we're just done */
} /* main */

#ifdef HAVE_HELP		/* unless we wanna be *really* cryptic */
/* helpme :
   the obvious */
void helpme(void)
{
  o_verbose = 1;
  holler ("[v1.10]\\n\\\nconnect to somewhere:\tnc [-options] hostname port[s] [ports] ... \\n\\\nlisten for inbound:\tnc -l -p port [-options] [hostname] [port]\\n\\\noptions:", NULL, NULL, NULL, NULL, NULL, NULL);
/* sigh, this necessarily gets messy.  And the trailing \ characters may be
   interpreted oddly by some compilers, generating or not generating extra
   newlines as they bloody please.  u-fix... */
#ifdef GAPING_SECURITY_HOLE	/* needs to be separate holler() */
  holler ("\
	-e prog			program to exec after connect [dangerous!!]", NULL, NULL, NULL, NULL, NULL, NULL);
#endif
  holler ("\
	-g gateway		source-routing hop point[s], up to 8\n\
	-G num			source-routing pointer: 4, 8, 12, ...\n\
	-h			this cruft\n\
	-k password		[REQUIRED] encryption password (min 8 chars)\n\
	-i secs			delay interval for lines sent, ports scanned\n\
	-l			listen mode, for inbound connects\n\
	-n			numeric-only IP addresses, no DNS\n\
	-o file			hex dump of traffic\n\
	-p port			local port number\n\
	-r			randomize local and remote ports\n\
	-s addr			local source address", NULL, NULL, NULL, NULL, NULL, NULL);
#ifdef TELNET
  holler ("\
	-t			answer TELNET negotiation", NULL, NULL, NULL, NULL, NULL, NULL);
#endif
  holler ("\
	-u			UDP mode\n\
	-v			verbose [use twice to be more verbose]\n\
	-w secs			timeout for connects and final net reads\n\
	-z			zero-I/O mode [used for scanning]", NULL, NULL, NULL, NULL, NULL, NULL);
  bail("port numbers can be individual or ranges: lo-hi [inclusive]", NULL, NULL, NULL, NULL, NULL, NULL);

} /* helpme */
#endif /* HAVE_HELP */

/* None genuine without this seal!  _H*/
