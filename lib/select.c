/*
   mtr  --  a network diagnostic tool
   Copyright (C) 1997,1998  Matt Kimball

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License version 2 as 
   published by the Free Software Foundation.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
   */

#include "config.h"

#include <sys/types.h>
#include <sys/time.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/select.h>
#include <string.h>
#include <math.h>
#include <errno.h>

#include "utils.h"
#include "net.h"
/*
extern int MaxPing;
extern int ForceMaxPing;
extern float WaitTime;
extern int mtrtype;
*/

static struct timeval intervaltime;


#define GRACETIME (5 * 1000*1000)

void select_loop(struct nettask *t, int MaxPing,
		int ForceMaxPing, float WaitTime, int mtrtype) {
	fd_set readfd;
	fd_set writefd;
	int anyset = 0;
	int maxfd = 0;
	int netfd;
	int NumPing = 0;
	struct timeval lasttime, thistime, selecttime;
	struct timeval startgrace;
	int dt;
	int rv; 
	int graceperiod = 0;

	memset(&startgrace, 0, sizeof(startgrace));

	gettimeofday(&lasttime, NULL);

	while(1) {
		dt = calc_deltatime(t, WaitTime);
		intervaltime.tv_sec  = dt / 1000000;
		intervaltime.tv_usec = dt % 1000000;

		FD_ZERO(&readfd);
		FD_ZERO(&writefd);

		maxfd = 0;

		netfd = net_waitfd(t);
		FD_SET(netfd, &readfd);
		if(netfd >= maxfd) maxfd = netfd + 1;

		if (mtrtype == IPPROTO_TCP)
			net_add_fds(t, &writefd, &maxfd);

		do {
			if(anyset) {
				/* Set timeout to 0.1s.
				 * While this is almost instantaneous for human operators,
				 * it's slow enough for computers to go do something else;
				 * this prevents mtr from hogging 100% CPU time on one core.
				 */
				selecttime.tv_sec = 0;
				selecttime.tv_usec = 0; 

				rv = select(maxfd, (void *)&readfd, &writefd, NULL, &selecttime);

			} else {

				gettimeofday(&thistime, NULL);

				if(thistime.tv_sec > lasttime.tv_sec + intervaltime.tv_sec ||
						(thistime.tv_sec == lasttime.tv_sec + intervaltime.tv_sec &&
						 thistime.tv_usec >= lasttime.tv_usec + intervaltime.tv_usec)) {
					lasttime = thistime;

					if (!graceperiod) {
						if (NumPing >= MaxPing) {
							graceperiod = 1;
							startgrace = thistime;
						}

						/* do not send out batch when we've already initiated grace period */
						if (!graceperiod && net_send_batch(t))
							NumPing++;
					}
				}

				if (graceperiod) {
					dt = (thistime.tv_usec - startgrace.tv_usec) +
						1000000 * (thistime.tv_sec - startgrace.tv_sec);
					if (dt > GRACETIME)
						return;
				}

				selecttime.tv_usec = (thistime.tv_usec - lasttime.tv_usec);
				selecttime.tv_sec = (thistime.tv_sec - lasttime.tv_sec);
				if (selecttime.tv_usec < 0) {
					--selecttime.tv_sec;
					selecttime.tv_usec += 1000000;
				}
				selecttime.tv_usec = intervaltime.tv_usec - selecttime.tv_usec;
				selecttime.tv_sec = intervaltime.tv_sec - selecttime.tv_sec;
				if (selecttime.tv_usec < 0) {
					--selecttime.tv_sec;
					selecttime.tv_usec += 1000000;
				}

				rv = select(maxfd, (void *)&readfd, NULL, NULL, &selecttime);
			}
		} while ((rv < 0) && (errno == EINTR));

		if (rv < 0) {
			perror ("Select failed");
			exit (1);
		}
		anyset = 0;

		/*  Have we got new packets back?  */
		if(FD_ISSET(netfd, &readfd)) {
			net_process_return(t);
			anyset = 1;
		}

		/*  Has a key been pressed?  */
		if(FD_ISSET(0, &readfd)) {
			anyset = 1;
		}

		/* Check for activity on open sockets */
		if (mtrtype == IPPROTO_TCP)
			net_process_fds(t, &writefd);
	}
	return;
}

