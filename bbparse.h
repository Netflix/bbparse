#ifndef __test_dump_lib_h__
#define	__test_dump_lib_h__	1
/*-
 * Copyright (c) 2017
 *	Netflix Inc.
 *      All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
#define TCP_LOG_VER_8		(8)	/* Previous version V9 adds 2 new fids */
#define TCP_LOG_VER_7		(7)	/* Version before that sacknewdata becomes flex3 */

/*
 * This holds the Version 8 type data for
 * the conversion routine within the library
 * bbparse.a.
 */
struct tcp_log_buffer_v8
{
	/* Event basics */
	struct timeval	tlb_tv;		/* Timestamp of trace */
	uint32_t	tlb_ticks;	/* Timestamp of trace */
	uint32_t	tlb_sn;		/* Serial number */
	uint8_t		tlb_stackid;	/* Stack ID */
	uint8_t		tlb_eventid;	/* Event ID */
	uint16_t	tlb_eventflags;	/* Flags for the record */
	int		tlb_errno;	/* Event error (if any) */

	/* Internal session state */
	struct tcp_log_sockbuf tlb_rxbuf; /* Receive buffer */
	struct tcp_log_sockbuf tlb_txbuf; /* Send buffer */

	int		tlb_state;	/* TCPCB t_state */
	uint32_t	tlb_starttime;	/* TCPCB t_starttime */
	uint32_t	tlb_iss;	/* TCPCB iss */
	uint32_t	tlb_flags;	/* TCPCB flags */
	uint32_t	tlb_snd_una;	/* TCPCB snd_una */
	uint32_t	tlb_snd_max;	/* TCPCB snd_max */
	uint32_t	tlb_snd_cwnd;	/* TCPCB snd_cwnd */
	uint32_t	tlb_snd_nxt;	/* TCPCB snd_nxt */
	uint32_t	tlb_snd_recover;/* TCPCB snd_recover */
	uint32_t	tlb_snd_wnd;	/* TCPCB snd_wnd */
	uint32_t	tlb_snd_ssthresh; /* TCPCB snd_ssthresh */
	uint32_t	tlb_srtt;	/* TCPCB t_srtt */
	uint32_t	tlb_rttvar;	/* TCPCB t_rttvar */
	uint32_t	tlb_rcv_up;	/* TCPCB rcv_up */
	uint32_t	tlb_rcv_adv;	/* TCPCB rcv_adv */
	uint32_t	tlb_rcv_nxt;	/* TCPCB rcv_nxt */
	uint32_t	tlb_flex3;	/* Formerly tlb_sack_newdata */
	uint32_t	tlb_rcv_wnd;	/* TCPCB rcv_wnd */
	uint32_t	tlb_dupacks;	/* TCPCB t_dupacks */
	int		tlb_segqlen;	/* TCPCB segqlen */
	int		tlb_snd_numholes; /* TCPCB snd_numholes */
	uint32_t	tlb_flex1;	/* Event specific information */
	uint32_t	tlb_flex2;	/* Event specific information */
	uint8_t		tlb_snd_scale:4, /* TCPCB snd_scale */
			tlb_rcv_scale:4; /* TCPCB rcv_scale */
	uint8_t		_pad[3];	/* Padding */
	/* Per-stack info */
	union tcp_log_stackspecific tlb_stackinfo;

	/* The packet */
	uint32_t	tlb_len;	/* The packet's data length */
	struct tcphdr	tlb_th;		/* The TCP header */
	uint8_t		tlb_opts[TCP_MAXOLEN]; /* The TCP options */

	/* Verbose information (optional) */
	struct tcp_log_verbose tlb_verbose[0];
} ALIGN_TCP_LOG;

int bbr_get_next(void *, const struct tcp_log_buffer **,
    const struct tcphdr **) __attribute__((nonnull));
const char *bbr_get_stackname(void * __attribute__((nonnull)), uint8_t)
    __attribute__((returns_nonnull));
const struct tcp_log_header *bbr_get_tlh(void * __attribute__((nonnull)));
void *bbr_init_fd(int, int);
void *bbr_init_file(const char * __attribute__((nonnull)), int);
void bbr_fini(void * __attribute__((nonnull)));
int bbr_convert(void *ctxp, const struct tcp_log_buffer *, struct tcp_log_buffer *);
#endif
