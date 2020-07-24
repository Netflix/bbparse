/*-
 * Copyright (c) 2017-20
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
#include <sys/param.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <dev/tcp_log/tcp_log_dev.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/tcp_log_buf.h>
#include <pcap/pcap.h>
#include <assert.h>
#include <bitstring.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <lzma.h>

#include "bbparse.h"

#define	LCL_IP	htonl(0x0a000001)
#define	RMT_IP	htonl(0x0a000002)

/* PCAP-NG defines */
#define	MAGIC_NG	0x1A2B3C4D
#define	MAJOR_NG	1
#define	MINOR_NG	0

#define	BT_IDB		0x00000001
#define	BT_EPB		0x00000006
#define	BT_SHB		0x0A0D0D0A
#define	BT_CB_COPY	0x00000BAD
#define	BT_CB_NOCOPY	0x40000BAD

#define	OPT_ENDOFOPT		0
#define	OPT_COMMENT		1
#define	OPT_CUST_BIN_COPY	2989
#define	OPT_CUST_BIN_NOCOPY	19373

enum netflix_opt_types {
	NFLX_OPT_VERSION=1,
	NFLX_OPT_TCPINFO,
	NFLX_OPT_TCPVERBOSE,
	NFLX_OPT_DUMPINFO,
	NFLX_OPT_DUMPTIME,
	NFLX_OPT_STACKNAME,
};

enum netflix_block_types {
	NFLX_EVENT_BLOCK=1,
	NFLX_SKIPPED_BLOCK,
};

#define NFLX_PEN        10949

struct private_context {
	int		pc_fd;
	void		*pc_base;
	size_t		pc_maplen;
	uint32_t	*pc_cur, *pc_end;
	struct tcp_log_header *pc_tlh;
	struct tcp_log_buffer *pc_tlb;
	struct tcphdr	*pc_th;
	struct tcp_log_buffer *pc_alignedtlb;
	int		pc_alignedtlblen;
	char		*pc_stacknames[256];
	bool		pc_stacknames_initd;
	bool		pc_tlh_allocd;
	bool		pc_interactive;
	bool		pc_fatalerr;
};

/*
 * Warning/error functions.
 *
 * Use bbr_err/bbr_warn as replacements for err()/warn().
 * Use fatal_error/warning when you want to display a message without
 * the automatic errno expansion.
 */
static void fatal_error(struct private_context *ctx, const char *msg, ...)
    __attribute__((format (printf, 2, 3)));

static void warning(struct private_context *ctx, const char *msg, ...)
    __attribute__((format (printf, 2, 3)));

#define	bbr_err(ctx, fmt, ...)						\
do {									\
	if (ctx->pc_interactive)					\
		err(1, fmt, ##__VA_ARGS__);				\
	else								\
		ctx->pc_fatalerr = true;				\
} while (0)

#define bbr_warn(ctx, fmt, ...)						\
do {									\
	if (ctx->pc_interactive)					\
		warn(fmt, ##__VA_ARGS__);				\
} while (0)

static void
fatal_error(struct private_context *ctx, const char *msg, ...)
{
	va_list ap;
	char buf[1024] = "Error: ";
	int string_size;

	if (ctx->pc_interactive) {
		/* Create a local copy of the message so we can modify it. */
		string_size = strlcpy(buf, msg, 1023);
		if (string_size > 1022)
			string_size = 1022;
		buf[string_size++] = '\n';
		buf[string_size] = '\0';

		va_start(ap, msg);
		vfprintf(stderr, buf, ap);
		va_end(ap);
		exit(1);
	}
	ctx->pc_fatalerr = true;
}

static void
warning(struct private_context *ctx, const char *msg, ...)
{
	va_list ap;
	char buf[1024] = "Warning: ";
	int string_size;

	if (ctx->pc_interactive) {
		/* Create a local copy of the message so we can modify it. */
		string_size = strlcat(buf, msg, 1023);
		if (string_size > 1022)
			string_size = 1022;
		buf[string_size++] = '\n';
		buf[string_size] = '\0';

		va_start(ap, msg);
		vfprintf(stderr, buf, ap);
		va_end(ap);
	}
}

static void
do_nflx_opt(struct private_context *ctx, uint32_t *buf, int optlen)
{
	size_t alignment;
	char *stackname;
	void *ptr;
	int alloclen, stackid;

	/*
	 * The option length must be at least 1 32-bit word to handle the
	 * netflix type.
	 */
	assert(optlen >= 4);
	optlen -= 4;

	/* Check the Netflix type */
	switch (*buf) {
	case NFLX_OPT_TCPINFO:
		/*
		 * Cast through (void *) to overcome compiler alignment check.
		 * Instead, conduct a run-time check. If the input structure
		 * meets alignment constraints, use it in place. Otherwise,
		 * copy the TLB to our private context and use an aligned
		 * structure there.
		 */
		ctx->pc_tlb = (void *)(buf + 1);
		alignment = __alignof__(struct tcp_log_buffer);
		if ((uintptr_t)ctx->pc_tlb % (uintptr_t)alignment == 0)
			break;

		/* Always try to allocate along alignment boundaries. */
		alloclen = roundup2(optlen, alignment);

		/* Can we reuse the last aligned allocation? */
		if (ctx->pc_alignedtlblen < alloclen) {
			free(ctx->pc_alignedtlb);
			ctx->pc_alignedtlb = aligned_alloc(alignment, alloclen);
			if (ctx->pc_alignedtlb == NULL) {
				bbr_err(ctx, "Error allocating aligned buffer "
				    "for (struct tcp_log_buffer)");
				ctx->pc_tlb = NULL;
				break;
			}
			ctx->pc_alignedtlblen = alloclen;
		}
		memcpy(ctx->pc_alignedtlb, ctx->pc_tlb, optlen);
		ctx->pc_tlb = ctx->pc_alignedtlb;
		break;
	case NFLX_OPT_STACKNAME:
		/*
		 * Format is 1-byte ID and variable-length string. The
		 * string may not be NULL-terminated, so we don't count on
		 * this.
		 */
		assert(optlen >= 2);
		buf++;
		stackid = *(uint8_t *)buf;
		stackname = ((char *)buf) + 1;
		ctx->pc_stacknames[stackid] = malloc(optlen);
		if (ctx->pc_stacknames[stackid] == NULL) {
			bbr_err(ctx, "Error allocating buffer for stack name");
			break;
		}
		optlen--;
		memcpy(ctx->pc_stacknames[stackid], stackname, optlen);
		ctx->pc_stacknames[stackid][optlen] = '\0';
		break;
	case NFLX_OPT_DUMPINFO:
		/*
		 * See if we need to allocate a header locally due to
		 * alignment constraints. The cast through (void *) lets
		 * us do this as a run-time, rather than compile-time,
		 * check.
		 */
		ptr = (void *)(buf + 1);
		alignment = __alignof__(struct tcp_log_header);
		if (optlen < (int)sizeof(struct tcp_log_header)) {
			/* Option isn't big enough. Use NULL. */
			ptr = NULL;
		}
		if ((uintptr_t)ptr % (uintptr_t)alignment == 0) {
			/*
			 * We can use the pointer in place. Free the old
			 * pointer, if we allocated it.
			 */
			if (ctx->pc_tlh_allocd) {
				free(ctx->pc_tlh);
				ctx->pc_tlh_allocd = false;
			}
			ctx->pc_tlh = ptr;
			break;
		}

		/* We can reuse an aligned buffer, if one is available. */
		if (!ctx->pc_tlh_allocd) {
			ctx->pc_tlh = aligned_alloc(alignment,
			    roundup2(sizeof(struct tcp_log_header), alignment));
			if (ctx->pc_tlh == NULL)
				break;
			ctx->pc_tlh_allocd = true;
		}
		memcpy(ctx->pc_tlh, ptr, sizeof(struct tcp_log_header));
		break;
	}
}

static void
do_opts(struct private_context *ctx, uint32_t *buf, uint32_t len)
{
	uint16_t *opt;
	int optlen;

	assert(len % 4 == 0);
	while (len >= 4) {
		opt = (uint16_t *)buf;
		optlen = *(opt + 1);
		buf++;
		len -= 4;
		assert((uint32_t)optlen <= len);
		switch (*opt) {
		case OPT_ENDOFOPT:
			return;
		case OPT_CUST_BIN_COPY:
		case OPT_CUST_BIN_NOCOPY:
			if (optlen < 4)
				break;
			/* Check PEN */
			if (*(buf) != NFLX_PEN)
				break;
			/* Decode the data */
			do_nflx_opt(ctx, buf + 1, optlen - 4);
			break;
		}
		/* Round length up to 4-byte boundary. */
		if (optlen & 0x3)
			optlen += 4 - (optlen & 0x3);
		assert(optlen > 0);
		/* Increment through the option. */
		buf += (optlen / 4);
		/* Decrement len. */
		len -= optlen;
	}
	assert(len == 0);
}

static void
cb(struct private_context *ctx, uint32_t len)
{
	uint32_t *buf;

	buf = ctx->pc_cur + 2;

	/* Check the length. */
	if (len < 8)
		return;
	len -= 8;

	/* Check the PEN. */
	if (*(buf++) != NFLX_PEN)
		return;

	/* Check the type. */
	switch (*(buf++)) {
	case NFLX_EVENT_BLOCK: 
		do_opts(ctx, buf, len);
		break;
	case NFLX_SKIPPED_BLOCK:
		if (len != 4)
			return;
		printf("%u events lost during capture.\n", *buf);
		break;
	}
}

static struct tcphdr *
find_tcp_header(uint32_t *buf, uint32_t len)
{

	/*
	 * Assumptions:
	 * 1. Null header.
	 * 2. Minimal IPv4/IPv6 header.
	 *
	 * These assumptions should be true with our current PCAPNG files.
	 */
	switch (*buf) {
	case PF_INET:
		if (len > 24)
			return ((struct tcphdr *)(buf + 6));
	case PF_INET6:
		if (len > 44)
			return ((struct tcphdr *)(buf + 11));
	}
	return NULL;
}

static void
epb(struct private_context *ctx, uint32_t len)
{
	uint32_t *buf;
	uint32_t caplen;

	buf = ctx->pc_cur + 2;

	/* We need 20 bytes for the fixed fields. */
	if (len < 20)
		return;

	/* Get the caplen and round up to a 4-byte field. */
	caplen = *(buf + 3);
	caplen = roundup2(caplen, 4);

	/* Validate length. */
	if (caplen > (len - 20))
		return;

	/* Skip fixed fields. */
	buf += 5;
	len -= 20;

	/* Find the header. */
	ctx->pc_th = find_tcp_header(buf, len);
	buf += caplen / 4;
	len -= caplen;

	/* If we have any space left, process the options. */
	if (len > 0)
		do_opts(ctx, buf, len);
}

static void
shb(struct private_context *ctx, uint32_t len)
{
	int i;

	/*
	 * The caller subtracts the length of the type and two length
	 * fields. What is left of the fixed SHB is 16 bytes.
	 */
	if (len < 16) {
		fatal_error(ctx,
		    "SHB is only %u bytes, must be at least 28 bytes.",
		    len + 12);
		return;
	}
	len -= 16;

	/*
	 * If we already initialized the stacknames, free the previous
	 * mappings.
	 */
	if (ctx->pc_stacknames_initd) {
		for (i = 0; i < 256; i++) {
			if (ctx->pc_stacknames[i] != NULL) {
				free(ctx->pc_stacknames[i]);
				ctx->pc_stacknames[i] = NULL;
			}
		}
	} else {
		memset(ctx->pc_stacknames, 0, sizeof(ctx->pc_stacknames));
		ctx->pc_stacknames_initd = true;
	}
	/* Parse options -- the real thing about which we care. */
	if (len)
		do_opts(ctx, ctx->pc_cur + 6, len);
}

int
bbr_get_next(void *ctxp, const struct tcp_log_buffer **tlb,
    const struct tcphdr **th)
{ 
	struct private_context *ctx;
	uint32_t len, type;

	ctx = (struct private_context *)ctxp;
	ctx->pc_tlb = NULL;

	while (!ctx->pc_fatalerr && ctx->pc_cur < ctx->pc_end) {
		ctx->pc_th = NULL;

		/* Get the type and length. */
		type = *ctx->pc_cur;
		len = *(ctx->pc_cur + 1);

		/* Validate length. */
		if (len < 12 || (len & 0x3) ||
		    ctx->pc_cur + (len / 4) > ctx->pc_end) {
			fatal_error(ctx, "Invalid length %u for block", len);
			break;
		}

		/* Do the right thing with each type. */
		switch (type) {
		case BT_EPB:
			epb(ctx, len - 12);
			break;
		case BT_CB_COPY:
		case BT_CB_NOCOPY:
			/*
			 * Skip the type and length. The length is reduced by
			 * 12 (type + length + length field at end of block).
			 */
			cb(ctx, len - 12);
			break;
		case BT_SHB:
			shb(ctx, len - 12);
			break;
		}

		/* Move to next block. */
		ctx->pc_cur += (len / 4);

		/* Do we have something to return? If so, do it now. */
		if (!ctx->pc_fatalerr && ctx->pc_tlb != NULL) {
			*tlb = ctx->pc_tlb;
			*th = ctx->pc_th;
			return (0);
		}
	}

	/* We reached the end of the file or had an error. */
	return (ctx->pc_fatalerr ? -1 : 1);
}

const char *
bbr_get_stackname(void *ctxp, uint8_t stackid)
{
	struct private_context *ctx;

	ctx = (struct private_context *)ctxp;
	if (ctx->pc_stacknames[stackid] != NULL)
		return (ctx->pc_stacknames[stackid]);
	return ("unknown");
}

const struct tcp_log_header *
bbr_get_tlh(void *ctxp)
{
	struct private_context *ctx;

	ctx = (struct private_context *)ctxp;

	return (ctx->pc_tlh);
}

static void
bbr_init_xzfile(struct private_context *ctx)
{
	void *outptr;
	caddr_t next;
	size_t increment, outmaplen;
	lzma_stream lzma_strm = LZMA_STREAM_INIT;
	lzma_ret lzmarv;

	/* Set up the decoding context. */
	if (lzma_auto_decoder(&lzma_strm, UINT64_MAX, 0) != LZMA_OK) {
		fatal_error(ctx,
		    "Error when preparing XZ context to expand file");
		return;
	}

	/*
	 * Use the input file already mapped into memory. For output, start
	 * by allocating twice the size of the file.
	 */
	outmaplen = roundup2(ctx->pc_maplen, 4096) * 2;
	outptr = mmap(0, outmaplen, PROT_READ | PROT_WRITE,
	    MAP_ANON | MAP_PRIVATE, -1, 0);
	if (outptr == MAP_FAILED) {
		fatal_error(ctx,
		    "Error mapping %zu bytes for XZ buffer", outmaplen);
		goto done;
	}
	next = (caddr_t)outptr + outmaplen;

	lzma_strm.next_in = ctx->pc_base;
	lzma_strm.avail_in = ctx->pc_maplen;
	lzma_strm.next_out = outptr;
	lzma_strm.avail_out = outmaplen;
	increment = roundup2(ctx->pc_maplen, 4096);

	lzmarv = LZMA_OK;
	do {
		/* Add more space, if needed. */
		if (lzma_strm.avail_out == 0) {
			/*
			 * Try to expand the current space. If that fails,
			 * allocate a new block and copy over the existing
			 * state.
			 */
			if (mmap(next, increment, PROT_READ | PROT_WRITE,
			    MAP_ANON | MAP_PRIVATE | MAP_FIXED | MAP_EXCL,
			    -1, 0) == next) {
				next += increment;
				outmaplen += increment;
			} else {
				void *newoutptr;

				newoutptr = mmap(0, outmaplen + increment,
				    PROT_READ | PROT_WRITE,
				    MAP_ANON | MAP_PRIVATE, -1, 0);
				if (newoutptr == MAP_FAILED)
					fatal_error(ctx, "Error mapping %zu "
					    "bytes for expanded XZ buffer",
					    outmaplen + increment);
				else
					memcpy(newoutptr, outptr, outmaplen);
				if (munmap(outptr, outmaplen)) {
					bbr_warn(ctx, "Error unmapping "
					    "temporary buffer for XZ expansion");
					/*
					 * In the non-interactive
					 * case, this needs to be
					 * fatal. It almost certainly
					 * indicates a bug, and could
					 * lead to a big memory leak
					 * if not corrected.
					 */
					if (!ctx->pc_interactive)
						abort();
				}
				/*
				 * If there's been a fatal error, we
				 * leave things in this state:
				 *
				 * The input is still mapped at ctx->pc_base.
				 * The output has been freed.
				 * The temporary XZ data needs to be freed
				 * with lzma_end().
				 *
				 * Going to "done" should lead us through a
				 * code path where we unmap ctx->pc_base and
				 * call lzma_end() to free temporary memory
				 * allocated for decompression.
				 */
				if (ctx->pc_fatalerr)
					goto done;
				outptr = newoutptr;
				lzma_strm.next_out = (uint8_t *)outptr + outmaplen;
				outmaplen += increment;
				next = (caddr_t)outptr + outmaplen;
			}
			lzma_strm.avail_out = increment;
		} else if (lzmarv == LZMA_BUF_ERROR) {
			fatal_error(ctx, "Error decoding XZ file with "
			    "blackbox records: corrupted file?");
			break;
		}
		lzmarv = lzma_code(&lzma_strm, LZMA_FINISH);
	} while (lzmarv == LZMA_OK || lzmarv == LZMA_BUF_ERROR);
	if (lzmarv != LZMA_STREAM_END)
		fatal_error(ctx, "Unknown error decoding blackbox records "
		    "from XZ file");

	/*
	 * We may have seen a success or failure at this
	 * point. However, we can act the same way either way: Unmap
	 * the input file and record the memory we mapped to hold the
	 * expanded file. Also, record the size of the data we
	 * expanded.
	 */
	if (munmap(ctx->pc_base, ctx->pc_maplen)) {
		bbr_warn(ctx, "Error unmapping original XZ-compressed "
		    "black box file");
		/* See above for why we abort here. */
		if (!ctx->pc_interactive)
			abort();
	}
	ctx->pc_base = outptr;
	ctx->pc_maplen = outmaplen;
	ctx->pc_cur = ctx->pc_base;
	ctx->pc_end = ctx->pc_cur + (lzma_strm.total_out / 4);

	/* Do/redo file size checks. */
	if (lzma_strm.total_out & 0x3)
		warning(ctx, "file may have been truncated.");
	if (lzma_strm.total_out < 12)
		fatal_error(ctx, "File length (%ju) is less than the minimum "
		    "length of a block", (uintmax_t)lzma_strm.total_out);

done:
	/* Clean up the XZ state. */
	lzma_end(&lzma_strm);
}

void *
bbr_init_fd(int fd, int interactive)
{
	struct stat sb;
	struct private_context *ctx;
	uint32_t len, type;
	const char xz_magic[6] = { 0xFD, '7', 'z', 'X', 'Z', 0x00 };

	ctx = malloc(sizeof(struct private_context));
	if (ctx == NULL) {
		if (interactive)
			err(1, "Allocating private context");
		else
			return (NULL);
	}

	/*
	 * Initialize the internal FD to -1. This will keep us from
	 * automatically closing the FD.
	 */
	ctx->pc_fd = -1;

	/* Initialize the interactive state so we know how to handle errors. */
	ctx->pc_interactive = !!(interactive);

	/* Initialize the fatal error flag. */
	ctx->pc_fatalerr = false;

	/* Get the file size. */
	if (fstat(fd, &sb)) {
		bbr_err(ctx, "Error running fstat() on pcap file");
		free(ctx);
		return (NULL);
	}

	/* Make sure the file is at least 12 bytes long. */
	if (sb.st_size < 12) {
		fatal_error(ctx, "File length (%zu) is less than the minimum "
		    "length of a block", sb.st_size);
		free(ctx);
		return (NULL);
	}

	/* Map the file to memory. */
	ctx->pc_maplen = sb.st_size;
	ctx->pc_base = mmap(0, ctx->pc_maplen, PROT_READ, MAP_PRIVATE, fd, 0);
	if (ctx->pc_base == MAP_FAILED) {
		bbr_err(ctx, "Error mapping pcap file");
		free(ctx);
		return (NULL);
	}

	/* Schedule the stack name table for initialization. */
	ctx->pc_stacknames_initd = false;

	/* Initialize the header storage. */
	ctx->pc_tlh = NULL;
	ctx->pc_tlh_allocd = false;

	/* Initialize the aligned allocation variables. */
	ctx->pc_alignedtlb = NULL;
	ctx->pc_alignedtlblen = 0;

	/* Determine whether this is an XZ file or not. */
	if (memcmp(ctx->pc_base, &xz_magic, 6) == 0) {
		bbr_init_xzfile(ctx);
		if (ctx->pc_fatalerr)
			goto bad;
	} else {
		/* Find the beginning and end of the buffer. */
		ctx->pc_cur = ctx->pc_base;
		ctx->pc_end = ctx->pc_cur + (ctx->pc_maplen / 4);
		if (ctx->pc_maplen & 0x3)
			warning(ctx, "file may have been truncated.");
	}

	/* Get the type and length of the first block. */
	type = *ctx->pc_cur;
	len = *(ctx->pc_cur + 1);

	/* Make sure the first block is a section header. */
	if (type != BT_SHB) {
		fatal_error(ctx, "First block was not a section header");
		goto bad;
	}

	/* Check the length. It must be greater than 12 and a multiple of 4. */
	if (len < 12 || (len & 0x3) || len > sb.st_size) {
		fatal_error(ctx, "Invalid length %u for section header block",
		    len);
		goto bad;
	}

	/* Parse the SHB. */
	shb(ctx, len - 12);
	if (ctx->pc_fatalerr)
		goto bad;

	/* Advance through the section header. */
	ctx->pc_cur += (len / 4);

	return ((void *)ctx);

bad:
	bbr_fini(ctx);
	return (NULL);
}

void *
bbr_init_file(const char *filename, int interactive)
{
	struct private_context *ctx;
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		if (interactive)
			err(1, "Error opening pcap file");
		else
			return (NULL);
	}

	ctx = bbr_init_fd(fd, interactive);
	if (ctx != NULL)
		ctx->pc_fd = fd;
	else
		close(fd);
	return ((void *)ctx);
}

void
bbr_fini(void *arg)
{
	struct private_context *ctx;
	int i;

	ctx = (struct private_context *)arg;

	if (ctx->pc_fd > 0)
		close(ctx->pc_fd);

	if (ctx->pc_base != NULL && munmap(ctx->pc_base, ctx->pc_maplen)) {
		bbr_warn(ctx, "Error unmapping PCAPNG file");
		if (!ctx->pc_interactive)
			abort();
	}

	free(ctx->pc_alignedtlb);

	if (ctx->pc_stacknames_initd)
		for (i = 0; i < 256; i++)
			if (ctx->pc_stacknames[i] != NULL)
				free(ctx->pc_stacknames[i]);

	free(ctx);
}

static void
convert_v8_to_cur(const struct tcp_log_buffer *in, struct tcp_log_buffer *out)
{
	const struct tcp_log_buffer_v8 *v8;
	size_t len;

	v8 = (const struct tcp_log_buffer_v8 *)in;
	len = offsetof(struct tcp_log_buffer, tlb_flex2);
	/* We want to be sure and copy flex2 also */
	len += sizeof(uint32_t);
	/* 
	 * V8 is the same as V9 up until tlb_rcv_scale so
	 * lets copy in that part byte for byte.
	 */
	memcpy(out, in, len);
	/* We must manually copy the bit fields */
	out->tlb_snd_scale = in->tlb_snd_scale;
	out->tlb_rcv_scale = in->tlb_rcv_scale;
	/*
	 * Now V8 does not have the new tlb_fbyte_in and
	 * tlb_fbyte_out fields lets make sure those are 0.
	 */
	out->tlb_fbyte_in = 0;
	out->tlb_fbyte_out = 0;
	out->tlb_flags2 = 0;
	/* 
	 * Now we don't care about the _pad its just
	 * that padding. We want to copy from the beginning
	 * of the stack information down to the tlb_th. We
	 * never have any valid information in user space
	 * in either tlb_th or tlb_opts. In fact the 
	 * information in the pcap likely does not even
	 * have that data and if we are pointing into
	 * the buffer we could be past the end.
	 */
	len = offsetof(struct tcp_log_buffer_v8, tlb_th) -
		offsetof(struct tcp_log_buffer_v8, tlb_stackinfo);
	memcpy(&out->tlb_stackinfo, &v8->tlb_stackinfo, len);
	/* Tada its now a version 9 record */
}

int
bbr_convert(void *ctxp, const struct tcp_log_buffer *in, struct tcp_log_buffer *out)
{
	/*
	 * Forward convert an older version of 
	 * the library to the current version.
	 */
	struct private_context *ctx;

	ctx = (struct private_context *)ctxp;
	if (ctx->pc_tlh->tlh_version == TCP_LOG_BUF_VER) {
		/* Nothing to do but copy it to the out record */
		memcpy(out, in, sizeof(struct tcp_log_buffer));
		return (0);
	}
	if (ctx->pc_tlh->tlh_version == TCP_LOG_VER_7) {
		/* 
		 * Version 7 converts the same as version 8  
		 * except sacknewdata became flex3
		 * which then became flags2.
		 */
		convert_v8_to_cur(in, out);
		return (0);
	} else if (ctx->pc_tlh->tlh_version == TCP_LOG_VER_8) {
		/* We know how to convert this one */
		convert_v8_to_cur(in, out);
		return (0);
	}
	/* We don't know how to convert any other types */
	return (-1);
}
