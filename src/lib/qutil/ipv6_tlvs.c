#include <errno.h>
#include <linux/genetlink.h>
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libgenl.h"
#include "qutils.h"

static inline void *ERR_PTR(long error)
{
	return (void *) error;
}

static inline long PTR_ERR(const void *ptr)
{
	return (long) ptr;
}

/**
 * ipv6_opt_validate_tlvs - Check TLVs options have reasonable lengths.
 * @opt: the option header
 *
 * Description:
 * Walks the TLVs in a list to verify that the TLV lengths are in bounds
 * for a Destination or Hop-by-Hop option. Return -EINVAL is there is a
 * problem, zero otherwise.
 */
int ipv6_opt_validate_tlvs(struct ipv6_opt_hdr *opt)
{
	unsigned char *tlv = (unsigned char *)opt;
	unsigned int opt_len, tlv_len, offset;

	opt_len = ipv6_optlen(opt);
	offset = sizeof(*opt);

	while (offset < opt_len) {
		switch (tlv[offset]) {
		case IPV6_TLV_PAD1:
			tlv_len = 1;
			break;
		case IPV6_TLV_PADN:
		default:
			if (offset + 1 >= opt_len)
				return -EINVAL;

			tlv_len = tlv[offset + 1] + 2;

			if (offset + tlv_len > opt_len)
				return -EINVAL;
		}
		offset += tlv_len;
	}

	return 0;
}

/**
 * ipv6_opt_validate_single - Check that a single TLV is valid.
 * @tlv: the TLV
 * @len: Length of buffer holding TLV
 *
 * Description:
 * Validates a single TLV. The TLV must be non-padding type. The length
 * of the TLV (as determined by the second byte that gives lenght of the
 * option data) must match @len.
 */
int ipv6_opt_validate_single_tlv(unsigned char *tlv, size_t len)
{
	if (len < 2)
		return -EINVAL;

	switch (tlv[0]) {
	case IPV6_TLV_PAD1:
	case IPV6_TLV_PADN:
		return -EINVAL;
	default:
		break;
	}

	if (tlv[1] + 2 != len)
		return -EINVAL;

	return 0;
}

/* Find the end of the TLV list. Assumes input header has be validated */
static void ipv6_opt_tlv_find_end(struct ipv6_opt_hdr *opt,
				  unsigned int *start, unsigned int *end)
{
	unsigned int opt_len, offset, offset_s = 0;
	unsigned char *tlv = (unsigned char *)opt;

	opt_len = ipv6_optlen(opt);
	offset = sizeof(*opt);

	while (offset < opt_len) {
		switch (tlv[offset]) {
		case IPV6_TLV_PAD1:
			offset++;
			break;
		default:
			offset_s = offset;
			/* Fallthrough */
		case IPV6_TLV_PADN:
			offset += tlv[offset + 1] + 2;
			break;
		}
	}

	*start = offset_s + tlv[offset_s + 1] + 2;
	*end = opt_len;
}

/**
 * ipv6_opt_tlv_find - Finds a particular TLV in an IPv6 options header
 * (destinaton or hop-by-hop options). If TLV is not present, then the
 * preferred insertion point is determined.
 * @opt: the options header
 * @target: TLV type to find
 * @start: on return holds the offset of any leading padding if option
 *       is present, or offset at which option is inserted.
 * @end: on return holds the offset of the first non-pad TLV after option
 *       if the option was found, else points to the first TLV after
 *       padding at intsertion point.
 *
 * Description:
 * Finds the space occupied by particular option (including any leading and
 * trailing padding), or the perferred position for insertion if the
 * TLV is not present.
 *
 * If the TLV is found set @start and @end to the offsets within @opt of the
 * start of padding before the option and the end of padding after the TLV.
 * In this case the function returns the offset of the TLV in @opt.
 *
 * If the TLV isn't found, @start is set to offset in @opt at which the option
 * may be inserted, and @end is set to the offset of the frst TLV after the
 * insertion point. The function will returns -ENOENT.
 */
int ipv6_opt_tlv_find(struct ipv6_opt_hdr *opt, unsigned char *targ_tlv,
		      unsigned int *start, unsigned int *end)
{
	unsigned int offset_s = 0, offset_e = 0, last_s = 0;
	unsigned char *tlv = (unsigned char *)opt;
	unsigned int opt_len, tlv_len, offset;
	unsigned int pad_e = sizeof(*opt);
	int ret_val = -ENOENT;

	opt_len = ipv6_optlen(opt);
	offset = sizeof(*opt);

	while (offset < opt_len) {
		switch (tlv[offset]) {
		case IPV6_TLV_PAD1:
			if (offset_e)
				offset_e = offset;
			tlv_len = 1;
			break;
		case IPV6_TLV_PADN:
			if (offset_e)
				offset_e = offset;
			tlv_len = tlv[offset + 1] + 2;
			break;
		default:
			if (ret_val >= 0)
				goto out;

			/* Not found yet */
				
			if (tlv[offset] == targ_tlv[0]) {
				/* Found it */

				ret_val = offset;
				offset_e = offset;
				offset_s = last_s;
			} else if (targ_tlv[0] < tlv[offset] && !offset_s) {
				/* Found candidate for insert location */

				pad_e = offset;
				offset_s = last_s;
			}

			last_s = offset;
			tlv_len = tlv[offset + 1] + 2;
			break;
		}

		offset += tlv_len;
	}

out:
	if (offset_s)
		*start = offset_s +
		    (tlv[offset_s] ? tlv[offset_s + 1] + 2 : 1);
	else
		*start = sizeof(*opt);

	if (ret_val >= 0)
		*end = offset_e +
		    (tlv[offset_e] ? tlv[offset_e + 1] + 2 : 1);
	else
		*end = pad_e;

	return ret_val;
}

/**
 * ipv6_opt_tlv_pad_write - Writes pad bytes in TLV format
 * @buf: the buffer
 * @offset: offset from start of buffer to write padding
 * @count: number of pad bytes to write
 *
 * Description:
 * Write @count bytes of TLV padding into @buffer starting at offset @offset.
 * @count should be less than 8 - see RFC 4942.
 *
 */
static void ipv6_opt_tlv_pad_write(unsigned char *buf, unsigned int offset,
				   unsigned int count)
{
	switch (count) {
	case 0:
		break;
	case 1:
		buf[offset] = IPV6_TLV_PAD1;
		break;
	default:
		buf[offset] = IPV6_TLV_PADN;
		buf[offset + 1] = count - 2;
		if (count > 2)
			memset(buf + offset + 2, 0, count - 2);
		break;
	}
}

#define IPV6_OPT_MAX_PAD (3 + 7)
static const unsigned char padding[4] = {2, 1, 0, 3};

/**
 * ipv6_opt_tlv_insert - Inserts a TLV into an IPv6 destination options
 * or Hop-by-Hop options extension header.
 * 
 * @opt: the original options extensions header
 * @tlv: the new TLV being inserted
 *
 * Description:
 * Creates a new options header based on @opt with the specified option
 * in @new option added to it.  If @tlv already contains the same type
 * of TLV, then the TLV is overwritten, otherwise the new TLV is inserted
 * at the preferred insertsion point returned by ipv6_opt_tlv_find.
 * If @opt is NULL then the new header will contain just the new option
 * and any needed padding.
 */
struct ipv6_opt_hdr *ipv6_opt_tlv_insert(struct ipv6_opt_hdr *opt,
					 unsigned char *tlv)
{
	unsigned int start = 0, end = 0, buf_len, pad, optlen;
	size_t tlv_len = tlv[1] + 2;
	struct ipv6_opt_hdr *new;
	int ret_val;

	if (opt) {
		optlen = ipv6_optlen(opt);
		ret_val = ipv6_opt_tlv_find(opt, tlv, &start, &end);
		if (ret_val < 0) {
			if (ret_val != -ENOENT)
				return ERR_PTR(ret_val);
		} else if (((unsigned char *)opt)[ret_val + 1] == tlv[1]) {
			unsigned int roff = ret_val + tlv[1] + 2;

			/* Replace existing TLV with one of the same length,
			 * we can fast path this.
			 */

			new = malloc(optlen);
			if (!new)
				return ERR_PTR(-ENOMEM);

			memcpy((unsigned char *)new,
			       (unsigned char *)opt, ret_val);
			memcpy((unsigned char *)new + ret_val, tlv, tlv[1] + 2);
			memcpy((unsigned char *)new + roff,
			       (unsigned char *)opt + roff, optlen - roff);

			return new;
		}
	} else {
		optlen = 0;
		start = sizeof(*opt);
		end = 0;
	}

	/* Maximum buffer size we'll need including possible padding */
	buf_len = optlen + start - end + tlv_len + IPV6_OPT_MAX_PAD;
	new = malloc(buf_len);
	if (!new)
		return ERR_PTR(-ENOMEM);

	buf_len = start;

	if (start > sizeof(*opt))
		memcpy(new, opt, start);

	 /* Assume 4n + 2 alignment */
	pad = padding[start & 3];
	ipv6_opt_tlv_pad_write((__u8 *)new, start, pad);
	buf_len += pad;

	memcpy((__u8 *)new + buf_len, tlv, tlv_len);
	buf_len += tlv_len;

	if (end != optlen) {
		unsigned int last_start, last_end;

		/* Replacing a TLV and there are trailing TLVs */

		/* Assume all TLVs are padded to 4n + 2 alignment */
		pad = padding[buf_len & 3];
		ipv6_opt_tlv_pad_write((unsigned char *)new, buf_len, pad);
		buf_len += pad;

		/* Find the end of the last TLV, this is what we need to copy.
		 * Any padding beyond the last TLV is irrelevant, we'll add our
		 * own trailer padding later.
		 */
		ipv6_opt_tlv_find_end(opt, &last_start, &last_end);
		memcpy((char *)new + buf_len, (char *)opt + end,
		       last_start - end);
		buf_len += last_start - end;
	}

	/* Trailer pad to 8 byte alignment */
	pad = (8 - (buf_len & 7)) & 7;
	ipv6_opt_tlv_pad_write((__u8 *)new, buf_len, pad);
	buf_len += pad;

	/* Set header */
	new->nexthdr = 0;
	new->hdrlen = buf_len / 8 - 1;

	return new;
}

/**
 * ipv6_opt_tlv_delete - Removes the specified TLV from the destination or
 * Hop-by-Hop extension header.
 * @opt: the original header
 * @tlv: TLV type being removed
 *
 * Description:
 * Creates a new header based on @hop without the specified option in
 * @tlv. If @tlv doesn't contain the specified option it returns -ENOENT.
 * If the new header is found, it is removed and an the new header without
 * the TLV is returned. If the TLV being deleted is the only non-padding
 * option in the header, then the function returns. Otherwise it returns
 * the new header.
 */
struct ipv6_opt_hdr *ipv6_opt_tlv_delete(struct ipv6_opt_hdr *opt,
					 unsigned char *tlv)
{
	unsigned int start, end, pad, optlen, buf_len;
	struct ipv6_opt_hdr *new;
	int ret_val;

	ret_val = ipv6_opt_tlv_find(opt, tlv, &start, &end);
	if (ret_val < 0)
		return ERR_PTR(ret_val);

	optlen = ipv6_optlen(opt);
	if (start == sizeof(*opt) && end == optlen) {
		/* There's no other option in the header so return NULL */
		return NULL;
	}

	new = malloc(optlen - (end - start) + IPV6_OPT_MAX_PAD);
	if (!new)
		return ERR_PTR(-ENOMEM); /* DIFF */

	memcpy(new, opt, start);
	buf_len = start;

	if (end != optlen) {
		unsigned int last_start, last_end;

		/* Not deleting last TLV, need to copy TLVs that follow and
		 * adjust padding
		 */

		/* Assume all TLVs are padded to 4n + 2 alignment */
		pad = padding[buf_len & 3];
		ipv6_opt_tlv_pad_write((unsigned char *)new, buf_len, pad);
		buf_len += pad;

		/* Find the end of the last TLV, this is what we need to copy.
		 * Any padding beyond the last TLV is irrelevant, we'll add our
		 * own trailer padding later.
		 */
		ipv6_opt_tlv_find_end(opt, &last_start, &last_end);
		memcpy((char *)new + buf_len, (char *)opt + end,
		       last_start - end);
		buf_len += last_start - end;
	}

	/* Now set trailer padding, buf_len is at the end of the last TLV at
	 * this point
	 */
	pad = (8 - (buf_len & 7)) & 7;
	ipv6_opt_tlv_pad_write((__u8 *)new, buf_len, pad);
	buf_len += pad;

	/* Set new header length */
	new->hdrlen = buf_len / 8 - 1;

	return new;
}

/* netlink socket */
static struct rtnl_handle genl_rth = { .fd = -1 };
static int genl_family = -1;

#define IPV6_TLV_REQUEST(_req, _bufsiz, _cmd, _flags)		\
        GENL_REQUEST(_req, _bufsiz, genl_family, 0,		\
                     IPV6_TLV_GENL_VERSION, _cmd, _flags)

static int print_one(struct nlmsghdr *n)

{
	struct genlmsghdr *ghdr;
	struct rtattr *tb[IPV6_TLV_ATTR_MAX + 1];
	int len = n->nlmsg_len;

	if (n->nlmsg_type != genl_family)
		return 0;

	len -= NLMSG_LENGTH(GENL_HDRLEN);
	if (len < 0)
		return -1;

	ghdr = NLMSG_DATA(n);

	parse_rtattr(tb, IPV6_TLV_ATTR_MAX, (void *) ghdr + GENL_HDRLEN, len);

	if (tb[IPV6_TLV_ATTR_ORDER]) {
		unsigned char *v = RTA_DATA(tb[IPV6_TLV_ATTR_ORDER]);
		int i;

		for (i = 0; i < 254; i++)
			printf("%d\n", v[i]);
	}

	return 0;
}

void show_ipv6_tlvs(void)
{
	struct {
		struct nlmsghdr n;
		struct genlmsghdr g;
		char buf[4096];
	} a;

	if (genl_init_handle(&genl_rth, IPV6_TLV_GENL_NAME, &genl_family))
		exit(1);

	IPV6_TLV_REQUEST(req, 4096, IPV6_TLV_CMD_GET, NLM_F_REQUEST);

	if (rtnl_talk(&genl_rth, &req.n, &a.n, 520) < 0) {
		perror("rtnl_talk");
		exit(-1);
	}
		
	print_one(&a.n);
}

void set_ipv6_tlvs(void)
{
	char buf[254];
	int i;

	if (genl_init_handle(&genl_rth, IPV6_TLV_GENL_NAME, &genl_family))
		exit(1);

	IPV6_TLV_REQUEST(req, 4096, IPV6_TLV_CMD_SET, NLM_F_REQUEST);

	for (i = 0; i < 254; i++)
		buf[i] = 255 - i;
	buf[10] = 10;

	addattr_l(&req.n, 1024, IPV6_TLV_ATTR_ORDER, buf, sizeof(buf));

	if (rtnl_talk(&genl_rth, &req.n, NULL, 0) < 0) {
		perror("rtnl_talk");
		exit(-1);
	}
}

