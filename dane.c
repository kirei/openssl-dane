/*
 * Copyright (c) 2012 Mathias Samuelson. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unbound.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "dane.h"

BIO *b_err;
int get_tlsa(struct ub_result *result, char *s_host, short s_port);
int ca_constraint(const SSL *con, const X509 *tlsa_cert, int usage);
int service_cert_constraint(const X509 *con_cert, const X509 *tlsa_cert);
int synthesize_tlsa_domain(char *tlsa_domain, const SSL *con, char *hostname);

int synthesize_tlsa_domain(char *tlsa_domain, const SSL *con, char *hostname) {
	int peerfd;
	peerfd = SSL_get_fd(con);
	socklen_t len;
	struct sockaddr_storage addr;
	char ipstr[INET6_ADDRSTRLEN];
	char node[NI_MAXHOST];
	char dns_name[256];
	char proto[4];
	int sock_type, optlen;
	int port;
	int retval;
	len = sizeof addr;
	getpeername(peerfd, (struct sockaddr*)&addr, &len);
	// deal with both IPv4 and IPv6:
	if (addr.ss_family == AF_INET) {
	    struct sockaddr_in *s = (struct sockaddr_in *)&addr;
	    port = ntohs(s->sin_port);
	    inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr);
		struct sockaddr_in sa;
		sa.sin_family = AF_INET;
		inet_pton(AF_INET, ipstr, &sa.sin_addr);
		int res = getnameinfo((struct sockaddr*)&sa, sizeof(sa), node, sizeof(node), NULL, 0, 0);
	} else { // AF_INET6
		struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
	    port = ntohs(s->sin6_port);
	    inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof ipstr);
	}
	optlen = sizeof(sock_type);
	retval = getsockopt(peerfd, SOL_SOCKET, SO_TYPE, &sock_type, &optlen);
	if (retval == -1) {
		BIO_printf(b_err, "synthesize_tlsa_domain failed to get socket type: %d\n", retval);
		return -1;
	}
	switch (sock_type) {
		case SOCK_STREAM:
			sprintf(proto, "tcp");
			break;
		case SOCK_DGRAM:
			sprintf(proto, "udp");
			break;
	}
	
	retval = sprintf(tlsa_domain, "_%d._%s.%s", port, proto, node);
	if(retval < 0) {
		printf("failure to create dns name\n");
		return -1;
	}
	BIO_printf(b_err,"DANE synthesize_tlsa_domain() dns name: %s\n", tlsa_domain);
	
	return 0;
}

int dane_verify_callback(int ok, X509_STORE_CTX *store) {
	if (b_err == NULL)
		b_err=BIO_new_fp(stderr,BIO_NOCLOSE);
		
	char data[256];
	if (! ok) {
		X509 *cert = X509_STORE_CTX_get_current_cert(store);
		int depth = X509_STORE_CTX_get_error_depth(store);
		int err = X509_STORE_CTX_get_error(store);
		
		BIO_printf(b_err, "dane_verify_callback error with cert at depth: %d\n", depth);
		X509_NAME_oneline(X509_get_issuer_name(cert), data, sizeof(data));
		BIO_printf(b_err, "dane_verify_callback issuer  = %s\n", data);
		X509_NAME_oneline(X509_get_subject_name(cert), data, sizeof(data));
		BIO_printf(b_err, "dane_verify_callback subject = %s\n", data);
		BIO_printf(b_err, "dane_verify_callback error %i:%s\n", err,
			X509_verify_cert_error_string(err));
	}
	
	return ok;
}
int dane_verify(SSL *con, char *s_host, short s_port) {
	struct ub_result *dns_result;
	struct ub_ctx* ctx;
	char dns_name[256];
	int retval;
	
	if (b_err == NULL)
		b_err=BIO_new_fp(stderr,BIO_NOCLOSE);
	BIO_printf(b_err, "DANE:%s:%d\n", s_host, s_port);
	
	ctx = ub_ctx_create();
	if(!ctx) {
		printf("error: could not create unbound context\n");
		return -1;
	}
	if( (retval=ub_ctx_resolvconf(ctx, "/etc/resolv.conf")) != 0) {
		printf("error reading resolv.conf: %s. errno says: %s\n", 
			ub_strerror(retval), strerror(errno));
		return -1;
	}
	if( (retval=ub_ctx_hosts(ctx, "/etc/hosts")) != 0) {
		printf("error reading hosts: %s. errno says: %s\n", 
			ub_strerror(retval), strerror(errno));
		return -1;
	}
	if( (retval=ub_ctx_add_ta_file(ctx, "keys")) != 0) {
		printf("error adding keys: %s\n", ub_strerror(retval));
		return 1;
	}
	
	synthesize_tlsa_domain(dns_name, con, s_host);
	BIO_printf(b_err,"DANE:dns name: %s\n", dns_name);
	retval = ub_resolve(ctx, dns_name, 65534, 1, &dns_result);
	if(retval != 0) {
		printf("resolve error: %s\n", ub_strerror(retval));
		return -1;
	}
	if (dns_result->secure)
		BIO_printf(b_err, "DANE DNS result is secure\n");
	else if (dns_result->bogus) {
		BIO_printf(b_err, "DANE DNS result is bogus: %s\n", dns_result->why_bogus);
		SSL_shutdown(con);

		return -1;
	} else {
		// should allow PKIX validation to proceed but without DANE
		BIO_printf(b_err, "DANE DNS result is insecure\n");
		return -1;
	}
		
	if(dns_result->havedata) {
		int i;
		for (i = 0; dns_result->data[i] != NULL; i++) {
			unsigned char usage, selector, matching_type;
			unsigned char *tlsa_bytes;
			
			if (dns_result->len[i] < 35) {
				// must have at least 1+1+1+32 bytes for the SHA-256 case
				BIO_printf(b_err, "DANE: Not enough data: %d available\n",
					dns_result->len[i]);
				return -1;
			}
			unsigned char *rdata = (unsigned char *)dns_result->data[i];
			usage = (char) *rdata++;
			selector = (char) *rdata++;
			matching_type = (char) *rdata++;
			tlsa_bytes = (unsigned char *)rdata;
			X509 *tlsa_cert;
			tlsa_cert = d2i_X509(NULL, &tlsa_bytes, dns_result->len[i]-3);
			
			BIO_printf(b_err, "DANE: Usage %d Selector %d Matching Type %d\n",
				usage, selector, matching_type);
			
			if (selector != 0)
				continue;
			if (matching_type != 0)
				continue;

			int retval;
			switch (usage) {
				case 0:
					return ca_constraint(con, tlsa_cert, usage);
					//break;
				case 1: {
					X509 *cert = NULL;
					cert = SSL_get_peer_certificate(con);
					retval = service_cert_constraint(cert, tlsa_cert);
					if (retval == 0)
						BIO_printf(b_err, "DANE: Passed validation for usage 1\n");
					else
						BIO_printf(b_err, "DANE: Failed validation for usage 1\n");
					X509_free(cert);
					return retval;
					break;
				}
				case 2: {
					SSL_CTX *con_ctx = SSL_get_SSL_CTX(con);
					X509_STORE *vfy_store;
					
					if (!(vfy_store = X509_STORE_new())) {
						BIO_printf(b_err, "DANE dane_verify error creating store");
						retval = -1;
					} else {
						X509_STORE_add_cert(vfy_store, tlsa_cert);
						SSL_CTX_set_cert_store(con_ctx, vfy_store);
						retval = 0;
						break;
					}
				}
			}
			X509_free(tlsa_cert);
		}
	} else
		return 0;

	(void)BIO_flush(b_err);
	return retval;
}

/*
 *	Returns: 	0 if successfully matching certificate to TLSA record bytes
 *				-1 if there was no match
 */
int ca_constraint(const SSL *con, const X509 *tlsa_cert, int usage) {
	STACK_OF(X509) *cert_chain = NULL;
	cert_chain = SSL_get_peer_cert_chain(con);
	BIO_printf(b_err, "DANE ca_constraint() chain of %d length\n", 
		sk_X509_num(cert_chain));
	int ret_val;
	ret_val = 0;
	
	if (cert_chain != NULL) {
		int i;
		for (i = 0; i < sk_X509_num(cert_chain); i++) {			
			BIO_printf(b_err, "DANE ca_constraint() cert %d of %d.\n",
				i, sk_X509_num(cert_chain));
				
			if (X509_cmp(tlsa_cert, sk_X509_value(cert_chain, i)) < 0) {
				ret_val = -1;
				BIO_printf(b_err, "DANE ca_constraint() certificates didn't match\n");
			} else {
				BIO_printf(b_err, "DANE ca_constraint() certificates matches\n");
				return 0;
			}
		}
	}
	return ret_val;
}

/*
 *	Returns: 	0 if successfully matching certificate to TLSA record bytes
 *				-1 if there was no match
 */
//int service_cert_constraint(const SSL *con, const unsigned char *tlsa_bytes, int tlsa_len) {
int service_cert_constraint(const X509 *con_cert, const X509 *tlsa_cert) {
	int ret_val;
	ret_val = 0;
	
	if (con_cert != NULL) {
		if (X509_cmp(tlsa_cert, con_cert) != 0) {
			ret_val = -1;
			BIO_printf(b_err, "DANE server_cert_constraint() certificates didn't match\n");
		} else {
			BIO_printf(b_err, "DANE server_cert_constraint() certificates matches\n");
			// Must return immediately in case there are non-matching certificates
			return 0;
		}
	} else
		BIO_printf(b_err,"DANE:no peer certificate available\n");
		
	return ret_val;
}
