/*
 * emb6 is licensed under the 3-clause BSD license. This license gives everyone
 * the right to use and distribute the code, either in binary or source code
 * format, as long as the copyright license is retained in the source code.
 *
 * The emb6 is derived from the Contiki OS platform with the explicit approval
 * from Adam Dunkels. However, emb6 is made independent from the OS through the
 * removal of protothreads. In addition, APIs are made more flexible to gain
 * more adaptivity during run-time.
 *
 * The license text is:
 *
 * Copyright (c) 2015,
 * Hochschule Offenburg, University of Applied Sciences
 * Laboratory Embedded Systems and Communications Electronics.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
/*============================================================================*/
/**
 *   \addtogroup emb6
 * 	 @{
 * 	 \addtogroup demo
 * 	 @{
 * 	 \addtogroup demo_dtls
 * 	 @{
 * 	 \addtogroup demo_dtls_client DTLS UDP Client
 * 	 @{
*/
/*! \file   demo_dtls_cli.c

 \author Fesseha T. Mamo

 \brief  DTLS Client example application

 \version 0.0.1
 */
/*============================================================================*/

/*==============================================================================
 INCLUDE FILES
 =============================================================================*/

#include "emb6.h"
#include "bsp.h"
#include "uip.h"
//#include "udp-socket.h"
#include "evproc.h"
#include "demo_dtls_cli.h"

#include "tinydtls.h"
#include "dtls.h"
#include "debug.h"
#include "evproc.h"


/*==============================================================================
                                     MACROS
 =============================================================================*/

#define 	LOGGER_ENABLE		TRUE
#include	"logger.h"

#ifdef DTLS_PSK
/* The PSK information for DTLS */
/* make sure that default identity and key fit into buffer, i.e.
 * sizeof(PSK_DEFAULT_IDENTITY) - 1 <= PSK_ID_MAXLEN and
 * sizeof(PSK_DEFAULT_KEY) - 1 <= PSK_MAXLEN
*/

#define PSK_ID_MAXLEN 32
#define PSK_MAXLEN 32
#define PSK_DEFAULT_IDENTITY "Client_identity"
#define PSK_DEFAULT_KEY      "secretPSK"
#endif /* DTLS_PSK */

#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#ifndef UIP_UDP_BUF
#define UIP_UDP_BUF  ((struct uip_udp_hdr *)&uip_buf[UIP_LLIPH_LEN])
#endif

#define MAX_PAYLOAD_LEN 120
/*==============================================================================
                          LOCAL VARIABLE DECLARATIONS
 =============================================================================*/

static struct etimer et;
uip_ipaddr_t server_ipaddr;

session_t dst;
static int connected = 0;
static struct etimer et;

//static struct uip_udp_conn *client_conn;
//TODO LW
//static  struct  udp_socket          st_udp_socket;
//        struct  udp_socket*         pst_udp_socket;

dtls_context_t *dtls_context;
static char buf[200] = {0x36, 0x37, 0x38, 0x39};
static size_t buflen = 9;

#ifndef DTLS_X509
static const unsigned char ecdsa_priv_key[] = {
			0x41, 0xC1, 0xCB, 0x6B, 0x51, 0x24, 0x7A, 0x14,
			0x43, 0x21, 0x43, 0x5B, 0x7A, 0x80, 0xE7, 0x14,
			0x89, 0x6A, 0x33, 0xBB, 0xAD, 0x72, 0x94, 0xCA,
			0x40, 0x14, 0x55, 0xA1, 0x94, 0xA9, 0x49, 0xFA};

static const unsigned char ecdsa_pub_key_x[] = {
			0x36, 0xDF, 0xE2, 0xC6, 0xF9, 0xF2, 0xED, 0x29,
			0xDA, 0x0A, 0x9A, 0x8F, 0x62, 0x68, 0x4E, 0x91,
			0x63, 0x75, 0xBA, 0x10, 0x30, 0x0C, 0x28, 0xC5,
			0xE4, 0x7C, 0xFB, 0xF2, 0x5F, 0xA5, 0x8F, 0x52};

static const unsigned char ecdsa_pub_key_y[] = {
			0x71, 0xA0, 0xD4, 0xFC, 0xDE, 0x1A, 0xB8, 0x78,
			0x5A, 0x3C, 0x78, 0x69, 0x35, 0xA7, 0xCF, 0xAB,
			0xE9, 0x3F, 0x98, 0x72, 0x09, 0xDA, 0xED, 0x0B,
			0x4F, 0xAB, 0xC3, 0x6F, 0xC7, 0x72, 0xF8, 0x29};

#else

static const unsigned char ecdsa_ca_pub_x[] = {
	0xff, 0x5d, 0x3e, 0xc6, 0x40, 0x7f, 0x27, 0x5d, 0x1a, 0x12, 0x91, 0x54, 0x0c, 0x9c, 0x06, 0x7d,
	0xf9, 0xa5, 0x23, 0x82, 0x8c, 0x2e, 0xeb, 0x3b, 0x23, 0xe9, 0x8b, 0x7c, 0xf0, 0x15, 0xc3, 0x80
};

static const unsigned char ecdsa_ca_pub_y[] = {
	0x4c, 0x38, 0x41, 0x37, 0x70, 0xc4, 0x13, 0x1a, 0x30, 0x8c, 0xcc, 0x4a, 0x6b, 0x78, 0xc3, 0x25,
	0xec, 0x00, 0x91, 0xd3, 0xc2, 0x88, 0x18, 0x20, 0xfd, 0xcc, 0x41, 0x9c, 0x39, 0x92, 0x28, 0x74
};

#endif

/*==============================================================================
                           LOCAL FUNCTION PROTOTYPES
 =============================================================================*/

static void dtls_udp_callback(void);
/*==============================================================================
                                LOCAL CONSTANTS
 =============================================================================*/

#define TOGGLE_INTERVAL 2  /* interval for client requests */

/* Example URIs that can be queried. */
#define NUMBER_OF_URLS 2

/* leading and ending slashes only for demo purposes, get cropped automatically when setting the Uri-Path */
char *service_urls[NUMBER_OF_URLS] =
{ ".well-known/core", "actuators/LED_toggle"};

/*==============================================================================
                                LOCAL FUNCTIONS
 =============================================================================*/

/* This function is will be passed to coap_nonblocking_request() to handle responses. */
void _client_chunk_handler(void *response)
{
	if(!response) {
		LOG_INFO("%s\n\r","Restart Timer (no response)");
	} else {
		LOG_INFO("%s\n\r","response payload:");
	}
	/* Restart Timer after response or timeout */
	etimer_restart(&et);
}

void
try_send(c_event_t c_event, p_data_t p_data) {
	int res;
	if (etimer_expired(&et) && (&et == p_data)) {
		res = dtls_write(dtls_context, &dst, (uint8 *)buf, buflen);
		if (res >= 0) {
			PRINTF("Sample data sent.\n");
//			memmove(buf, buf + res, buflen - res);
//			buflen -= res;
		}
		etimer_reset(&et);
	}
}


#ifdef DTLS_PSK
static unsigned char psk_id[PSK_ID_MAXLEN] = PSK_DEFAULT_IDENTITY;
static size_t psk_id_length = sizeof(PSK_DEFAULT_IDENTITY) - 1;
static unsigned char psk_key[PSK_MAXLEN] = PSK_DEFAULT_KEY;
static size_t psk_key_length = sizeof(PSK_DEFAULT_KEY) - 1;

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__((unused))
#else
#define UNUSED_PARAM
#endif /* __GNUC__ */

/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identity within this particular
 * session. */
int
get_psk_info(struct dtls_context_t *ctx UNUSED_PARAM,
	    const session_t *session UNUSED_PARAM,
	    dtls_credentials_type_t type,
	    const unsigned char *id, size_t id_len,
	    unsigned char *result, size_t result_length) {

  switch (type) {
  case DTLS_PSK_IDENTITY:
    if (result_length < psk_id_length) {
      dtls_warn("cannot set psk_identity -- buffer too small\n");
      return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    }

    memcpy(result, psk_id, psk_id_length);
    return psk_id_length;
  case DTLS_PSK_KEY:
    if (id_len != psk_id_length || memcmp(psk_id, id, id_len) != 0) {
      dtls_warn("PSK for unknown id requested, exiting\n");
      return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);
    } else if (result_length < psk_key_length) {
      dtls_warn("cannot set psk -- buffer too small\n");
      return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    }

    memcpy(result, psk_key, psk_key_length);
    return psk_key_length;
  default:
    dtls_warn("unsupported request type: %d\n", type);
  }

  return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
}
#endif /* DTLS_PSK */

#ifdef DTLS_ECC
#ifndef DTLS_X509
int
get_ecdsa_key(struct dtls_context_t *ctx,
	      const session_t *session,
	      const dtls_ecdsa_key_t **result) {
  static const dtls_ecdsa_key_t ecdsa_key = {
    .curve = DTLS_ECDH_CURVE_SECP256R1,
    .priv_key = ecdsa_priv_key,
    .pub_key_x = ecdsa_pub_key_x,
    .pub_key_y = ecdsa_pub_key_y
  };

  *result = &ecdsa_key;
  return 0;
}

int
verify_ecdsa_key(struct dtls_context_t *ctx,
		 const session_t *session,
		 const unsigned char *other_pub_x,
		 const unsigned char *other_pub_y,
		 size_t key_size) {
  return 0;
}
#else

int dtls_get_ecdsa_ca(struct dtls_context_t *ctx, const session_t *session,
                             const unsigned char **ca_pub_x, const unsigned char **ca_pub_y)
{
	*ca_pub_x = ecdsa_ca_pub_x;
	*ca_pub_y = ecdsa_ca_pub_y;

	return 0;
}

int dtls_verify_ecdsa_cert(struct dtls_context_t *ctx, const session_t *session,
                                  const unsigned char *cert, size_t cert_size)
{
  return 0;
}

#endif
#endif /* DTLS_ECC */

static void
dtls_handle_read(dtls_context_t *ctx) {
  static session_t session;

  if(uip_newdata()) {
    uip_ipaddr_copy(&session.addr, &UIP_IP_BUF->srcipaddr);
    session.port = UIP_UDP_BUF->srcport;
    session.size = sizeof(session.addr) + sizeof(session.port);

    ((char *)uip_appdata)[uip_datalen()] = 0;
    //TODO debug incoming packet commented
    PRINTF("Client received message from ");
    PRINT6ADDR(&session.addr);
    PRINTF(":%d\n", uip_ntohs(session.port));
    dtls_handle_message(ctx, &session, uip_appdata, uip_datalen());
  }
}

//static void
//set_connection_address(uip_ipaddr_t *ipaddr)
//{
//#define _QUOTEME(x) #x
//#define QUOTEME(x) _QUOTEME(x)
//#ifdef UDP_CONNECTION_ADDR
//  if(uiplib_ipaddrconv(QUOTEME(UDP_CONNECTION_ADDR), ipaddr) == 0) {
//    PRINTF("UDP client failed to parse address '%s'\n", QUOTEME(UDP_CONNECTION_ADDR));
//  }
//#elif UIP_CONF_ROUTER
//  /* todo Set IPv6 address of the DTLS UDP server accordingly. */
//  /* 2001:bbbb:dddd:0:d04d:e1d3:4fad:97b8 */
//  //uip_ip6addr(ipaddr,0x2001,0xbbbb,0xdddd,0,0xd04d,0xe1d3,0x4fad,0x97b8);
//
//  //uip_ip6addr(ipaddr,0xfe80,0,0,0,0xba27,0xebff,0xfe24,0xb98d);
//  uip_ip6addr(ipaddr,0x2001,0xbbbb,0xdddd,0,0xba27,0xebff,0xfe24,0xb98d);
//  //uip_ip6addr(ipaddr,0xfe80,0,0,0,0x0250,0xc2ff,0xfea8,0x00FF);
//
//
//#else
//  uip_ip6addr(ipaddr,0xfe80,0,0,0,0x6466,0x6666,0x6666,0x6666);
//#endif /* UDP_CONNECTION_ADDR */
//}

//void
//init_dtls(session_t *dst) {
//  static dtls_handler_t cb = {
//    .write = send_to_peer,
//    .read  = read_from_peer,
//    .event = NULL,
//#ifdef DTLS_PSK
//    .get_psk_info = get_psk_info,
//#endif /* DTLS_PSK */
//#ifdef DTLS_ECC
//#ifndef DTLS_X509
//    .get_ecdsa_key = get_ecdsa_key,
//    .verify_ecdsa_key = verify_ecdsa_key
//#else
//	.get_ecdsa_ca = dtls_get_ecdsa_ca,
//	.verify_ecdsa_cert = dtls_verify_ecdsa_cert
//#endif
//
//#endif /* DTLS_ECC */
//  };

//  dst->size = sizeof(dst->addr) + sizeof(dst->port);
//  /* todo set port address as needed */
//  dst->port = UIP_HTONS(1885);

  // Set the connection address to a predefined address
//  set_connection_address(&dst->addr);
////  client_conn = udp_new(&dst->addr, 0, NULL);
//
////  udp_bind(client_conn, dst->port);
//
//  PRINTF("set connection address to ");
//  PRINT6ADDR(&dst->addr);
//  PRINTF(":%d\n", uip_ntohs(dst->port));
//
//  /* set the pointer to the udp-socket */
//  //TODO LW pst_udp_socket = &st_udp_socket;
//
//  /* new connection with remote host */
// /* udp_socket_register(pst_udp_socket, NULL, (udp_socket_input_callback_t)dtls_udp_callback);
//  udp_socket_bind(pst_udp_socket, 1885);
//  PRINTF("Listening on port %u\n", uip_ntohs(pst_udp_socket->udp_conn->lport));
//*/
//
//  dtls_set_log_level(DTLS_LOG_DEBUG);
//
//  //TODO LW dtls_context = dtls_new_context(pst_udp_socket);
//  if (dtls_context)
//    dtls_set_handler(dtls_context, &cb);
//}

/*==============================================================================
                                 API FUNCTIONS
 =============================================================================*/

/*==============================================================================
 demo_dtlsInit()
==============================================================================*/

//int8_t demo_dtlsInit(void)
//{
//	dtls_init();
//
//	init_dtls(&dst);
//
//	if (!dtls_context) {
//		dtls_emerg("cannot create context\n");
//	}
//
//	if (!connected)
//	{
//		connected = dtls_connect(dtls_context, &dst) >= 0;
//	}
//
////	evproc_regCallback(EVENT_TYPE_TCPIP, dtls_udp_callback);
//
//	etimer_set(&et, 15 * bsp_get(E_BSP_GET_TRES), try_send);
//
//	return 1;
//}


static void dtls_udp_callback(void)
{
//	if(c_event == EVENT_TYPE_TCPIP) {
		dtls_handle_read(dtls_context);
//	} else if(connected && c_event == EVENT_TYPE_TIMER_EXP) {
//		try_send(dtls_context, &dst);
//	}
}

/*==============================================================================
 demo_dtlsConf()
==============================================================================*/

//uint8_t demo_dtlsConf(s_ns_t* pst_netStack)
//{
//	uint8_t c_ret = 1;	/*
//	 * By default stack
//	 */
//    if (pst_netStack != NULL) {
//        if (!pst_netStack->c_configured) {
//            pst_netStack->hc     = &sicslowpan_driver;
//            pst_netStack->llsec   = &nullsec_driver;
//            pst_netStack->hmac   = &nullmac_driver;
//            pst_netStack->lmac   = &sicslowmac_driver;
//            pst_netStack->frame  = &framer_802154;
//            pst_netStack->c_configured = 1;
//            /* Transceiver interface is defined by @ref board_conf function*/
//            /*pst_netStack->inif   = $<some_transceiver>;*/
//        } else {
//            if ((pst_netStack->hc == &sicslowpan_driver)   &&
//                (pst_netStack->llsec == &nullsec_driver)   &&
//                (pst_netStack->hmac == &nullmac_driver)    &&
//                (pst_netStack->lmac == &sicslowmac_driver) &&
//                (pst_netStack->frame == &framer_802154)) {
//                /* right configuration */
//            }
//            else {
//                c_ret = 0;
//            }
//        }
//    }
//    return (c_ret);
//}

/** @} */
/** @} */
/** @} */
/** @} */
