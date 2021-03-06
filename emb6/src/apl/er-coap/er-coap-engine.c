/*
 * Copyright (c) 2013, Institute for Pervasive Computing, ETH Zurich
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 */

/**
 * \file
 *      CoAP implementation for the REST Engine.
 * \author
 *      Matthias Kovatsch <kovatsch@inf.ethz.ch>
 *      Peter Lehmann <peter.lehmann@hs-offenburg.de>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "er-coap-engine.h"

#define DEBUG DEBUG_NONE
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#define PRINT6ADDR(addr) PRINTF("[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]", ((uint8_t *)addr)[0], ((uint8_t *)addr)[1], ((uint8_t *)addr)[2], ((uint8_t *)addr)[3], ((uint8_t *)addr)[4], ((uint8_t *)addr)[5], ((uint8_t *)addr)[6], ((uint8_t *)addr)[7], ((uint8_t *)addr)[8], ((uint8_t *)addr)[9], ((uint8_t *)addr)[10], ((uint8_t *)addr)[11], ((uint8_t *)addr)[12], ((uint8_t *)addr)[13], ((uint8_t *)addr)[14], ((uint8_t *)addr)[15])
#define PRINTLLADDR(lladdr) PRINTF("[%02x:%02x:%02x:%02x:%02x:%02x]", (lladdr)->addr[0], (lladdr)->addr[1], (lladdr)->addr[2], (lladdr)->addr[3], (lladdr)->addr[4], (lladdr)->addr[5])
#else
#define PRINTF(...)
#define PRINT6ADDR(addr)
#define PRINTLLADDR(addr)
#endif

/*==============================================================================
                          LOCAL VARIABLE DECLARATIONS
 =============================================================================*/

static service_callback_t service_cbk = NULL;
static struct request_state_t request_state;

/*==============================================================================
                               LOCAL FUNCTION PROTOTYPES
 =============================================================================*/

void _coap_nonblocking_request_task(struct request_state_t *state);
void _coap_nonblocking_request_start(struct request_state_t *state);

/*==============================================================================
                                LOCAL FUNCTIONS
 =============================================================================*/

static int
coap_receive(void)
{
  erbium_status_code = NO_ERROR;

  PRINTF("handle_incoming_data(): received uip_datalen=%u \n\r",
         (uint16_t)uip_datalen());

  /* static declaration reduces stack peaks and program code size */
  static coap_packet_t message[1]; /* this way the packet can be treated as pointer as usual */
  static coap_packet_t response[1];
  static coap_transaction_t *transaction = NULL;

  if(uip_newdata()) {

    PRINTF("receiving UDP datagram from: ");
    PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
    PRINTF(":%u\n\r  Length: %u\n\r", uip_ntohs(UIP_UDP_BUF->srcport),
           uip_datalen());

    erbium_status_code =
      coap_parse_message(message, uip_appdata, uip_datalen());

    if(erbium_status_code == NO_ERROR) {

      /*TODO duplicates suppression, if required by application */

      PRINTF("  Parsed: v %u, t %u, tkl %u, c %u, mid %u\n\r", message->version,
             message->type, message->token_len, message->code, message->mid);
      PRINTF("  URL: %d|%s\n\r", message->uri_path_len, message->uri_path);
      PRINTF("  Payload: %d|%s\n\r", message->payload_len, message->payload);

      /* handle requests */
      if(message->code >= COAP_GET && message->code <= COAP_DELETE) {

        /* use transaction buffer for response to confirmable request */
        if((transaction =
              coap_new_transaction(message->mid, &UIP_IP_BUF->srcipaddr,
                                   UIP_UDP_BUF->srcport))) {
          uint32_t block_num = 0;
          uint16_t block_size = REST_MAX_CHUNK_SIZE;
          uint32_t block_offset = 0;
          int32_t new_offset = 0;

          /* prepare response */
          if(message->type == COAP_TYPE_CON) {
            /* reliable CON requests are answered with an ACK */
            coap_init_message(response, COAP_TYPE_ACK, CONTENT_2_05,
                              message->mid);
          } else {
            /* unreliable NON requests are answered with a NON as well */
            coap_init_message(response, COAP_TYPE_NON, CONTENT_2_05,
                              coap_get_mid());
            /* mirror token */
          } if(message->token_len) {
            coap_set_token(response, message->token, message->token_len);
            /* get offset for blockwise transfers */
          }
          if(coap_get_header_block2
               (message, &block_num, NULL, &block_size, &block_offset)) {
            PRINTF("\rBlockwise: block request %lu (%u/%u) @ %lu bytes\n\r",
                   block_num, block_size, REST_MAX_CHUNK_SIZE, block_offset);
            block_size = MIN(block_size, REST_MAX_CHUNK_SIZE);
            new_offset = block_offset;
          }

          /* invoke resource handler */
          if(service_cbk) {

            /* call REST framework and check if found and allowed */
            if(service_cbk
                 (message, response, transaction->packet + COAP_MAX_HEADER_SIZE,
                 block_size, &new_offset)) {

              if(erbium_status_code == NO_ERROR) {

                /* TODO coap_handle_blockwise(request, response, start_offset, end_offset); */

                /* resource is unaware of Block1 */
                if(IS_OPTION(message, COAP_OPTION_BLOCK1)
                   && response->code < BAD_REQUEST_4_00
                   && !IS_OPTION(response, COAP_OPTION_BLOCK1)) {
                  PRINTF("Block1 NOT IMPLEMENTED\n\r");

                  erbium_status_code = NOT_IMPLEMENTED_5_01;
                  coap_error_message = "NoBlock1Support";

                  /* client requested Block2 transfer */
                } else if(IS_OPTION(message, COAP_OPTION_BLOCK2)) {

                  /* unchanged new_offset indicates that resource is unaware of blockwise transfer */
                  if(new_offset == block_offset) {
                    PRINTF
                      ("Blockwise: unaware resource with payload length %u/%u\n\r",
                      response->payload_len, block_size);
                    if(block_offset >= response->payload_len) {
                      PRINTF
                        ("handle_incoming_data(): block_offset >= response->payload_len\n\r");

                      response->code = BAD_OPTION_4_02;
                      coap_set_payload(response, "BlockOutOfScope", 15); /* a const char str[] and sizeof(str) produces larger code size */
                    } else {
                      coap_set_header_block2(response, block_num,
                                             response->payload_len -
                                             block_offset > block_size,
                                             block_size);
                      coap_set_payload(response,
                                       response->payload + block_offset,
                                       MIN(response->payload_len -
                                           block_offset, block_size));
                    } /* if(valid offset) */

                    /* resource provides chunk-wise data */
                  } else {
                    PRINTF("Blockwise: blockwise resource, new offset %ld\n\r",
                           new_offset);
                    coap_set_header_block2(response, block_num,
                                           new_offset != -1
                                           || response->payload_len >
                                           block_size, block_size);

                    if(response->payload_len > block_size) {
                      coap_set_payload(response, response->payload,
                                       block_size);
                    }
                  } /* if(resource aware of blockwise) */

                  /* Resource requested Block2 transfer */
                } else if(new_offset != 0) {
                  PRINTF
                    ("Blockwise: no block option for blockwise resource, using block size %u\n\r",
                    COAP_MAX_BLOCK_SIZE);

                  coap_set_header_block2(response, 0, new_offset != -1,
                                         COAP_MAX_BLOCK_SIZE);
                  coap_set_payload(response, response->payload,
                                   MIN(response->payload_len,
                                       COAP_MAX_BLOCK_SIZE));
                } /* blockwise transfer handling */
              } /* no errors/hooks */
                /* successful service callback */
                /* serialize response */
            }
            if(erbium_status_code == NO_ERROR) {
              if((transaction->packet_len = coap_serialize_message(response,
                                                                   transaction->
                                                                   packet)) ==
                 0) {
                erbium_status_code = PACKET_SERIALIZATION_ERROR;
              }
            }
          } else {
            erbium_status_code = NOT_IMPLEMENTED_5_01;
            coap_error_message = "NoServiceCallbck"; /* no 'a' to fit into 16 bytes */
          } /* if(service callback) */
        } else {
          erbium_status_code = SERVICE_UNAVAILABLE_5_03;
          coap_error_message = "NoFreeTraBuffer";
        } /* if(transaction buffer) */

        /* handle responses */
      } else {

        if(message->type == COAP_TYPE_CON && message->code == 0) {
          PRINTF("Received Ping\n\r");
          erbium_status_code = PING_RESPONSE;
        } else if(message->type == COAP_TYPE_ACK) {
          /* transactions are closed through lookup below */
          PRINTF("Received ACK\n\r");
        } else if(message->type == COAP_TYPE_RST) {
          PRINTF("Received RST\n\r");
          /* cancel possible subscriptions */
          coap_remove_observer_by_mid(&UIP_IP_BUF->srcipaddr,
                                      UIP_UDP_BUF->srcport, message->mid);
        }

        if((transaction = coap_get_transaction_by_mid(message->mid))) {
          /* free transaction memory before callback, as it may create a new transaction */
          restful_response_handler callback = transaction->callback;
          void *callback_data = transaction->callback_data;

          coap_clear_transaction(transaction);

          /* check if someone registered for the response */
          if(callback) {
            callback(callback_data, message);
          }
        }
        /* if(ACKed transaction) */
        transaction = NULL;
      } /* request or response */
    } /* parsed correctly */

    /* if(parsed correctly) */
    if(erbium_status_code == NO_ERROR) {
      if(transaction) {
        coap_send_transaction(transaction);
      }
    } else if(erbium_status_code == MANUAL_RESPONSE) {
      PRINTF("Clearing transaction for manual response\n\r");
      coap_clear_transaction(transaction);
    } else {
      coap_message_type_t reply_type = COAP_TYPE_ACK;

      PRINTF("ERROR %u: %s\n\r", erbium_status_code, coap_error_message);
      coap_clear_transaction(transaction);

      if(erbium_status_code == PING_RESPONSE) {
        erbium_status_code = 0;
        reply_type = COAP_TYPE_RST;
      } else if(erbium_status_code >= 192) {
        /* set to sendable error code */
        erbium_status_code = INTERNAL_SERVER_ERROR_5_00;
        /* reuse input buffer for error message */
      }
      coap_init_message(message, reply_type, erbium_status_code,
                        message->mid);
      coap_set_payload(message, coap_error_message,
                       strlen(coap_error_message));
      coap_send_message(&UIP_IP_BUF->srcipaddr, UIP_UDP_BUF->srcport,
                        uip_appdata, coap_serialize_message(message,
                                                            uip_appdata));
    }
  }

  /* if(new data) */
  return erbium_status_code;
}
/*---------------------------------------------------------------------------*/
void
coap_set_service_callback(service_callback_t callback)
{
  service_cbk = callback;
}
/*---------------------------------------------------------------------------*/
rest_resource_flags_t
coap_get_rest_method(void *packet)
{
  return (rest_resource_flags_t)(1 <<
                                 (((coap_packet_t *)packet)->code - 1));
}
/*---------------------------------------------------------------------------*/
/*- Server Part -------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/

/* the discover resource is automatically included for CoAP */
extern resource_t res_well_known_core;
#ifdef WITH_DTLS
extern resource_t res_dtls;
#endif

void 
coap_init_engine(void)
{
  PRINTF("Starting %s receiver...\n\r", coap_rest_implementation.name);
  rest_activate_resource(&res_well_known_core, ".well-known/core");

  coap_init_connection(SERVER_LISTEN_PORT,
                      (udp_socket_input_callback_t)coap_receive);
}
/*---------------------------------------------------------------------------*/
void 
coap_engine_callback(c_event_t c_event, p_data_t p_data)
{
    if(c_event == EVENT_TYPE_TIMER_EXP) {
      /* retransmissions are handled here */
      coap_check_transactions();
    }
}
/*---------------------------------------------------------------------------*/
/*- Client Part -------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
void
coap_nonblocking_request_callback(void *callback_data, void *response)
{
  struct request_state_t *state = (struct request_state_t *)callback_data;

  state->response = (coap_packet_t *)response;

  _coap_nonblocking_request_task(state);
}
/*---------------------------------------------------------------------------*/
void
coap_nonblocking_request(uip_ipaddr_t *remote_ipaddr, uint16_t remote_port,
            coap_packet_t *request,
            nonblocking_response_handler request_callback)
{
      static struct request_state_t *state = &request_state;

      state->block_num = 0;
      state->response = NULL;
      state->more = 0;
      state->res_block = 0;
      state->block_error = 0;
      state->remote_ipaddr = remote_ipaddr;
      state->remote_port = remote_port;
      state->request = request;
      state->request_callback = request_callback;

      _coap_nonblocking_request_start(state);
}
/*---------------------------------------------------------------------------*/
void
_coap_nonblocking_request_start(struct request_state_t *state)
{
    state->request->mid = coap_get_mid();
    if((state->transaction = coap_new_transaction(state->request->mid, state->remote_ipaddr,
            state->remote_port))) {
      state->transaction->callback = coap_nonblocking_request_callback;
      state->transaction->callback_data = state;

      if(state->block_num > 0) {
        coap_set_header_block2(state->request, state->block_num, 0,
                               REST_MAX_CHUNK_SIZE);
      }

      state->transaction->packet_len = coap_serialize_message(state->request, state->transaction->packet);

      coap_send_transaction(state->transaction);
      PRINTF("Requested #%lu (MID %u)\n\r", state->block_num, state->request->mid);
    } else {
          PRINTF("Could not allocate transaction buffer");
    }
}
/*---------------------------------------------------------------------------*/
void
_coap_nonblocking_request_task(struct request_state_t *state)
 {
    if(!state->response) {
        PRINTF("Server not responding\n\r");
        state->request_callback(NULL);
        /* exit request */
        return;
     }

      coap_get_header_block2(state->response, &state->res_block, &state->more, NULL, NULL);
      PRINTF("Received #%lu%s (%u bytes)\n\r", state->res_block, state->more ? "+" : "",
             state->response->payload_len);

      if(state->res_block == state->block_num) {
        state->request_callback(state->response);
        ++(state->block_num);
      } else {
        PRINTF("WRONG BLOCK %lu/%lu\n", state->res_block, state->block_num);
        ++(state->block_error);
      }

      if(state->more && state->block_error < COAP_MAX_ATTEMPTS) {
          /* request next block */
          _coap_nonblocking_request_start(state);
      }
}

/*---------------------------------------------------------------------------*/
/*- REST Engine Interface ---------------------------------------------------*/
/*---------------------------------------------------------------------------*/
const struct rest_implementation coap_rest_implementation = {
  "CoAP-18",

  coap_init_engine,
  coap_set_service_callback,

  coap_get_header_uri_path,
  coap_get_rest_method,
  coap_set_status_code,

  coap_get_header_content_format,
  coap_set_header_content_format,
  coap_get_header_accept,
  coap_get_header_size2,
  coap_set_header_size2,
  coap_get_header_max_age,
  coap_set_header_max_age,
  coap_set_header_etag,
  coap_get_header_if_match,
  coap_get_header_if_none_match,
  coap_get_header_uri_host,
  coap_set_header_location_path,

  coap_get_payload,
  coap_set_payload,

  coap_get_header_uri_query,
  coap_get_query_variable,
  coap_get_post_variable,

  coap_notify_observers,
  coap_observe_handler,

  {
    CONTENT_2_05,
    CREATED_2_01,
    CHANGED_2_04,
    DELETED_2_02,
    VALID_2_03,
    BAD_REQUEST_4_00,
    UNAUTHORIZED_4_01,
    BAD_OPTION_4_02,
    FORBIDDEN_4_03,
    NOT_FOUND_4_04,
    METHOD_NOT_ALLOWED_4_05,
    NOT_ACCEPTABLE_4_06,
    REQUEST_ENTITY_TOO_LARGE_4_13,
    UNSUPPORTED_MEDIA_TYPE_4_15,
    INTERNAL_SERVER_ERROR_5_00,
    NOT_IMPLEMENTED_5_01,
    BAD_GATEWAY_5_02,
    SERVICE_UNAVAILABLE_5_03,
    GATEWAY_TIMEOUT_5_04,
    PROXYING_NOT_SUPPORTED_5_05
  },

  {
    TEXT_PLAIN,
    TEXT_XML,
    TEXT_CSV,
    TEXT_HTML,
    IMAGE_GIF,
    IMAGE_JPEG,
    IMAGE_PNG,
    IMAGE_TIFF,
    AUDIO_RAW,
    VIDEO_RAW,
    APPLICATION_LINK_FORMAT,
    APPLICATION_XML,
    APPLICATION_OCTET_STREAM,
    APPLICATION_RDF_XML,
    APPLICATION_SOAP_XML,
    APPLICATION_ATOM_XML,
    APPLICATION_XMPP_XML,
    APPLICATION_EXI,
    APPLICATION_FASTINFOSET,
    APPLICATION_SOAP_FASTINFOSET,
    APPLICATION_JSON,
    APPLICATION_X_OBIX_BINARY
  }
};
/*---------------------------------------------------------------------------*/
