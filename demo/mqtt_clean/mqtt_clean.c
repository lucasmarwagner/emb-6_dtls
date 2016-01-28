/**
 * 	 \addtogroup embetter6
 * 	 @{
 * 	 \addtogroup demo
 * 	 @{
 * 	 \addtogroup demo_mqtt
 * 	 @{
*/
/*============================================================================*/
/*! \file   demo_mqtt_qos0.c

    \author Peter Lehmann, peter.lehmann@hs-offenburg.de

    \brief  This is the source file of the demo MQTT client

    \version 0.0.1
 */
/*============================================================================*/

/*==============================================================================
 INCLUDE FILES
 =============================================================================*/

#include "emb6.h"
#include "bsp.h"
#include "MQTTSNPacket.h"
#include "etimer.h"
#include "evproc.h"
#include "tcpip.h"
#include "uip.h"
#include "uiplib.h"
#include "uip-udp-packet.h"
#include "mqtt_clean.h"
#include "board_conf.h"
#include "rpl.h"

#include "demo_dtls_cli.h"
#include "dtls.h"
#include "uip-debug.h"
#include "debug.h"

/*==============================================================================
 	 	 	 	 	 	 	 	 MACROS
 =============================================================================*/

/** MQTT-SN Communication port */
/** Normal : 1884 | Secured : 1885 */
#define 	MQTTSN_PORT 			1885
/** If MQTTSN_PORT is a secured port the following line must be uncommented */
#define DTLS 1

/** Bootstrap Server Communication port */
#define 	BOOTSTRAP_PORT 			3033
/** Delay for starting mqtt engine */
#define 	START_DELAY				10
/** Delay for retransmissions */
#define 	TIMEOUT_DELAY			5
/** retransmission counter */
#define 	MQTT_RETRANSMISSIONS	3
/** call interval in seconds of mqtt timer callback */
#define 	RUN_INTERVAL			1
/** PING SETTINGS */
#define		PING_INTERVAL			30
#define		PING_ENABLE				TRUE
/** Maximum topic count */
#define MAX_TOPIC_COUNT 			50
/** Buffer Length */
#define BUF_LEN						200

#if USE_BOOTSTRAP_SERVER == 0
/** Define a network prefix for all addresses */
#define NETWORK_PREFIX						0x2001, 0xbbbb, 0xdddd, 0x0000 //0x2001, 0xbbbb, 0xdddd, 0x0000 // PL
/** RSMB IPv6 address */
#define SERVER_IP_ADDR_8_0					0xba27, 0xebff, 0xfe24, 0xb98d // lw

#define SERVER_IP_ADDR						NETWORK_PREFIX,SERVER_IP_ADDR_8_0
#endif


extern void dtls_retransmit_process();
/*==============================================================================
 	 	 	 	 	 	 	 	 ENUMS
 =============================================================================*/

enum topic_status {
	STATUS_INACTIVE,
	STATUS_ACTIVE,
	STATUS_REGISTERED,
	STATUS_SUBSCRIBED
};

enum mqtt_state {
	MQTT_STOP,
	MQTT_BOOTSTRAP,
	MQTT_CONNECT,
	MQTT_RUN,
	MQTT_PING,
	MQTT_DTLS_HANDSHAKE
};

/*==============================================================================
 	 	 	 	 	 STRUCTURES AND OTHER TYPEDEFS
 =============================================================================*/
struct 	etimer 			mq_et;
static struct 	uip_udp_conn 	*pst_conn = NULL;

#if USE_BOOTSTRAP_SERVER
static			uip_ipaddr_t 	un_server_ipaddr, bootstrap_ipaddr;
#else
static			uip_ipaddr_t 	un_server_ipaddr = {					  \
													.u16={SERVER_IP_ADDR} \
													};
#endif

static mqtt_topic_t topic_db[MAX_TOPIC_COUNT];
static char devicename_str[] = "x0000";

/*==============================================================================
 	 	 	 	 	 LOCAL VARIABLE DECLARATIONS
 =============================================================================*/

static uint8_t mqtt_state = 0;
static uint8_t buf[BUF_LEN];
static uint8_t *p_buf;
static int16_t mqtt_len = 0;
static uint32_t packetid = 0;
static uint8_t mqtt_ping_count = 0;

#ifdef DTLS
extern session_t dst;
extern dtls_context_t* dtls_context;
#endif

MQTTSNPacket_connectData options = MQTTSNPacket_connectData_initializer;

/*==============================================================================
 	 	 	 	 	 	 	 LOCAL CONSTANTS
 =============================================================================*/

/*==============================================================================
 	 	 	 	 	 	 LOCAL FUNCTION PROTOTYPES
 =============================================================================*/
void mqtt_sendpacket(void);
#ifdef DTLS
#ifdef DTLS_PSK
	extern int get_psk_info(struct dtls_context_t *ctx,const session_t *session, dtls_credentials_type_t type, const unsigned char *desc, size_t desc_len, unsigned char *result, size_t result_length);
#endif /* DTLS_PSK */
#ifdef DTLS_ECC
#ifndef DTLS_X509
	extern int get_ecdsa_key();
	extern int verify_ecdsa_key();
#else
	extern int dtls_get_ecdsa_ca();
	extern int dtls_verify_ecdsa_cert();
#endif
#endif
#endif

/*==============================================================================
 	 	 	 	 	 	 	 LOCAL FUNCTIONS
 =============================================================================*/

int8_t mqtt_add_topic (char *topicname, uint8_t sub_or_pub, uint16_t interval,
						int8_t qos, int8_t retained, void* callback)
{
	if (mqtt_state == MQTT_STOP)
	{
		return -1;
	}
	mqtt_topic_t * topic = NULL;
	uint8_t i=0;
	for (i=0;i<MAX_TOPIC_COUNT;i++)
	{
		topic = mqtt_get_topic(i);

		if (topic->status == STATUS_INACTIVE)
		{
			if (sub_or_pub == SUBSCRIBE  && callback == NULL)
			{
				/* error no callback for subscriber or ack */
				return -1;
			}
			topic->topicname = topicname;
			topic->topic.type = MQTTSN_TOPIC_TYPE_NORMAL;
			topic->status = STATUS_ACTIVE;
			topic->flags.type = sub_or_pub;
			topic->flags.qos = qos;
			topic->flags.retained = retained;
			topic->response_callback = callback;
			topic->interval = interval;
			return i;
		}
	}
	return -1;
}

int8_t mqtt_remove_topic (int8_t topic_no)
{
	mqtt_topic_t * topic = mqtt_get_topic(topic_no);
	if (topic->status != STATUS_INACTIVE)
	{
		if (topic->flags.type== SUBSCRIBE)
		{
			/* unsubscribe topic */
			topic->flags.packetid = ++packetid;
			mqtt_len = MQTTSNSerialize_unsubscribe(buf, BUF_LEN,
					topic->flags.packetid, &topic->topic);
			mqtt_sendpacket();
			return 1;
		}
		topic->status = STATUS_INACTIVE;
		topic->topic.data.id = 0;
		return 1;
	}
	return 0;
}

uint8_t mqtt_publish_topic (uint8_t topic_no)
{
	mqtt_topic_t * topic_pub = mqtt_get_topic(topic_no);

	if (topic_pub->status == STATUS_REGISTERED && topic_pub->flags.type == PUBLISH)
	{
		topic_pub->flags.packetid = ++packetid;
		if (topic_pub->flags.qos > 0)
		{
			topic_pub->timeout = TIMEOUT_DELAY;
		}
		mqtt_len = MQTTSNSerialize_publish(buf, BUF_LEN, topic_pub->flags.dup,
				topic_pub->flags.qos, topic_pub->flags.retained, topic_pub->flags.packetid,
				topic_pub->topic, topic_pub->payload, topic_pub->payloadlen);
		mqtt_sendpacket();
		topic_pub->last_interval = bsp_getSec();
		bsp_delay_us(5000);
		return 1;
	}
	return 0;
}

uint8_t mqtt_register_subscribe_topic (mqtt_topic_t* topic)
{
	uint8_t rc = 0;
	MQTTSNString topicstr;
	if (topic->status == STATUS_ACTIVE)
	{
		if  (topic->flags.type == PUBLISH)
		{
			topic->flags.packetid = ++packetid;
			topic->last_interval = bsp_getSec();
			topicstr.cstring = topic->topicname;
			topicstr.lenstring.len = strlen(topic->topicname);
			mqtt_len = MQTTSNSerialize_register(buf, BUF_LEN, 0,
										topic->flags.packetid, &topicstr);
			rc = 1;
		} else
			if (topic->flags.type == SUBSCRIBE)
			{
				topic->flags.packetid = ++packetid;
				topic->topic.data.long_.name = topic->topicname;
				topic->topic.data.long_.len = strlen(topic->topicname);
				mqtt_len = MQTTSNSerialize_subscribe(buf, BUF_LEN, 0, topic->flags.qos,
											topic->flags.packetid, &topic->topic);
				rc = 1;
			}
		mqtt_sendpacket();
	}
	return rc;
}



/*----------------------------------------------------------------------------*/
/** \brief  This function is called whenever a timer expired.
 *
 *  \param  event 	Event type
 *  \param	data	Pointer to data
 *
 *  \returns none
 */

static void _demo_mqtt_timercallback(c_event_t c_event, p_data_t p_data)
{
	if (etimer_expired(&mq_et)) {
		switch (mqtt_state)
		{
			case MQTT_BOOTSTRAP:
			{
#if USE_BOOTSTRAP_SERVER
				/* connect to bootstrap server */
				rpl_dag_t* dodag = rpl_get_any_dag();
				for (uint8_t i=0;i<8;i++)
				{
					bootstrap_ipaddr.u8[i] = dodag->prefix_info.prefix.u8[i];
					bootstrap_ipaddr.u8[i+8] = dodag->dag_id.u8[i+8];
				}
				char* buffer = {"["};
				mqtt_len = strlen(buffer);
				uip_udp_packet_sendto(pst_conn, buffer, mqtt_len, &bootstrap_ipaddr, UIP_HTONS(BOOTSTRAP_PORT));
#endif
				break;
			}
			case MQTT_DTLS_HANDSHAKE:
			{
#ifdef DTLS
				dtls_peer_t *peer = dtls_get_peer(dtls_context, &dst);
				if(peer)
				{
					if(peer->state == DTLS_STATE_CONNECTED)
					{
						mqtt_state = MQTT_CONNECT;
						break;
					}
				}
				dtls_connect(dtls_context,&dst);
				//dtls_retransmit_process(dtls_context);
#endif
				break;
			}
			case MQTT_CONNECT:
			{
				mqtt_topic_t * topic = NULL;
				uint8_t i=0;
				for (i=0;i<MAX_TOPIC_COUNT;i++)
				{
					topic = mqtt_get_topic(i);

					if (topic->status >= 2) //REGISTRED OR SUBSCRIBED
					{
						topic->status = STATUS_ACTIVE;
					}
				}
				options.clientID.cstring = devicename_str;
				mqtt_len = MQTTSNSerialize_connect(buf, BUF_LEN, &options);
#ifdef DTLS
				dtls_write(dtls_context,&dst,buf,mqtt_len);
				// Must encrypt the buffer 'buf' before sending the packet
#else
				mqtt_sendpacket();
#endif
				etimer_set(&mq_et, TIMEOUT_DELAY * bsp_get(E_BSP_GET_TRES), _demo_mqtt_timercallback);
				break;
			}
			case MQTT_RUN:
			{
				mqtt_topic_t * topic = NULL;
				uint8_t i;
#if PING_ENABLE
				mqtt_ping_count++;
				if (mqtt_ping_count == PING_INTERVAL) {
					mqtt_state = MQTT_PING;
					break;
				} else if (mqtt_ping_count > (PING_INTERVAL * 4))
				{
					mqtt_ping_count = 0;
					mqtt_state = MQTT_CONNECT;
					break;
				}
#endif
				/* register, publish or subscribe a topic */
				for (i=0;i<MAX_TOPIC_COUNT;i++)
				{
					topic = mqtt_get_topic(i);
					/* register/subscribe topic name if not registered */
					 if (mqtt_register_subscribe_topic(topic))
					 {
						 break;
					 }
					if (topic->interval > 0) {
						if (bsp_getSec() > (topic->last_interval + topic->interval)) {
							/* publish with obtained id */
							topic->payload = "132456";
							topic->payloadlen = 6;
							mqtt_publish_topic(i);
						}
					}
					if (topic->timeout > 0)	{
						if (bsp_getSec() > (topic->last_interval + topic->timeout) &&
								topic->retrans_counter < MQTT_RETRANSMISSIONS)	{
							topic->retrans_counter++;
							topic->flags.dup = 1;
							/* timeout: publish again with obtained id */
							mqtt_publish_topic(i);
						} else	{
								topic->retrans_counter = 0;
								topic->timeout = 0;
								topic->flags.dup = 0;
							}
					}
				}
				break;
			}
#if PING_ENABLE
			case MQTT_PING:
			{
				/* ping rsmb */
				mqtt_len = MQTTSNSerialize_pingreq(buf, BUF_LEN, options.clientID);
				mqtt_sendpacket();
				mqtt_state = MQTT_RUN;
				break;
			}
#endif
			default:
			{
				break;
			}
		}
		etimer_restart(&mq_et);
	}
}

#if USE_BOOTSTRAP_SERVER
uint8_t _parse_ip_address (uint8_t* ip_buf)
{
	if (uiplib_ipaddrconv((char*)ip_buf, &un_server_ipaddr))
	{
		return MQTT_CONNECT;
		//return MQTT_PING;
	}
	return MQTT_BOOTSTRAP;
}
#endif

static void _demo_mqtt_callback(c_event_t c_event, p_data_t p_data)
{
	if (c_event == EVENT_TYPE_TCPIP) {

		if (uip_newdata()) {
			((char *)uip_appdata)[uip_datalen()] = 0;
#ifdef DTLS
			dtls_handle_message(dtls_context, &dst, uip_appdata, uip_datalen());
			p_buf = dtls_context->readbuf;
			mqtt_len = dtls_context->decrypted_length;
#else
			//Read the application data from the incoming packet
			p_buf = uip_appdata;
			mqtt_len = uip_datalen();
#endif


#if USE_BOOTSTRAP_SERVER
			if (p_buf[0] == '[' && mqtt_state == MQTT_BOOTSTRAP)
			{
				mqtt_state = _parse_ip_address(p_buf);
				return;
			}
#endif
			switch (MQTTSNPacket_read(p_buf, mqtt_len, NULL))
			{
				/* get ping response */
				case MQTTSN_PINGRESP:
				{
					if (MQTTSNDeserialize_pingresp(p_buf, mqtt_len))
					{
						mqtt_ping_count = 0;
					}
					break;
				}
				/* get connect acknowledgment */
				case MQTTSN_CONNACK:
				{
					int connack_rc = -1;
					if (MQTTSNDeserialize_connack(&connack_rc, p_buf, mqtt_len) != 1 || connack_rc != 0)
					{
						/* unable to connect, do nothing and try again */
					} else {
						/* connected! */
						/* register first topic */
						mqtt_register_subscribe_topic(mqtt_get_topic(0));
						mqtt_state = MQTT_RUN;
						etimer_set(&mq_et, RUN_INTERVAL * bsp_get(E_BSP_GET_TRES), _demo_mqtt_timercallback);
					}
					break;
				}
				/* get register acknowledgment */
				case MQTTSN_REGACK:
				{
					unsigned short submsgid, topicid;
					unsigned char returncode;

					MQTTSNDeserialize_regack(&topicid, &submsgid, &returncode, p_buf, mqtt_len);
					if (returncode != 0)
					{
						/* register error, do nothing and try again */
					} else {
						/* topic successful registered */
						mqtt_topic_t * topic = NULL;
						uint8_t i=0;
						for (i=0;i<MAX_TOPIC_COUNT;i++)
						{
							topic = mqtt_get_topic(i);
							if (topic->flags.packetid == submsgid && topic->status  == STATUS_ACTIVE)
							{
								/* save corresponding topic id */
								topic->topic.data.id = topicid;
								topic->status = STATUS_REGISTERED;
								/* register next topic */
								mqtt_register_subscribe_topic(mqtt_get_topic(i+1));
								break;
							}
						}
					}
					break;
				}
				/* get register for new topic */
				case MQTTSN_REGISTER:
				{
					unsigned short submsgid, topicid;
					unsigned char rc = MQTTSN_RC_REJECTED_CONGESTED;
					MQTTSNString topicname;
					if (MQTTSNDeserialize_register(&topicid, &submsgid, &topicname, p_buf, mqtt_len))
					{
						mqtt_topic_t * topic = NULL;
						uint8_t i=0;
						for (i=0;i<MAX_TOPIC_COUNT;i++)
						{
							topic = mqtt_get_topic(i);
							if (topic->status == STATUS_INACTIVE)
							{
								topic->topic.data.id = topicid;
								topic->flags.type = SUBSCRIBE;
								topic->payloadlen = topicname.lenstring.len;
								topic->topicname = (char*)malloc(topicname.lenstring.len * sizeof(char));
								strncpy(topic->topicname, topicname.lenstring.data, topicname.lenstring.len);
								char* end;
								end = topic->topicname + (topicname.lenstring.len * sizeof(char));
								*end = '\0';
								topic->topic.type = MQTTSN_TOPIC_TYPE_NORMAL;
								topic->status = STATUS_ACTIVE;
								mqtt_topic_t * subtopic = NULL;
								uint8_t j=0;
								for (j=0;i<MAX_TOPIC_COUNT;j++)
								{
									subtopic = mqtt_get_topic(j);
									if (subtopic->status == STATUS_SUBSCRIBED && subtopic->topic.data.id == 0)
									{
										topic->response_callback = subtopic->response_callback;
										rc = MQTTSN_RC_ACCEPTED;
										break;
									}
								}
								break;
							}
						}
					}
					bsp_delay_us(5000);
					mqtt_len = MQTTSNSerialize_regack(buf, BUF_LEN, topicid, submsgid, rc);
					mqtt_sendpacket();
					break;
				}
				/* get publish acknowledgment */
				case MQTTSN_PUBACK:
				{
					unsigned short packet_id, topic_id;
					unsigned char returncode;

					if (MQTTSNDeserialize_puback(&topic_id, &packet_id,
							&returncode, p_buf, mqtt_len) != 1 || returncode != MQTTSN_RC_ACCEPTED)
					{
						/* puback error */
					}
					else
					{
						mqtt_topic_t* topic = NULL;
						uint8_t i=0;
						for (i=0;i<MAX_TOPIC_COUNT;i++)
						{
							topic = mqtt_get_topic(i);
							if (topic->flags.packetid == packet_id && topic->status  == STATUS_REGISTERED)
							{
								topic->timeout = 0;
								if (topic->response_callback != NULL)
								{
									topic->response_callback(topic);
									break;
								}
								break;
							}
						}
					}
					break;
				}
				/* get subscribe acknowledgment */
				case MQTTSN_SUBACK:
				{
					unsigned short submsgid, subtopicid;
					int granted_qos;
					unsigned char returncode;

					MQTTSNDeserialize_suback(&granted_qos, &subtopicid,
							&submsgid, &returncode, p_buf, mqtt_len);
					mqtt_topic_t * topic = NULL;
					uint8_t i=0;
					for (i=0;i<MAX_TOPIC_COUNT;i++)
					{
						topic = mqtt_get_topic(i);
						if (topic->flags.packetid == submsgid && topic->flags.type == SUBSCRIBE)
						{
							/* save corresponding topic id */
							topic->topic.data.id = subtopicid;
							topic->status = STATUS_SUBSCRIBED;
							break;
						}
					}
					break;
				}
				/* get unsubscribe acknowledgment */
				case MQTTSN_UNSUBACK:
				{
					unsigned short submsgid;
					MQTTSNDeserialize_unsuback(&submsgid, p_buf, mqtt_len);
					mqtt_topic_t * topic = NULL;
					uint8_t i=0;
					for (i=0;i<MAX_TOPIC_COUNT;i++)
					{
						topic = mqtt_get_topic(i);
						if (topic->flags.packetid == submsgid && topic->status == SUBSCRIBE)
						{
							topic->status = STATUS_INACTIVE;
							topic->topic.data.id = 0;
							break;
						}
					}
					break;
				}
				/* receive publish */
				case MQTTSN_PUBLISH:
				{
					uint16_t packet_id;
					int qos, payloadlen_sub;
					unsigned char dup, retained;
					unsigned char *payload_sub;

					MQTTSN_topicid pubtopic;

					if (MQTTSNDeserialize_publish(&dup, &qos, &retained, &packet_id, &pubtopic,
							&payload_sub, &payloadlen_sub, p_buf, mqtt_len) != 1)
					{
						/* error */
						mqtt_len = MQTTSNSerialize_puback(buf, BUF_LEN, pubtopic.data.id, packet_id, MQTTSN_RC_REJECTED_CONGESTED);
						mqtt_sendpacket();

					} else {
						mqtt_topic_t * topic = NULL;
						uint8_t i=0;
						for (i=0;i<MAX_TOPIC_COUNT;i++)
						{
							topic = mqtt_get_topic(i);
							if (topic->flags.type == SUBSCRIBE
									&& topic->topic.data.id == pubtopic.data.id)
							{
								/* save payload pointer */
								topic->payloadlen = payloadlen_sub;
								topic->payload = (char*)payload_sub;
								if (qos == 1)
								{
									mqtt_len = MQTTSNSerialize_puback(buf, BUF_LEN, pubtopic.data.id, packet_id, MQTTSN_RC_ACCEPTED);
									mqtt_sendpacket();
								}
								if (topic->response_callback != NULL)
								{
									topic->response_callback(topic);
									break;
								}
							}
						}
					}
					break;
				}
				default:
				{
					break;
				}
			}
		}
	}
}

/*==============================================================================
 	 	 	 	 	 	 	 	 API FUNCTIONS
 =============================================================================*/
uint8_t demo_mqttConf(s_ns_t* pst_netStack)
{
	uint8_t c_ret = 1;

	/*
	 * By default stack
	 */
    if (pst_netStack != NULL) {
    	if (!pst_netStack->c_configured) {
        	pst_netStack->hc     = &sicslowpan_driver;
        	pst_netStack->llsec  = &nullsec_driver;
        	pst_netStack->hmac   = &nullmac_driver;
        	pst_netStack->lmac   = &sicslowmac_driver;
        	pst_netStack->frame  = &framer_802154;
        	pst_netStack->c_configured = 1;
            /* Transceiver interface is defined by @ref board_conf function*/
    	} else {
            if ((pst_netStack->hc == &sicslowpan_driver)   &&
            	(pst_netStack->llsec == &nullsec_driver)   &&
            	(pst_netStack->hmac == &nullmac_driver)    &&
            	(pst_netStack->lmac == &sicslowmac_driver) &&
            	(pst_netStack->frame == &framer_802154)) {
            	/* right configuration */
            }
            else {
                c_ret = 0;
            }
    	}
    }
    return (c_ret);
}

mqtt_topic_t* mqtt_get_topic(uint8_t topic_no)
{
	if (topic_no > MAX_TOPIC_COUNT) {
		return NULL;
	}
	return &topic_db[topic_no];
}

void mqtt_sendpacket(void)
{
#ifdef DTLS
	dtls_write(dtls_context,&dst,buf,mqtt_len);
#else
	uip_udp_packet_sendto(pst_conn, buf, mqtt_len, &un_server_ipaddr, UIP_HTONS(MQTTSN_PORT));
#endif
}

void sub_handler (void *response)
{
	mqtt_topic_t* topic = response;
	//e.g. do something with topic->payload
	int i;
	printf("Incoming packet : ");

	for (i=0;i<(topic->payloadlen);i++)
	{
		printf("%c",topic->payload[i]);
	}
	printf("\n");
}


/*----------------------------------------------------------------------------*/
/*	DTLS functions 														  */
/*----------------------------------------------------------------------------*/
static int
send_to_peer(struct dtls_context_t *ctx,
	     session_t *session, uint8 *data, size_t len) {
  //mqtt_len = sizeof(buf);

	uip_udp_packet_sendto(pst_conn, data, len, &session->addr, UIP_HTONS(MQTTSN_PORT));

  return len;
}

static int
read_from_peer(struct dtls_context_t *ctx,
	       session_t *session, uint8 *data, size_t len) {
	memcpy(&ctx->readbuf,data,len);
	ctx->decrypted_length = len;
	printf("read from peer\n");

  return len;
}


/*----------------------------------------------------------------------------*/
/*	demo_mqttInit() 														  */
/*----------------------------------------------------------------------------*/
int8_t demo_mqttInit(void)
{
	dtls_set_log_level(DTLS_LOG_DEBUG);

	mqtt_state = MQTT_STOP;
	dtls_init();
	pst_conn = udp_new(NULL, 0, NULL);
	udp_bind(pst_conn, UIP_HTONS(MQTTSN_PORT)); // TODO LW old value -> 53231
	etimer_set(&mq_et, START_DELAY * bsp_get(E_BSP_GET_TRES), _demo_mqtt_timercallback);
	evproc_regCallback(EVENT_TYPE_TCPIP, _demo_mqtt_callback);

#ifdef DTLS
	mqtt_state = MQTT_DTLS_HANDSHAKE;
#else
	mqtt_state = MQTT_CONNECT;
#endif

#if USE_BOOTSTRAP_SERVER
	mqtt_state = MQTT_BOOTSTRAP;
#else
	// Set the ipv6 address from RSMB
	uip_ip6addr(&un_server_ipaddr, 	un_server_ipaddr.u16[0],un_server_ipaddr.u16[1],\
									un_server_ipaddr.u16[2],un_server_ipaddr.u16[3],\
									un_server_ipaddr.u16[4],un_server_ipaddr.u16[5],\
									un_server_ipaddr.u16[6],un_server_ipaddr.u16[7]);
#endif

#ifdef DTLS
static dtls_handler_t cb = {
	.write = send_to_peer,
	.read  = read_from_peer,
	.event = NULL,
#ifdef DTLS_PSK
	.get_psk_info = get_psk_info,
#endif /* DTLS_PSK */
#ifdef DTLS_ECC
#ifndef DTLS_X509
	.get_ecdsa_key = get_ecdsa_key,
	.verify_ecdsa_key = verify_ecdsa_key
#else
	.get_ecdsa_ca = dtls_get_ecdsa_ca,
	.verify_ecdsa_cert = dtls_verify_ecdsa_cert
#endif

#endif /* DTLS_ECC */
};


	memcpy(&dst.addr,&un_server_ipaddr,sizeof(dst.addr));
	dst.port = UIP_HTONS(MQTTSN_PORT);
	dst.size = sizeof(dst.port) + sizeof(dst.addr);

	PRINT6ADDR(&dst->addr);
	PRINTF(":%d\n", uip_ntohs(dst->port));

	dtls_context = dtls_new_context(pst_conn);
    if (dtls_context)
	dtls_set_handler(dtls_context, &cb);
#endif
	/* Add device name to database */
	sprintf(devicename_str, "x%02x%02x", mac_phy_config.mac_address[6], mac_phy_config.mac_address[7]);

	mqtt_add_topic("/topic/1", PUBLISH, 1, 1, 0, NULL);
	mqtt_add_topic("/topic/2", SUBSCRIBE, 0, 0, 0, sub_handler);
	//etimer_set(&mq_et, START_DELAY * bsp_get(E_BSP_GET_TRES), _demo_mqtt_timercallback);

	return 1;
} /* demo_mqttInit()  */
/** @} */
/** @} */
/** @} */

