#ifndef DEMO_MQTT_H_
#define DEMO_MQTT_H_

/*============================================================================*/
/*! \file   demo_mqtt.h

    \author Peter Lehmann, peter.lehmann@hs-offenburg.de

    \brief  This is the header file of the MQTT engine

    \version 0.0.1
*/
/*============================================================================*/

#include "emb6.h"
#include "MQTTSNPacket.h"

#define PUBLISH 			0
#define SUBSCRIBE 			1


typedef void (*mqtt_callback)(void *response);

typedef struct {
	uint8_t type;
	int8_t retained;
	int16_t packetid;
	int8_t qos;
	int8_t dup;
} mqtt_flags_t;

typedef struct {
	MQTTSN_topicid topic;
	mqtt_flags_t flags;
	char* topicname;
	char* payload;
	uint16_t payloadlen;
	uint8_t status;
	uint16_t interval;
	uint8_t timeout;
	uint8_t retrans_counter;
	clock_time_t last_interval;
	mqtt_callback response_callback;
} mqtt_topic_t;

/*==============================================================================
                         FUNCTION PROTOTYPES OF THE API
==============================================================================*/

/*============================================================================*/
/*!
   \brief Initialization of the MQTT engine

*/
/*============================================================================*/
int8_t demo_mqttInit(void);

/*============================================================================*/
/*!
	\brief Configuration of the MQTT engine

	\return 0 - error, 1 - success
*/
/*============================================================================*/
uint8_t demo_mqttConf(s_ns_t* pst_netStack);

/*============================================================================*/
/*!
	\brief Add a topic to the topic database

	\param sub_or_pub	topic type: PUBLISH or SUBSCRIBE
	\param interval		publish interval for automatic publishing
	\param qos			quality of service (see mqtt spec)
	\param retained		retained bit (see mqtt spec)
	\param callback		callback for subscriptions and puback' if qos > 0
	\return 		-1 for error or number of added topic
*/
/*============================================================================*/
int8_t mqtt_add_topic (char *topicname, uint8_t sub_or_pub, uint16_t interval,
						int8_t qos, int8_t retained, void* callback);

/*============================================================================*/
/*!
	\brief Publish a predefined topic

	\return 0 - error, 1 - success
*/
/*============================================================================*/
uint8_t mqtt_publish_topic (uint8_t topic_no);


/*============================================================================*/
/*!
	\brief Remove and deregisters a predefined topic

	\return 0 - error, 1 - success
*/
/*============================================================================*/
int8_t mqtt_remove_topic (int8_t topic_no);

/*============================================================================*/
/*!
	\brief Get a predefined topic

	\return topic pointer
*/
/*============================================================================*/
mqtt_topic_t* mqtt_get_topic(uint8_t topic_no);

#endif /* DEMO_MQTT_H_ */
/** @} */
/** @} */
/** @} */
