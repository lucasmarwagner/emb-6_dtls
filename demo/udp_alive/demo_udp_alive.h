#ifndef _DEMO_UDP_ALIVE_H_
#define _DEMO_UDP_ALIVE_H_
/**
 *      \addtogroup emb6
 *      @{
 *   \defgroup demo
 *
 *   This is a set of libraries to demonstrate behavior of different supported
 *   protocols. Files which a started from demo are using for
 *   demonstrate functionality of a protocol.
 *   @{
 *   \defgroup demo_udp_alive    UDP-Alive for 6LBR
 *
 *   UDP Client Header for DODAG visualization on Cetic 6LBR
 *   @{
*/
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
/*! \file   demo_udp_alive.h

    \author Peter Lehmann, peter.lehmann@hs-offenburg.de

    \brief  UDP Client for DODAG visualization on Cetic 6LBR

    \version 0.0.1
*/
/*============================================================================*/

/*==============================================================================
                         FUNCTION PROTOTYPES OF THE API
==============================================================================*/

/*----------------------------------------------------------------------------*/
/*!
   \brief Initialization of the simple UDP client server application.

*/
/*----------------------------------------------------------------------------*/
int8_t demo_udpAliveInit(void);

/*----------------------------------------------------------------------------*/
/*!
    \brief Configuration of the simple UDP client application.

    \return 0 - error, 1 - success
*/
/*----------------------------------------------------------------------------*/
uint8_t demo_udpAliveConf(s_ns_t* pst_netStack);

#endif /* _DEMO_UDP_ALIVE_H_ */
/** @} */
/** @} */
/** @} */
