// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/include/teavpn2/tcp.h
 *
 *  TCP header file for TeaVPN2
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__TCP_H
#define TEAVPN2__TCP_H

#include <teavpn2/base.h>


#define TUN_READ_SIZE	(0x1000u)

#define INTERNAL____TEAVPN2__TCP_H
#include <teavpn2/tcp_server.h>
#undef INTERNAL____TEAVPN2__TCP_H

#endif /* #ifndef TEAVPN2__TCP_H */
