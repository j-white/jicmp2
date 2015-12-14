/*******************************************************************************
 * This file is part of OpenNMS(R).
 *
 * Copyright (C) 2010-2015 The OpenNMS Group, Inc.
 * OpenNMS(R) is Copyright (C) 1999-2015 The OpenNMS Group, Inc.
 *
 * OpenNMS(R) is Copyright (C) 2002-2015 The OpenNMS Group, Inc.  All rights
 * reserved.  OpenNMS(R) is a derivative work, containing both original code,
 * included code and modified code that was published under the GNU General
 * Public License.  Copyrights for modified and included code are below.
 *
 * OpenNMS(R) is a registered trademark of The OpenNMS Group, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License with the Classpath
 * Exception; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * For more information contact:
 *     OpenNMS(R) Licensing <license@opennms.org>
 *     http://www.opennms.org/
 *     http://www.opennms.com/
 *******************************************************************************/
#include <config.h>

#include "IcmpSocket.h"
#include <jni.h>

#if 0
#pragma export on
#endif
#include "ICMPSocket_java_interface.h"
#if 0
#pragma export reset
#endif

typedef struct {
	sa_family_t family;
	onms_socket fd;
	uint16_t id;
} IcmpSocketAttributes;

/**
 * Utility class for throwing exceptions.
 */
static void throwError(JNIEnv *env, char *exception, char *error_msg) {
	jclass exception_class = (*env)->FindClass(env, exception);
	if (exception_class != NULL) {
		(*env)->ThrowNew(env, exception_class, error_msg);
	}
}

/**
 * Retrieves the attributes from the given ICMPSocket instance.
 * Returns 0 on success.
 */
static int getIcmpSocketAttributes(JNIEnv *env, jobject instance, IcmpSocketAttributes* state) {
	jclass icmp_socket_class = NULL;
	jfieldID field_id = NULL;
	jclass fd_class = NULL;
	jfieldID fd_field = NULL;
	jobject fd_instance = NULL;
	int ret = -1;

	// Find the class that describes ourself
	icmp_socket_class = (*env)->GetObjectClass(env, instance);
	if (icmp_socket_class == NULL) {
		goto end_getstate;
	}

	// Grab a reference to the 'm_useIPv6' field
	field_id = (*env)->GetFieldID(env, icmp_socket_class, "m_useIPv6", "Z");
	if (field_id == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_getstate;
	}

	// Grab the value
	jboolean using_ipv6 = (*env)->GetBooleanField(env, instance, field_id);
	if (using_ipv6 == JNI_TRUE) {
		state->family = AF_INET6;
	} else {
		state->family = AF_INET;
	}

	// Grab a reference to the 'm_pingerId' field
	field_id = (*env)->GetFieldID(env, icmp_socket_class, "m_pingerId", "I");
	if (field_id == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_getstate;
	}

	// Grab the value
	state->id = (uint16_t)(*env)->GetIntField(env, instance, field_id);

	// Find the java.io.FileDescriptor class
	field_id = (*env)->GetFieldID(env, icmp_socket_class, "m_rawFd", "Ljava/io/FileDescriptor;");
	if (field_id == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_getstate;
	}

	// Get the instance of the FileDescriptor class from the instance of ourself
	fd_instance = (*env)->GetObjectField(env, instance, field_id);
	if (fd_instance == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_getstate;
	}

	// Get the class object for the java.io.FileDescriptor
	fd_class = (*env)->GetObjectClass(env, fd_instance);
	if (fd_class == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_getstate;
	}

	// Get the field identifier for the primitive integer
	// that is part of the FileDescriptor class.
#ifdef __WIN32__
	fd_field = (*env)->GetFieldID(env, fd_class, "handle", "J");
#else
	fd_field = (*env)->GetFieldID(env, fd_class, "fd", "I");
#endif
	if (fd_field == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_getstate;
	}

	// Recover the value
#ifdef __WIN32__
	state->fd = (SOCKET)(*env)->GetLongField(env, thisFdInstance, fdField);
#else
	state->fd = (*env)->GetIntField(env, fd_instance, fd_field);
#endif

	// We've successfully retrieved all of the attributes
	ret = 0;

end_getstate:
	// Cleanup
	if (icmp_socket_class != NULL) {
		(*env)->DeleteLocalRef(env, icmp_socket_class);
	}
	if (fd_class != NULL) {
		(*env)->DeleteLocalRef(env, fd_class);
	}
	if (fd_instance != NULL) {
		(*env)->DeleteLocalRef(env, fd_instance);
	}

	return ret;
}

static void setIcmpFd(JNIEnv *env, jobject instance, onms_socket fd_value) {
	jclass icmp_socket_class = NULL;
	jclass fd_class = NULL;
	jfieldID fd_field = NULL;
	jobject fd_instance = NULL;

	// Find the class that describes ourself
	icmp_socket_class = (*env)->GetObjectClass(env, instance);
	if (icmp_socket_class == NULL) {
		goto end_setfd;
	}

	// Find the java.io.FileDescriptor class
	fd_field = (*env)->GetFieldID(env, icmp_socket_class, "m_rawFd", "Ljava/io/FileDescriptor;");
	if (fd_field == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_setfd;
	}

	// Get the instance of the FileDescriptor class from the instance of ourself
	fd_instance = (*env)->GetObjectField(env, instance, fd_field);
	if (fd_instance == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_setfd;
	}

	// Get the class object for the java.io.FileDescriptor
	fd_class = (*env)->GetObjectClass(env, fd_instance);
	if (fd_class == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_setfd;
	}

	// Get the field identifier for the primitive integer
	// that is part of the FileDescriptor class.
#ifdef __WIN32__
	fd_field = (*env)->GetFieldID(env, fd_class, "handle", "J");
#else
	fd_field = (*env)->GetFieldID(env, fd_class, "fd", "I");
#endif
	if (fd_field == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_setfd;
	}

#ifdef __WIN32__
	(*env)->SetLongField(env, fd_instance, fd_field, fd_value);
#else
	(*env)->SetIntField(env, fd_instance, fd_field, fd_value);
#endif

end_setfd:
	if (icmp_socket_class != NULL) {
		(*env)->DeleteLocalRef(env, icmp_socket_class);
	}
	if (fd_class != NULL) {
		(*env)->DeleteLocalRef(env, fd_class);
	}
	if (fd_instance != NULL) {
		(*env)->DeleteLocalRef(env, fd_instance);
	}
}

static jobject newInetAddressFromBytes(JNIEnv *env, unsigned char* addr, u_int size) {
	jclass addr_class;
	jmethodID addr_by_address_method_id;
	jobject new_addr_instance = NULL;
	jbyteArray addr_bytes = NULL;

	// Copy the address into a jbyteArray
	addr_bytes = (*env)->NewByteArray(env, size);
	if (addr_bytes != NULL && (*env)->ExceptionOccurred(env) == NULL) {
		(*env)->SetByteArrayRegion(env,
								   addr_bytes,
								   0,
								   (jsize)size,
								   (jbyte *)addr);
	} else if ((*env)->ExceptionOccurred(env) != NULL) {
		goto end_inet;
	}

	// Load the class
	addr_class = (*env)->FindClass(env, "java/net/InetAddress");
	if (addr_class == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_inet;
	}

	// Find the static method
	addr_by_address_method_id = (*env)->GetStaticMethodID(env,
													  addr_class,
													  "getByAddress",
													  "([B)Ljava/net/InetAddress;");
	if (addr_by_address_method_id == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_inet;
	}

	// Invoke it!
	new_addr_instance = (*env)->CallStaticObjectMethod(env,
												  addr_class,
												  addr_by_address_method_id,
												  addr_bytes);
end_inet:
	if (addr_class != NULL) {
		(*env)->DeleteLocalRef(env, addr_class);
	}
	if (addr_bytes != NULL) {
		(*env)->DeleteLocalRef(env, addr_bytes);
	}
	return new_addr_instance;
}

static void getInetAddressBytes(JNIEnv *env, jobject inet_address_instance, jsize len, jbyte *buf) {
	jclass addr_class = NULL;
	jmethodID get_address_method_id = NULL;
	jbyteArray addr_bytes = NULL;

	// Load the class
	addr_class = (*env)->GetObjectClass(env, inet_address_instance);
	if (addr_class == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_inet;
	}

	// Find the method
	get_address_method_id = (*env)->GetMethodID(env,
												addr_class,
												"getAddress",
												"()[B");
	if (get_address_method_id == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_inet;
	}

	addr_bytes = (*env)->CallObjectMethod(env, inet_address_instance, get_address_method_id);
	if (addr_bytes == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_inet;
	}

	// The byte array returned from java.net.InetAddress.getAddress()
	// (which was fetched above and is stored as a jbyteArray in addrData)
	// is in network byte order (high byte first, AKA big endian).
	// the value of in_addr_t is also in network byte order, so no
	// conversion needs to be performed.
	(*env)->GetByteArrayRegion(env,
							   addr_bytes,
							   0,
							   len,
							   buf);

end_inet:
	if (addr_class != NULL) {
		(*env)->DeleteLocalRef(env, addr_class);
	}
	if (addr_bytes != NULL) {
		(*env)->DeleteLocalRef(env, addr_bytes);
	}
}

/*
* Opens a new socket that is set to send and receive the ICMP protocol.
*
* We first attempt to open a datagram socket, as these can be used
* without any special privileges, and if this fails, we resort
* to opening a raw socket.
*
* An exception is thrown if the socket() calls fail.
*
* Class:     org_opennms_protocols_icmp_ICMPSocket
* Method:    initSocket
* Signature: ()V
*/
JNIEXPORT void JNICALL
Java_org_opennms_protocols_icmp_ICMPSocket_initSocket (JNIEnv *env, jobject instance) {
	char exception_msg[256];
	char error_msg[128];
#ifdef __WIN32__
	int result;
	WSADATA info;
	result = WSAStartup(MAKEWORD(2,2), &info);
	if (result != 0) {
		snprintf(error_msg, sizeof(error_msg), "WSAStartup failed: %d", result);
		throwError(env, "java/net/IOException", error_msg);
		return;
	}
#endif

	// Lookup the instance specific attributes
	IcmpSocketAttributes attr;
	if (getIcmpSocketAttributes(env, instance, &attr)) {
		throwError(env, "java/lang/Exception", "Failed to retrieve ICMP socket attributes.");
		return;
	}

    // Attempt to open a diagram (UDP) socket
	int protocol = attr.family == AF_INET ? IPPROTO_ICMP : IPPROTO_ICMPV6;
    attr.fd = socket(attr.family, SOCK_DGRAM, protocol);
	if (attr.fd == SOCKET_ERROR) {
        // We weren't able to successfully acquire the diagram socket, let's try a raw socket instead
		attr.fd = socket(attr.family, SOCK_RAW, protocol);
        if (attr.fd == SOCKET_ERROR) {
		    int	saved_errno = errno;
			strerror_r(saved_errno, error_msg, sizeof(error_msg));
		    snprintf(exception_msg, sizeof(exception_msg), "System error creating ICMP socket (%d, %s)", saved_errno, error_msg);
		    throwError(env, "java/net/SocketException", exception_msg);
		    return;
        }
	} else {
		// We've successfully acquired a diagram socket
		// When using a diagram socket on Linux, the ID in the ICMP Echo Request header
		// is replaced with the source port. In order to generate packets with the
		// correct ID we need to bind the socket to this port.
		struct sockaddr *source_addr;
		size_t source_addr_len;

		if (attr.family == AF_INET6) {
			struct sockaddr_in6 source_address;
			memset(&source_address, 0, sizeof(struct sockaddr_in6));
			source_address.sin6_family = attr.family;
			source_address.sin6_port = htons(attr.id);

			source_addr = (struct sockaddr *)&source_address;
			source_addr_len = sizeof(struct sockaddr_in6);
		} else {
			struct sockaddr_in source_address;
			memset(&source_address, 0, sizeof(struct sockaddr_in));
			source_address.sin_family = attr.family;
			source_address.sin_port = htons(attr.id);

			source_addr = (struct sockaddr *)&source_address;
			source_addr_len = sizeof(struct sockaddr_in);
		}

		if (bind(attr.fd, source_addr, source_addr_len)) {
			int saved_errno = errno;
			strerror_r(saved_errno, error_msg, sizeof(error_msg));
			snprintf(exception_msg, sizeof(error_msg), "Failed to bind ICMP socket (%d, %s)", saved_errno, error_msg);
			throwError(env, "java/net/SocketException", exception_msg);
			return;
		}
	}

	// Save the fd on the instance of the ICMPSocket
	setIcmpFd(env, instance, attr.fd);
}

/*
* Class:     org_opennms_protocols_icmp_ICMPSocket
* Method:    receive
* Signature: ()Ljava/net/DatagramPacket;
*/
JNIEXPORT jobject JNICALL
Java_org_opennms_protocols_icmp_ICMPSocket_receive (JNIEnv *env, jobject instance) {
	int			iRC;
	void *			inBuf = NULL;

	onms_socklen_t		inAddrLen;
	struct sockaddr*    inAddr;
	struct sockaddr_in	inAddrV4;

	iphdr_t *		ip4Hdr = NULL;
	icmphdr_t *		icmp4Hdr = NULL;

	struct sockaddr_in6	inAddrV6;
	struct icmp6_hdr *	icmp6Hdr = NULL;

	jbyteArray		byteArray 	= NULL;
	jobject			addrInstance 	= NULL;
	jobject			datagramInstance = NULL;
	jclass			datagramClass 	= NULL;
	jmethodID		datagramCtorID 	= NULL;
	char errBuf[256];

	IcmpSocketAttributes attr;
	if (getIcmpSocketAttributes(env, instance, &attr)) {
		throwError(env, "java/lang/Exception", "Failed to retrieve ICMP socket attributes.");
		goto end_recv;
	}

	// Allocate a buffer to receive data if necessary.
	// This is probably more than necessary, but we don't
	// want to lose messages if we don't need to. This also
	// must be dynamic for MT-Safe reasons and avoids blowing
	// up the stack.
	//FIXME: Is this really necessary?
	inBuf = malloc(MAX_PACKET);
	if (inBuf == NULL) {
		throwError(env, "java/lang/OutOfMemoryError", "Failed to allocate memory to receive ICMP datagram");
		goto end_recv;
	}
	memset(inBuf, 0, MAX_PACKET);

	// Clear out the address structures where the
	// operating system will store the to/from address
	// information.
	if (attr.family == AF_INET) {
		memset((void *)&inAddrV4, 0, sizeof(inAddrV4));
		inAddrLen = sizeof(inAddrV4);
		inAddr = (struct sockaddr *)&inAddrV4;
	} else {
		memset((void *)&inAddrV6, 0, sizeof(inAddrV6));
		inAddrLen = sizeof(inAddrV6);
		inAddr = (struct sockaddr *)&inAddrV6;
	}

	// Receive the data from the operating system. This
	// will also include the IP header that precedes
	// the ICMP data, we'll strip that off later.
	iRC = (int)recvfrom(attr.fd, inBuf, MAX_PACKET, 0, inAddr, &inAddrLen);
	if(iRC == SOCKET_ERROR) {
		// Error reading the information from the socket
		int savedErrno = errno;
		snprintf(errBuf, sizeof(errBuf), "Error reading data from the socket descriptor (iRC = %d, fd_value = %d, %d, %s)", iRC, attr.fd, savedErrno, strerror(savedErrno));
		throwError(env, "java/io/IOException", errBuf);
		goto end_recv;
	} else if(iRC == 0) {
		// Error reading the information from the socket
		throwError(env, "java/io/EOFException", "End-of-File returned from socket descriptor");
		goto end_recv;
	}

	if (attr.family == AF_INET) {
		// update the length by removing the IP
		// header from the message. Don't forget to decrement
		// the bytes received by the size of the IP header.
		//
		// NOTE: The ip_hl field of the IP header is the number
		// of 4 byte values in the header. Thus the ip_hl must
		// be multiplied by 4 (or shifted 2 bits).
		ip4Hdr = (iphdr_t *)inBuf;
		iRC -= ip4Hdr->ONMS_IP_HL << 2;
		if(iRC <= 0) {
			throwError(env, "java/io/IOException", "Malformed ICMP datagram received");
			goto end_recv;
		}
		icmp4Hdr = (icmphdr_t *)((char *)inBuf + (ip4Hdr->ONMS_IP_HL << 2));

		// Check the ICMP header for type equal 0, which is ECHO_REPLY, and
		// then check the payload for the 'OpenNMS!' marker. If it's one
		//  we sent out then fix the recv time!
		//
		// Don't forget to check for a buffer overflow!
		if(iRC >= (OPENNMS_TAG_OFFSET + OPENNMS_TAG_LEN)
		   && icmp4Hdr->ICMP_TYPE == 0
		   && memcmp((char *)icmp4Hdr + OPENNMS_TAG_OFFSET, OPENNMS_TAG, OPENNMS_TAG_LEN) == 0) {
			uint64_t now;
			uint64_t sent;
			uint64_t diff;

			// Get the current time in microseconds and then
			// compute the difference
			CURRENTTIMEMICROS(now);
			memcpy((char *)&sent, (char *)icmp4Hdr + SENTTIME_OFFSET, TIME_LENGTH);
			sent = ntohll(sent);
			diff = now - sent;

			// Now fill in the sent, received, and diff
			sent = MICROS_TO_MILLIS(sent);
			sent = htonll(sent);
			memcpy((char *)icmp4Hdr + SENTTIME_OFFSET, (char *)&sent, TIME_LENGTH);

			now  = MICROS_TO_MILLIS(now);
			now  = htonll(now);
			memcpy((char *)icmp4Hdr + RECVTIME_OFFSET, (char *)&now, TIME_LENGTH);

			diff = htonll(diff);
			memcpy((char *)icmp4Hdr + RTT_OFFSET, (char *)&diff, TIME_LENGTH);

			// No need to recompute checksum on this on
			// since we don't actually check it upon receipt
		}

		// Now construct a new java.net.InetAddress object from
		// the receipt information. The network address must
		// be passed in network byte order!
		addrInstance = newInetAddressFromBytes(env, (unsigned char*)&inAddrV4.sin_addr.s_addr, 4);
		if(addrInstance == NULL || (*env)->ExceptionOccurred(env) != NULL) {
			goto end_recv;
		}

		// Get the byte array needed to setup the datagram constructor.
		byteArray = (*env)->NewByteArray(env, (jsize)iRC);
		if(byteArray != NULL && (*env)->ExceptionOccurred(env) == NULL) {
			(*env)->SetByteArrayRegion(env,
									   byteArray,
									   0,
									   (jsize)iRC,
									   (jbyte *)icmp4Hdr);
		}
		if((*env)->ExceptionOccurred(env) != NULL) {
			goto end_recv;
		}
	} else {
		icmp6Hdr = (struct icmp6_hdr *)((char *)inBuf);

		// Check the ICMP header for type ECHO_REPLY, and
		// then check the payload for the 'OpenNMS!' marker. If it's one
		// we sent out then fix the recv time!
		//
		// Don't forget to check for a buffer overflow!
		if(iRC >= (OPENNMS_TAG_OFFSET + OPENNMS_TAG_LEN)
		   && icmp6Hdr->icmp6_type == ICMP6_ECHO_REPLY
		   && memcmp((char *)icmp6Hdr + OPENNMS_TAG_OFFSET, OPENNMS_TAG, OPENNMS_TAG_LEN) == 0) {
			uint64_t now;
			uint64_t sent;
			uint64_t diff;

			// Get the current time in microseconds and then compute the difference
			CURRENTTIMEMICROS(now);
			memcpy((char *)&sent, (char *)icmp6Hdr + SENTTIME_OFFSET, TIME_LENGTH);
			sent = ntohll(sent);
			diff = now - sent;

			// Now fill in the sent, received, and diff
			sent = MICROS_TO_MILLIS(sent);
			sent = htonll(sent);
			memcpy((char *)icmp6Hdr + SENTTIME_OFFSET, (char *)&sent, TIME_LENGTH);

			now  = MICROS_TO_MILLIS(now);
			now  = htonll(now);
			memcpy((char *)icmp6Hdr + RECVTIME_OFFSET, (char *)&now, TIME_LENGTH);

			diff = htonll(diff);
			memcpy((char *)icmp6Hdr + RTT_OFFSET, (char *)&diff, TIME_LENGTH);

			// No need to recompute checksum on this on
			// since we don't actually check it upon receipt
		}

		// Now construct a new java.net.InetAddress object from
		// the receipt information. The network address must
		// be passed in network byte order!
		addrInstance = newInetAddressFromBytes(env, inAddrV6.sin6_addr.s6_addr, 16);
		if(addrInstance == NULL || (*env)->ExceptionOccurred(env) != NULL) {
			goto end_recv;
		}

		// Get the byte array needed to setup the datagram constructor.
		byteArray = (*env)->NewByteArray(env, (jsize)iRC);
		if(byteArray != NULL && (*env)->ExceptionOccurred(env) == NULL) {
			(*env)->SetByteArrayRegion(env,
									   byteArray,
									   0,
									   (jsize)iRC,
									   (jbyte *)icmp6Hdr);
		}
		if((*env)->ExceptionOccurred(env) != NULL) {
			goto end_recv;
		}
	}

	// Get the Datagram class
	datagramClass = (*env)->FindClass(env, "java/net/DatagramPacket");
	if(datagramClass == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_recv;
	}

	// Datagram constructor identifier
	datagramCtorID = (*env)->GetMethodID(env,
		datagramClass,
		"<init>",
		"([BILjava/net/InetAddress;I)V");
	if(datagramCtorID == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_recv;
	}

	// New one!
	datagramInstance = (*env)->NewObject(env,
		datagramClass,
		datagramCtorID,
		byteArray,
		(jint)iRC,
		addrInstance,
		(jint)0);

end_recv:
	if (addrInstance != NULL) {
		(*env)->DeleteLocalRef(env, addrInstance);
	}
	if (byteArray != NULL) {
		(*env)->DeleteLocalRef(env, byteArray);
	}
	if (datagramClass != NULL) {
		(*env)->DeleteLocalRef(env, datagramClass);
	}
	if(inBuf != NULL) {
		free(inBuf);
	}

	return datagramInstance;
}

/*
* Class:     org_opennms_protocols_icmp_ICMPSocket
* Method:    send
* Signature: (Ljava/net/DatagramPacket;)V
*/
JNIEXPORT void JNICALL
Java_org_opennms_protocols_icmp_ICMPSocket_send (JNIEnv *env, jobject instance, jobject packet) {
	jclass dgramClass;
	jmethodID dgramGetDataID;
	jmethodID dgramGetAddrID;
	jobject addrInstance;
	jbyteArray icmpDataArray;

	char * outBuffer = NULL;
	jsize bufferLen = 0;
	int iRC;

	struct sockaddr_in AddrV4;
	struct sockaddr_in6 AddrV6;

	IcmpSocketAttributes attr;
	if (getIcmpSocketAttributes(env, instance, &attr)) {
		throwError(env, "java/lang/Exception", "Failed to retrieve ICMP socket attributes.");
		goto end_send;
	}

	// Get the DatagramPacket class information
	dgramClass = (*env)->GetObjectClass(env, packet);
	if(dgramClass == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_send;
	}

	// Get the identifiers for the getData() and getAddress()
	// methods that are part of the DatagramPacket class.
	dgramGetDataID = (*env)->GetMethodID(env, dgramClass, "getData", "()[B");
	if(dgramGetDataID == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_send;
	}

	dgramGetAddrID = (*env)->GetMethodID(env, dgramClass, "getAddress", "()Ljava/net/InetAddress;");
	if(dgramGetAddrID == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_send;
	}

	(*env)->DeleteLocalRef(env, dgramClass);
	dgramClass = NULL;

	// Get the address information from the DatagramPacket
	// so that a useable Operating System address can
	// be constructed.
	addrInstance = (*env)->CallObjectMethod(env, packet, dgramGetAddrID);
	if(addrInstance == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_send;
	}

	struct sockaddr * Addr;
	size_t AddrLen;

	// Set up the address
	if (attr.family == AF_INET) {
		Addr = (struct sockaddr*)&AddrV4;
		AddrLen = sizeof(AddrV4);

		memset(&AddrV4, 0, AddrLen);
		AddrV4.sin_family = AF_INET;
		AddrV4.sin_port   = 0;

		getInetAddressBytes(env, addrInstance, 4, (jbyte *)&(AddrV4.sin_addr.s_addr));
		if((*env)->ExceptionOccurred(env) != NULL) {
			goto end_send;
		}
	} else {
		Addr = (struct sockaddr*)&AddrV6;
		AddrLen = sizeof(AddrV6);

		memset(&AddrV6, 0, AddrLen);
		AddrV6.sin6_family = AF_INET6;
		AddrV6.sin6_port   = 0;

		getInetAddressBytes(env, addrInstance, 16, (jbyte *)&(AddrV6.sin6_addr.s6_addr));
		if((*env)->ExceptionOccurred(env) != NULL) {
			goto end_send;
		}
	}

	// Remove local references that are no longer needed
	(*env)->DeleteLocalRef(env, addrInstance);
	addrInstance = NULL;

	// Get the byte[] data from the DatagramPacket
	// and then free up the local reference to the
	// method id of the getData() method.
	icmpDataArray = (*env)->CallObjectMethod(env, packet, dgramGetDataID);
	if(icmpDataArray == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_send;
	}

	// Get the length of the buffer so that
	// a suitable 'char *' buffer can be allocated
	// and used with the sendto() function.
	bufferLen = (*env)->GetArrayLength(env, icmpDataArray);
	if(bufferLen <= 0) {
		throwError(env, "java/io/IOException", "Insufficient data");
		goto end_send;
	}

	// Allocate the buffer where the java byte[] information
	// is to be transfered to.
	outBuffer = malloc((size_t)bufferLen);
	if(outBuffer == NULL) {
		char buf[128]; /// error condition: java.lang.OutOfMemoryError!
		int serror = errno;
		snprintf(buf, sizeof(buf), "Insufficent Memory (%d, %s)", serror, strerror(serror));

		throwError(env, "java/lang/OutOfMemoryError", buf);
		goto end_send;
	}

	// Copy the contents of the packet's byte[] array
	// into the newly allocated buffer.
	(*env)->GetByteArrayRegion(env,
		icmpDataArray,
		0,
		bufferLen,
		(jbyte *)outBuffer);
	if((*env)->ExceptionOccurred(env) != NULL)
		goto end_send;

	(*env)->DeleteLocalRef(env, icmpDataArray);

	// Check for 'OpenNMS!' at byte offset 32. If
	// it's found then we need to modify the time
	// and checksum for transmission. ICMP type
	// must equal 8 for ECHO_REQUEST
	// Don't forget to check for a potential buffer overflow!
	char shouldUpdate = 0;
	if (attr.family == AF_INET) {
		if(bufferLen >= (OPENNMS_TAG_OFFSET + OPENNMS_TAG_LEN)
		   && ((icmphdr_t *)outBuffer)->ICMP_TYPE == 0x08
		   && memcmp((char *)outBuffer + OPENNMS_TAG_OFFSET, OPENNMS_TAG, OPENNMS_TAG_LEN) == 0) {
			shouldUpdate = 1;

			// Checksum will be computed by system
			((icmphdr_t *)outBuffer)->ICMP_CHECKSUM = 0;
		}
	} else {
		if(bufferLen >= (OPENNMS_TAG_OFFSET + OPENNMS_TAG_LEN)
		   && ((struct icmp6_hdr *)outBuffer)->icmp6_type == ICMP6_ECHO_REQUEST
		   && memcmp((char *)outBuffer + OPENNMS_TAG_OFFSET, OPENNMS_TAG, OPENNMS_TAG_LEN) == 0) {
			shouldUpdate = 1;

			// Checksum will be computed by system
			((struct icmp6_hdr *)outBuffer)->icmp6_cksum = 0;
		}
	}

	if (shouldUpdate) {
		uint64_t now = 0;

		memcpy((char *)outBuffer + RECVTIME_OFFSET, (char *)&now, TIME_LENGTH);
		memcpy((char *)outBuffer + RTT_OFFSET, (char *)&now, TIME_LENGTH);

		CURRENTTIMEMICROS(now);
		now = htonll(now);
		memcpy((char *)outBuffer + SENTTIME_OFFSET, (char *)&now, TIME_LENGTH);
	}

	iRC = (int)sendto(attr.fd,
					  (void *)outBuffer,
					  (size_t)bufferLen,
					  0,
					  Addr,
					  AddrLen);

	if(iRC == SOCKET_ERROR && errno == EACCES) {
		throwError(env, "java/net/NoRouteToHostException", "cannot send to broadcast address");
	} else if(iRC != bufferLen) {
		char buf[128];
		int serror = errno;
		snprintf(buf, sizeof(buf), "sendto error (%d, %s)", serror, strerror(serror));
		throwError(env, "java/io/IOException", buf);
	}

end_send:
	if(outBuffer != NULL) {
		free(outBuffer);
	}
}

/*
* Class:     org_opennms_protocols_icmp_ICMPSocket
* Method:    close
* Signature: ()V
*/
JNIEXPORT void
JNICALL Java_org_opennms_protocols_icmp_ICMPSocket_close
		(JNIEnv *env, jobject instance) {
	IcmpSocketAttributes attr;
	if (getIcmpSocketAttributes(env, instance, &attr)) {
		throwError(env, "java/lang/Exception", "Failed to retrieve ICMP socket attributes.");
		return;
	}

	if(attr.fd >= 0) {
		close(attr.fd);
		setIcmpFd(env, instance, INVALID_SOCKET);
#ifdef __WIN32__
		WSACleanup();
#endif
	}
}
