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
	void *buffer;
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

	// Retrieve the pointer to our buffer
	field_id = (*env)->GetFieldID(env, icmp_socket_class, "m_receiveBufferPtr", "J");
	state->buffer = (void*)(*env)->GetLongField(env, instance, field_id);

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

static void setReceiveBufferPtr(JNIEnv *env, jobject instance, void *buffer) {
	jclass icmp_socket_class = NULL;
	jfieldID receive_buffer_ptr_field = NULL;

	// Find the class that describes ourself
	icmp_socket_class = (*env)->GetObjectClass(env, instance);
	if (icmp_socket_class == NULL) {
		goto end_setptr;
	}

	receive_buffer_ptr_field = (*env)->GetFieldID(env, icmp_socket_class, "m_receiveBufferPtr", "J");

	(*env)->SetLongField(env, instance, receive_buffer_ptr_field, (jlong)buffer);

end_setptr:
	if (icmp_socket_class != NULL) {
		(*env)->DeleteLocalRef(env, icmp_socket_class);
	}
}

/**
 * Creates a new InetAddress object.
 * Network address must be passed in network byte order.
 * Supports both IPv4 and IPv6 addresses (determined based on the given size)
 */
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

/**
 * Converts an InetAddress object to byte array.
 */
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

	// Allocate a buffer to receive data if necessary.
	// This is probably more than necessary, but we don't
	// want to lose messages if we don't need to.
	attr.buffer = malloc(MAX_PACKET);
	if (attr.buffer == NULL) {
		throwError(env, "java/lang/OutOfMemoryError", "Failed to allocate memory to receive ICMP datagram.");
		return;
	}

	// Save the reference to the buffer in the Java object
	setReceiveBufferPtr(env, instance, attr.buffer);
}

/*
* Class:     org_opennms_protocols_icmp_ICMPSocket
* Method:    receivePacket
* Signature: ()Ljava/net/DatagramPacket;
*/
JNIEXPORT jobject JNICALL
Java_org_opennms_protocols_icmp_ICMPSocket_receivePacket (JNIEnv *env, jobject instance) {
	int ret;
	struct sockaddr *in_addr;
	onms_socklen_t in_addr_len;
	uint64_t received_time;

	char exception_msg[256];
	char error_msg[128];

	// IPv4 specific structures
	struct sockaddr_in in_addr_v4;
	iphdr_t *ip_hdr_v4 = NULL;
	icmphdr_t *icmp_hdr_v4 = NULL;

	// IPv6 specific structures
	struct sockaddr_in6	in_addr_v6;
	struct icmp6_hdr *icmp_hdr_v6 = NULL;

	unsigned char *source_addr_bytes = NULL;
	u_int source_addr_size = 0;
	void *icmp_pkt_bytes = NULL;

	jbyteArray byte_array = NULL;
	jobject addr_instance = NULL;
	jobject	response_packet = NULL;
	jclass response_packet_class = NULL;
	jmethodID response_packet_ctor_method_id = NULL;

	IcmpSocketAttributes attr;
	if (getIcmpSocketAttributes(env, instance, &attr)) {
		throwError(env, "java/lang/Exception", "Failed to retrieve ICMP socket attributes.");
		goto end_recv;
	}

	// Clear out the address structures where the
	// operating system will store the to/from address
	// information.
	if (attr.family == AF_INET) {
		memset((void *)&in_addr_v4, 0, sizeof(in_addr_v4));
		in_addr_len = sizeof(in_addr_v4);
		in_addr = (struct sockaddr *)&in_addr_v4;
	} else {
		memset((void *)&in_addr_v6, 0, sizeof(in_addr_v6));
		in_addr_len = sizeof(in_addr_v6);
		in_addr = (struct sockaddr *)&in_addr_v6;
	}

	// Receive data from the socket:
	// IPv4 packets will also include the IP header preceding the ICMP data
	// IPv6 packets do NOT include the IP header
	ret = (int)recvfrom(attr.fd, attr.buffer, MAX_PACKET, 0, in_addr, &in_addr_len);
	if (ret == SOCKET_ERROR) {
		// Error reading the information from the socket
		int saved_errno = errno;
		strerror_r(saved_errno, error_msg, sizeof(error_msg));
		snprintf(exception_msg, sizeof(exception_msg), "Error reading data from the socket descriptor (iRC = %d, fd_value = %d, %d, %s)", ret, attr.fd, saved_errno, error_msg);
		throwError(env, "java/io/IOException", exception_msg);
		goto end_recv;
	} else if (ret == 0) {
		// Error reading the information from the socket
		throwError(env, "java/io/EOFException", "End-of-File returned from socket descriptor");
		goto end_recv;
	}
	CURRENTTIMEMICROS(received_time);

	if (attr.family == AF_INET) {
		// We need to remove the IP header from the message.
		// We also decrement the bytes received by the same size.
		//
		// NOTE: The ip_hl field of the IP header is the number
		// of 4 byte values in the header. Thus the ip_hl must
		// be multiplied by 4 (or shifted 2 bits).
		ip_hdr_v4 = (iphdr_t *) attr.buffer;
		ret -= ip_hdr_v4->ONMS_IP_HL << 2;
		if (ret <= 0) {
			throwError(env, "java/io/IOException", "Malformed ICMP datagram received");
			goto end_recv;
		}
		icmp_hdr_v4 = (icmphdr_t *) ((char *) attr.buffer + (ip_hdr_v4->ONMS_IP_HL << 2));

		source_addr_bytes = (unsigned char*)&in_addr_v4.sin_addr.s_addr;
		source_addr_size = 4;
		icmp_pkt_bytes = icmp_hdr_v4;
	} else {
		icmp_hdr_v6 = (struct icmp6_hdr *)((char *)attr.buffer);
		source_addr_bytes = in_addr_v6.sin6_addr.s6_addr;
		source_addr_size = 16;
		icmp_pkt_bytes = icmp_hdr_v6;
	}

	// Now construct a new java.net.InetAddress object from
	// the receipt information. The network address must
	// be passed in network byte order!
	addr_instance = newInetAddressFromBytes(env, source_addr_bytes, source_addr_size);
	if (addr_instance == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_recv;
	}

	// Get the byte array needed to setup the ResponsePacket constructor.
	byte_array = (*env)->NewByteArray(env, (jsize)ret);
	if (byte_array != NULL && (*env)->ExceptionOccurred(env) == NULL) {
		(*env)->SetByteArrayRegion(env,
								   byte_array,
								   0,
								   (jsize)ret,
								   (jbyte *)icmp_pkt_bytes);
	}

	if ((*env)->ExceptionOccurred(env) != NULL) {
		goto end_recv;
	}

	// Get the ResponsePacket class
	response_packet_class = (*env)->FindClass(env, "org/opennms/protocols/icmp/ResponsePacket");
	if (response_packet_class == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_recv;
	}

	// ResponsePacket constructor identifier
	response_packet_ctor_method_id = (*env)->GetMethodID(env,
														 response_packet_class,
														 "<init>",
														 "(Ljava/net/InetAddress;[BJ)V");
	if (response_packet_ctor_method_id == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_recv;
	}

	// New one!
	response_packet = (*env)->NewObject(env,
										response_packet_class,
										response_packet_ctor_method_id,
										addr_instance,
										byte_array,
										(jlong)received_time);

end_recv:
	if (addr_instance != NULL) {
		(*env)->DeleteLocalRef(env, addr_instance);
	}
	if (byte_array != NULL) {
		(*env)->DeleteLocalRef(env, byte_array);
	}
	if (response_packet_class != NULL) {
		(*env)->DeleteLocalRef(env, response_packet_class);
	}

	return response_packet;
}

/*
* Class:     org_opennms_protocols_icmp_ICMPSocket
* Method:    sendPacket
* Signature: (Ljava/net/DatagramPacket;)V
*/
JNIEXPORT void JNICALL
Java_org_opennms_protocols_icmp_ICMPSocket_sendPacket (JNIEnv *env, jobject instance, jobject destination, jbyteArray data) {
	int ret;
	void *buffer = NULL;
	jsize buffer_len = 0;
	struct sockaddr *in_addr;
	onms_socklen_t in_addr_len;

	char exception_msg[256];
	char error_msg[128];

	struct sockaddr_in in_addr_v4;
	struct sockaddr_in6 in_addr_v6;

	IcmpSocketAttributes attr;
	if (getIcmpSocketAttributes(env, instance, &attr)) {
		throwError(env, "java/lang/Exception", "Failed to retrieve ICMP socket attributes.");
		goto end_send;
	}

	// Set up the address
	if (attr.family == AF_INET) {
		in_addr = (struct sockaddr*)&in_addr_v4;
		in_addr_len = sizeof(in_addr_v4);

		memset(&in_addr_v4, 0, in_addr_len);
		in_addr_v4.sin_family = AF_INET;
		in_addr_v4.sin_port   = 0;

		getInetAddressBytes(env, destination, 4, (jbyte *)&(in_addr_v4.sin_addr.s_addr));
		if ((*env)->ExceptionOccurred(env) != NULL) {
			goto end_send;
		}
	} else {
		in_addr = (struct sockaddr*)&in_addr_v6;
		in_addr_len = sizeof(in_addr_v6);

		memset(&in_addr_v6, 0, in_addr_len);
		in_addr_v6.sin6_family = AF_INET6;
		in_addr_v6.sin6_port   = 0;

		getInetAddressBytes(env, destination, 16, (jbyte *)&(in_addr_v6.sin6_addr.s6_addr));
		if ((*env)->ExceptionOccurred(env) != NULL) {
			goto end_send;
		}
	}

	// Get the length of the buffer so that
	// a suitable 'char *' buffer can be allocated
	// and used with the sendto() function.
	buffer_len = (*env)->GetArrayLength(env, data);
	if (buffer_len <= 0) {
		throwError(env, "java/io/IOException", "Insufficient data");
		goto end_send;
	}

	// Allocate the buffer where the java byte[] information
	// is to be transfered to.
	buffer = malloc((size_t)buffer_len);
	if (buffer == NULL) {
		int	saved_errno = errno;
		strerror_r(saved_errno, error_msg, sizeof(error_msg));
		snprintf(exception_msg, sizeof(exception_msg), "Insufficent Memory (%d, %s)", saved_errno, error_msg);
		throwError(env, "java/lang/OutOfMemoryError", exception_msg);
	}

	// Copy the contents of the packet's byte[] array
	// into the newly allocated buffer.
	(*env)->GetByteArrayRegion(env,
							   data,
							   0,
							   buffer_len,
							   (jbyte *)buffer);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		goto end_send;
	}

	// Check for 'OpenNMS!' at byte offset 32. If
	// it's found then we need to modify the time
	// and checksum for transmission. ICMP type
	// must equal 8 for ECHO_REQUEST
	// Don't forget to check for a potential buffer overflow!
	char shouldUpdatePayload = 0;
	if (attr.family == AF_INET) {
		if (buffer_len >= (OPENNMS_TAG_OFFSET + OPENNMS_TAG_LEN)
		   && ((icmphdr_t *)buffer)->ICMP_TYPE == 0x08
		   && memcmp((char *)buffer + OPENNMS_TAG_OFFSET, OPENNMS_TAG, OPENNMS_TAG_LEN) == 0) {
			shouldUpdatePayload = 1;

			// Checksum will be computed by system
			((icmphdr_t *)buffer)->ICMP_CHECKSUM = 0;
		}
	} else {
		if (buffer_len >= (OPENNMS_TAG_OFFSET + OPENNMS_TAG_LEN)
		   && ((struct icmp6_hdr *)buffer)->icmp6_type == ICMP6_ECHO_REQUEST
		   && memcmp((char *)buffer + OPENNMS_TAG_OFFSET, OPENNMS_TAG, OPENNMS_TAG_LEN) == 0) {
			shouldUpdatePayload = 1;

			// Checksum will be computed by system
			((struct icmp6_hdr *)buffer)->icmp6_cksum = 0;
		}
	}

	if (shouldUpdatePayload) {
		uint64_t now = 0;
		CURRENTTIMEMICROS(now);
		now = htonll(now);
		memcpy((char *)buffer + SENTTIME_OFFSET, (char *)&now, TIME_LENGTH);
	}

	ret = (int)sendto(attr.fd,
					  buffer,
					  (size_t)buffer_len,
					  0,
					  in_addr,
					  in_addr_len);

	if (ret == SOCKET_ERROR && errno == EACCES) {
		throwError(env, "java/net/NoRouteToHostException", "cannot send to broadcast address");
	} else if (ret != buffer_len) {
		int	saved_errno = errno;
		strerror_r(saved_errno, error_msg, sizeof(error_msg));
		snprintf(exception_msg, sizeof(exception_msg), "sendto error (%d, %s)", saved_errno, error_msg);
		throwError(env, "java/io/IOException", exception_msg);
	}

end_send:
	if (buffer != NULL) {
		free(buffer);
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

	if (attr.fd >= 0) {
		close(attr.fd);
		setIcmpFd(env, instance, INVALID_SOCKET);
#ifdef __WIN32__
		WSACleanup();
#endif
	}

	if (attr.buffer != 0) {
		free(attr.buffer);
		setReceiveBufferPtr(env, instance, 0);
	}
}
