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

/**
* This routine is used to quickly compute the
* checksum for a particular buffer. The checksum
* is done with 16-bit quantities and padded with
* zero if the buffer is not aligned on a 16-bit
* boundry.
*
* FIXME: Add unit tests for this one.
*/
static unsigned short checksum(register unsigned short *p, register int sz) {
	register unsigned long sum = 0;	// need a 32-bit quantity

	// iterate over the 16-bit values and accumulate a sum.
	while (sz > 1) {
		sum += *p++;
		sz  -= 2;
	}

	// handle the odd byte out
	if (sz == 1) {
		// cast the pointer to an unsigned char pointer,
		// dereference and promote to an unsigned short.
		// Shift in 8 zero bits and voila the value is padded!
		sum += ((unsigned short) *((unsigned char *)p)) << 8;
	}

	// Add back the bits that may have overflowed the
	// "16-bit" sum. First add high order 16 to low
	// order 16, then repeat
	while (sum >> 16) {
		sum = (sum >> 16) + (sum & 0xffffUL);
	}

	sum = ~sum & 0xffffUL;
	return (unsigned short)sum;
}

/**
 * Returns the socket family, i.e. AF_INET (IPv4) or AF_INET6 (IPv6)
 * to use for this ICMPSocket instance.
 */
static int getSocketFamily(JNIEnv *env, jobject instance) {
    jclass  thisClass = NULL;
    jfieldID thisIdField = NULL;
    int socketFamily = AF_INET;

    // Find the class that describes ourself.
    thisClass = (*env)->GetObjectClass(env, instance);
    if(thisClass == NULL) {
		goto end_getfamily;
	}

    // Grab a reference to the field that stores the id
    thisIdField = (*env)->GetFieldID(env, thisClass, "m_useIPv6", "Z");
    if(thisIdField == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_getfamily;
	}

    // Grab the value
    jboolean using_ipv6 = (*env)->GetBooleanField(env, instance, thisIdField);
    if (using_ipv6 == JNI_TRUE) {
        socketFamily = AF_INET6;
    }

end_getfamily:
	// Cleanup
	if (thisClass != NULL) {
		(*env)->DeleteLocalRef(env, thisClass);
	}

    return socketFamily;
}

/**
* Returns the unique pinger id of this ICMPSocket instance.
* FIXME: Consolidate to return a struct with all of the instance specific details
*/
static int getPingerId(JNIEnv *env, jobject instance) {
    jclass  thisClass = NULL;
    jfieldID thisIdField = NULL;
	int pingerId = 0;

    // Find the class that describes ourself.
	thisClass = (*env)->GetObjectClass(env, instance);
	if(thisClass == NULL) {
		goto end_getid;
	}

	// Grab a reference to the field that stores the id
	thisIdField = (*env)->GetFieldID(env, thisClass, "m_pingerId", "I");
	if(thisIdField == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_getid;
	}

	// Grab the value
	pingerId = (*env)->GetIntField(env, instance, thisIdField);

end_getid:
	// Cleanup
	if (thisClass != NULL) {
		(*env)->DeleteLocalRef(env, thisClass);
	}

	return pingerId;
}

/**
* This method is used to lookup the instances java.io.FileDescriptor
* object and it's internal integer descriptor. This hidden integer
* is used to store the opened ICMP socket handle that was
* allocated by the operating system.
*
* If the descriptor could not be recovered or has not been
* set then a INVALID_SOCKET is returned.
*
* FIXME: Consolidate to return a struct with all of the instance specific details
*/
static onms_socket getIcmpFd(JNIEnv *env, jobject instance) {
	jclass	thisClass = NULL;
	jclass	fdClass   = NULL;

	jfieldID thisFdField    = NULL;
	jobject  thisFdInstance = NULL;

	jfieldID fdFdField = NULL;
	onms_socket	fd_value  = INVALID_SOCKET;

	// Find the class that describes ourself.
	thisClass = (*env)->GetObjectClass(env, instance);
	if (thisClass == NULL) {
		goto end_getfd;
	}

	// Find the java.io.FileDescriptor class
	thisFdField = (*env)->GetFieldID(env, thisClass, "m_rawFd", "Ljava/io/FileDescriptor;");
	if(thisFdField == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_getfd;
	}

	// Get the instance of the FileDescriptor class from the instance of ourself
	thisFdInstance = (*env)->GetObjectField(env, instance, thisFdField);
	if(thisFdInstance == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_getfd;
	}

	// Get the class object for the java.io.FileDescriptor
	fdClass = (*env)->GetObjectClass(env, thisFdInstance);
	if(fdClass == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_getfd;
	}

	// Get the field identifier for the primitive integer
	// that is part of the FileDescriptor class.
#ifdef __WIN32__
	fdFdField = (*env)->GetFieldID(env, fdClass, "handle", "J");
#else
	fdFdField = (*env)->GetFieldID(env, fdClass, "fd", "I");
#endif
	if (fdFdField == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_getfd;
	}

	// Recover the value
#ifdef __WIN32__
	fd_value = (SOCKET)(*env)->GetLongField(env, thisFdInstance, fdFdField);
#else
	fd_value = (*env)->GetIntField(env, thisFdInstance, fdFdField);
#endif

end_getfd:
	if (thisClass != NULL) {
		(*env)->DeleteLocalRef(env, thisClass);
	}
	if (fdClass != NULL) {
		(*env)->DeleteLocalRef(env, fdClass);
	}
	if (thisFdInstance != NULL) {
		(*env)->DeleteLocalRef(env, thisFdInstance);
	}

	return fd_value;
}

static void setIcmpFd(JNIEnv *env, jobject instance, onms_socket fd_value) {
	jclass	thisClass = NULL;
	jclass	fdClass   = NULL;

	jfieldID thisFdField    = NULL;
	jobject  thisFdInstance = NULL;

	jfieldID fdFdField = NULL;

	// Find the class that describes ourself.
	thisClass = (*env)->GetObjectClass(env, instance);
	if(thisClass == NULL) {
		goto end_setfd;
	}

	// Find the java.io.FileDescriptor class
	thisFdField = (*env)->GetFieldID(env, thisClass, "m_rawFd", "Ljava/io/FileDescriptor;");
	if(thisFdField == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_setfd;
	}

	// Get the instance of the FileDescriptor class from the instance of ourself
	thisFdInstance = (*env)->GetObjectField(env, instance, thisFdField);
	if(thisFdInstance == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_setfd;
	}

	// Get the class object for the java.io.FileDescriptor
	fdClass = (*env)->GetObjectClass(env, thisFdInstance);
	if(fdClass == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_setfd;
	}

	// Get the field identifier for the primitive integer
	// that is part of the FileDescriptor class.
#ifdef __WIN32__
	fdFdField = (*env)->GetFieldID(env, fdClass, "handle", "J");
#else
	fdFdField = (*env)->GetFieldID(env, fdClass, "fd", "I");
#endif
	if(fdFdField == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_setfd;
	}

#ifdef __WIN32__
	(*env)->SetLongField(env, thisFdInstance, fdFdField, fd_value);
#else
	(*env)->SetIntField(env, thisFdInstance, fdFdField, fd_value);
#endif
	(*env)->DeleteLocalRef(env, thisFdInstance);

end_setfd:
	if (thisClass != NULL) {
		(*env)->DeleteLocalRef(env, thisClass);
	}
	if (fdClass != NULL) {
		(*env)->DeleteLocalRef(env, fdClass);
	}
}

static jobject newInetAddressFromBytes(JNIEnv *env, unsigned char* addr, u_int size) {
	jclass addrClass;
	jmethodID addrByAddressMethodID;
	jobject addrInstance = NULL;
	jbyteArray addrArray = NULL;

	// Copy the address into a jbyteArray
	addrArray = (*env)->NewByteArray(env, size);
	if(addrArray != NULL && (*env)->ExceptionOccurred(env) == NULL) {
		(*env)->SetByteArrayRegion(env,
								   addrArray,
								   0,
								   (jsize)size,
								   (jbyte *)addr);
	}
	if ((*env)->ExceptionOccurred(env) != NULL) {
		goto end_inet;
	}

	// Load the class
	addrClass = (*env)->FindClass(env, "java/net/InetAddress");
	if(addrClass == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_inet;
	}

	// Find the static method
	addrByAddressMethodID = (*env)->GetStaticMethodID(env,
													  addrClass,
													  "getByAddress",
													  "([B)Ljava/net/InetAddress;");
	if(addrByAddressMethodID == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_inet;
	}

	// Invoke it!
	addrInstance = (*env)->CallStaticObjectMethod(env,
												  addrClass,
												  addrByAddressMethodID,
												  addrArray);
	end_inet:
	if(addrClass != NULL) {
		(*env)->DeleteLocalRef(env, addrClass);
	}
	if(addrArray != NULL) {
		(*env)->DeleteLocalRef(env, addrArray);
	}
	return addrInstance;
}

static in_addr_t getInetAddress(JNIEnv *env, jobject instance) {
	jclass		addrClass = NULL;
	jmethodID	addrArrayMethodID = NULL;
	jbyteArray	addrData = NULL;
	in_addr_t	retAddr = 0;

	// Load the class
	addrClass = (*env)->GetObjectClass(env, instance);
	if(addrClass == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_inet;
	}

	// Find the method
	addrArrayMethodID = (*env)->GetMethodID(env,
		addrClass,
		"getAddress",
		"()[B");
	if(addrArrayMethodID == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_inet;
	}

	addrData = (*env)->CallObjectMethod(env,instance,addrArrayMethodID);
	if(addrData == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_inet;
	}

	// The byte array returned from java.net.InetAddress.getAddress()
	// (which was fetched above and is stored as a jbyteArray in addrData)
	// is in network byte order (high byte first, AKA big endian).
	// the value of in_addr_t is also in network byte order, so no
	// conversion needs to be performed.
	(*env)->GetByteArrayRegion(env,
		addrData,
		0,
		4,
		(jbyte *) &retAddr);

end_inet:
	if (addrClass != NULL) {
		(*env)->DeleteLocalRef(env, addrClass);
	}
	if (addrData != NULL) {
		(*env)->DeleteLocalRef(env, addrData);
	}

	return retAddr;
}

static void getInet6Address(JNIEnv *env, jobject instance, unsigned char addr[]) {
	jclass		addrClass = NULL;
	jmethodID	addrArrayMethodID = NULL;
	jbyteArray	addrData = NULL;

	// Load the class
	addrClass = (*env)->GetObjectClass(env, instance);
	if(addrClass == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_inet;
	}

	// Find the method
	addrArrayMethodID = (*env)->GetMethodID(env,
											addrClass,
											"getAddress",
											"()[B");
	if(addrArrayMethodID == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_inet;
	}

	addrData = (*env)->CallObjectMethod(env,instance,addrArrayMethodID);
	if(addrData == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_inet;
	}

	// The byte array returned from java.net.InetAddress.getAddress()
	// (which was fetched above and is stored as a jbyteArray in addrData)
	// is in network byte order (high byte first, AKA big endian).
	// the value of in_addr_t is also in network byte order, so no
	// conversion needs to be performed.
	(*env)->GetByteArrayRegion(env,
							   addrData,
							   0,
							   16,
							   (jbyte *)addr);
end_inet:
	if (addrClass != NULL) {
		(*env)->DeleteLocalRef(env, addrClass);
	}
	if (addrData != NULL) {
		(*env)->DeleteLocalRef(env, addrData);
	}
	return;
}


static void throwError(JNIEnv *env, char *exception, char *errorBuffer) {
	jclass ioException = (*env)->FindClass(env, exception);
	if (ioException != NULL) {
		(*env)->ThrowNew(env, ioException, errorBuffer);
	}
}

/*
* Opens a new raw socket that is set to send
* and receive the ICMP protocol. The protocol
* for 'icmp' is looked up using the function
* getprotobyname() and passed to the newly
* constructed socket.
*
* An exception is thrown if either of the
* getprotobyname() or the socket() calls fail.
*
* Class:     org_opennms_protocols_icmp_ICMPSocket
* Method:    initSocket
* Signature: ()V
*/
JNIEXPORT void JNICALL
Java_org_opennms_protocols_icmp_ICMPSocket_initSocket (JNIEnv *env, jobject instance) {
	struct protoent *proto;
	onms_socket icmp_fd = INVALID_SOCKET;
	int sock_type = SOCK_RAW;
#ifdef __WIN32__
	int result;
	WSADATA info;

	result = WSAStartup(MAKEWORD(2,2), &info);
	if (result != 0)
	{
		char errBuf[128];
		sprintf(errBuf, "WSAStartup failed: %d", result);
		throwError(env, "java/net/IOException", errBuf);
		return;
	}
#endif

    int protocol;
    int family = getSocketFamily(env, instance);
    if (family == AF_INET) {
        protocol = IPPROTO_ICMP;
    } else if (family == AF_INET6) {
        protocol = IPPROTO_ICMPV6;
    } else {
        // TODO: Fail.
    }

    // Attempt to use a diagram (UDP) socket
    int type = SOCK_DGRAM;
    icmp_fd = socket(family, type, protocol);
	if (icmp_fd == SOCKET_ERROR) {
        // We weren't able to succesfully aquire the diagram socket, let's try a raw socket instead
        type = SOCK_RAW;
        icmp_fd = socket(family, type, protocol);
        if (icmp_fd == SOCKET_ERROR) {
		    char errBuf[128];
		    int	savedErrno  = errno;
		    snprintf(errBuf, sizeof(errBuf), "System error creating ICMP socket (%d, %s)", savedErrno, strerror(savedErrno));
		    throwError(env, "java/net/SocketException", errBuf);
		    return;
        }
	}

    if (type == SOCK_DGRAM) {
        // When using a diagram socket on Linux, the ID in the ICMP Echo Request header
        // is replaced with the source port. In order to generate packets with the
        // correct ID we need to bind the socket to this port.
        
        int pingerId = getPingerId(env, instance);
      
        if (family == AF_INET6) {
		    struct sockaddr_in6 source_address;
		    memset(&source_address, 0, sizeof(struct sockaddr_in6));
		    source_address.sin6_family = family;
		    source_address.sin6_port = htons(pingerId);

		    if(bind(icmp_fd, (struct sockaddr *)&source_address, sizeof(struct sockaddr_in6))) {
		    	char errBuf[128];
		    	int	savedErrno  = errno;
		    	snprintf(errBuf, sizeof(errBuf), "Failed to bind ICMPv6 socket (%d, %s)", savedErrno, strerror(savedErrno));
		    	throwError(env, "java/net/SocketException", errBuf);
		    	return;
		    }
        } else {
		    struct sockaddr_in source_address;
		    memset(&source_address, 0, sizeof(struct sockaddr_in));
		    source_address.sin_family = family;
		    source_address.sin_port = htons(pingerId);

		    if(bind(icmp_fd, (struct sockaddr *)&source_address, sizeof(struct sockaddr_in))) {
		    	char errBuf[128];
		    	int	savedErrno  = errno;
		    	snprintf(errBuf, sizeof(errBuf), "Failed to bind ICMPv4 socket (%d, %s)", savedErrno, strerror(savedErrno));
		    	throwError(env, "java/net/SocketException", errBuf);
		    	return;
		    }
        }
    }

	setIcmpFd(env, instance, icmp_fd);
	return;
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

	int family = getSocketFamily(env, instance);

	// Get the current descriptor's value
	onms_socket fd_value = getIcmpFd(env, instance);
	if((*env)->ExceptionOccurred(env) != NULL) {
		goto end_recv;
	} else if(fd_value < 0) {
		throwError(env, "java/io/IOException", "Invalid Socket Descriptor");
		goto end_recv;
	}

	// Allocate a buffer to receive data if necessary.
	// This is probably more than necessary, but we don't
	// want to lose messages if we don't need to. This also
	// must be dynamic for MT-Safe reasons and avoids blowing
	// up the stack.
	//FIXME: Is this really necessary?
	inBuf = malloc(MAX_PACKET);
	if(inBuf == NULL) {
		throwError(env, "java/lang/OutOfMemoryError", "Failed to allocate memory to receive ICMP datagram");
		goto end_recv;
	}
	memset(inBuf, 0, MAX_PACKET);

	// Clear out the address structures where the
	// operating system will store the to/from address
	// information.
	if (family == AF_INET) {
		memset((void *)&inAddrV4, 0, sizeof(inAddrV4));
		inAddrLen = sizeof(inAddrV4);
		inAddr = (struct sockaddr *)&inAddrV4;
	} else if (family == AF_INET6) {
		memset((void *)&inAddrV6, 0, sizeof(inAddrV6));
		inAddrLen = sizeof(inAddrV6);
		inAddr = (struct sockaddr *)&inAddrV6;
	} else {
		// TODO: ERR
		goto end_recv;
	}

	// Receive the data from the operating system. This
	// will also include the IP header that precedes
	// the ICMP data, we'll strip that off later.
	iRC = (int)recvfrom(fd_value, inBuf, MAX_PACKET, 0, inAddr, &inAddrLen);
	if(iRC == SOCKET_ERROR) {
		// Error reading the information from the socket
		char errBuf[256];
		int savedErrno = errno;
		snprintf(errBuf, sizeof(errBuf), "Error reading data from the socket descriptor (iRC = %d, fd_value = %d, %d, %s)", iRC, fd_value, savedErrno, strerror(savedErrno));
		throwError(env, "java/io/IOException", errBuf);
		goto end_recv;
	} else if(iRC == 0) {
		// Error reading the information from the socket
		throwError(env, "java/io/EOFException", "End-of-File returned from socket descriptor");
		goto end_recv;
	}

	if (family == AF_INET) {
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
	} else if (family == AF_INET6) {
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

    int family = getSocketFamily(env, instance);

	// Recover the operating system file descriptor
	// so that we can use it in the sendto function.
	onms_socket icmpfd = getIcmpFd(env, instance);

	// Check for exception
	if((*env)->ExceptionOccurred(env) != NULL) {
		goto end_send;
	}

	// Check the descriptor
	if(icmpfd < 0) {
		throwError(env, "java/io/IOException", "Invalid file descriptor");
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
	if (family == AF_INET) {
		Addr = (struct sockaddr*)&AddrV4;
		AddrLen = sizeof(AddrV4);

		memset(&AddrV4, 0, AddrLen);
		AddrV4.sin_family = AF_INET;
		AddrV4.sin_port   = 0;
		AddrV4.sin_addr.s_addr = getInetAddress(env, addrInstance);
		if((*env)->ExceptionOccurred(env) != NULL) {
			goto end_send;
		}
	} else if (family == AF_INET6) {
		Addr = (struct sockaddr*)&AddrV6;
		AddrLen = sizeof(AddrV6);

		memset(&AddrV6, 0, AddrLen);
		AddrV6.sin6_family = AF_INET6;
		AddrV6.sin6_port   = 0;

		getInet6Address(env, addrInstance, AddrV6.sin6_addr.s6_addr);
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
	if (family == AF_INET) {
		if(bufferLen >= (OPENNMS_TAG_OFFSET + OPENNMS_TAG_LEN)
		   && ((icmphdr_t *)outBuffer)->ICMP_TYPE == 0x08
		   && memcmp((char *)outBuffer + OPENNMS_TAG_OFFSET, OPENNMS_TAG, OPENNMS_TAG_LEN) == 0) {
			shouldUpdate = 1;

			// Checksum will be computed by system
			((icmphdr_t *)outBuffer)->ICMP_CHECKSUM = 0;
		}
	} else if (family == AF_INET6) {
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

	iRC = (int)sendto(icmpfd,
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
	const onms_socket fd_value = getIcmpFd(env, instance);
	if(fd_value >= 0 && (*env)->ExceptionOccurred(env) == NULL) {
		close(fd_value);
		setIcmpFd(env, instance, INVALID_SOCKET);
#ifdef __WIN32__
		WSACleanup();
#endif
	}
}
