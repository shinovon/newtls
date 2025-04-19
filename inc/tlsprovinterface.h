// Copyright (c) 2003-2009 Nokia Corporation and/or its subsidiary(-ies).
// All rights reserved.
// This component and the accompanying materials are made available
// under the terms of the License "Symbian Foundation License v1.0"
// which accompanies this distribution, and is available
// at the URL "http://www.symbianfoundation.org/legal/sfl-v10.html".
//
// Initial Contributors:
// Nokia Corporation - initial contribution.
//
// Contributors:
//
// Description:
// This file contains the interface exported from Tls provider
// 
//



/**
 @file 
 @internalComponent 
*/

#ifndef __TLSPROVINTERFACE_H__
#define __TLSPROVINTERFACE_H__

#include <e32std.h>
#include <e32base.h>
#include <hash.h>
#include "tlstypedef.h"
#include "ct.h"
#include "pkixcertchain.h"

class CTlsSessionImpl;
class CTlsProviderImpl;

/**
This class provides a wrapper around a MTLSSession object. A number of its methods simply
call corresponding MTLSSession methods. However it also acts as an intermediary between the 
client and cryptographic libraries where services not involving tokens are required.
@internalComponent
@released
*/
class CTLSSession : CBase
	{
friend class CTlsSessionImpl;
public:

	/**
	The ClientKeyExchange operation includes the following. The generation of the pre-master secret,
	The derivation of the master secret, Generation of keys for bulk data encryption and MAC secrets, 
	If weak Export cipher is used, generation of Weak keys, Creation of CTLSSession's member objects responsible for symmetric encryption and HMAC hashing. 
	ClientKeyExchange message created and returned
	@param aClientKeyExch - The client key exchange message
	@param aStatus - Asynchronous request status value
	*/
	IMPORT_C void ClientKeyExchange(		
		HBufC8*& aClientKeyExch,			
		TRequestStatus& aStatus);

	/**
	This asynchronous method is used to retrieve a client certificate in its encoded form, which would be normally send 
	out to the server. If the connection has reached a stage where the session would have been cached, then this API would 
	retrieve the information (CCTCertInfo) from token's cache and returns the retrieved certificate from the Certstore. In all 
	other case, the information (CCTCertInfo) is stored locally
	@param aEncodedClientCert- The client certificate used in this session in encoded form
	@param aStatus - Asynchronous request status value
	*/
	IMPORT_C void ClientCertificate(
		HBufC8*& aEncodedClientCert,
		TRequestStatus& aStatus);

	/**
	This asynchronous method is used to retrieve a client certificate in an X509 form, which would be normally used for 
	displaying it to the user. If the connection has reached a stage where the session would have been cached, then this API
	would retrieve the information (CCTCertInfo) from token's cache and returns the retrieved certificate from the Certstore. 
	In all other case, the information (CCTCertInfo) is stored locally.
	@param aX509ClientCert - The client certificate used in this session in X509 form 
	@param aStatus - Asynchronous request status value
	*/
	IMPORT_C void ClientCertificate(
		CX509Certificate*& aX509ClientCert,
		TRequestStatus& aStatus);

	/**
	This asynchronous method is used to retrieve a client certificate chain in its encoded form, which would be normally send 
	out to the server. If the connection has reached a stage where the session would have been cached, then this API would 
	retrieve the information (CCTCertInfo) from token's cache and returns the retrieved certificate from the Certstore. In all 
	other case, the information (CCTCertInfo) is stored locally
	@param aClientCertArray- The client certificate chain used in this session in encoded form
	@param aStatus - Asynchronous request status value
	*/
	IMPORT_C void ClientCertificate(
		RPointerArray<HBufC8>* aClientCertArray,
		TRequestStatus& aStatus);

	/**
	This asynchronous method is used to retrieve the associated server certificate of the current session in its X509 form, 
	which would be normally used for displaying it to the user. If the connection has reached a stage where the session would have been cached,
	then this API would retrieve the certificate from the Token. In all other case, the certificate is stored locally.
	@param aX509ServerCert - The server certificate used in this session in X509 form 
	@param aStatus - Asynchronous request status value
	*/
	IMPORT_C void ServerCertificate(
		CX509Certificate*& aX509ServerCert,
		TRequestStatus& aStatus);

	/**
	This asynchronous method generates a SSL/TLS protocol's Client 'Finished' message. This input for this message  is a hash 
	of concatenation of all the handshake messages exchanged thus far (as specified by RFC2246 and SSL3.0 specification). 
	In order to create the required output, 
	@param iMd5DigestInput - The input data.
	@param iShaDigestInput - The input data.
	@param aOutput - The result of the operation i.e. the Client's 'Finished' message.
	@param aStatus - Asynchronous request status value that can be checked by the client.
	*/
	IMPORT_C void ClientFinishedMsgL(		
		CMessageDigest* aMd5DigestInput,
		CMessageDigest* aShaDigestInput,
		HBufC8*& aOutput, 
		TRequestStatus& aStatus);

	/**
	This method generates ServerFinished message given as an input hash of concatenation of all handshake messages 
	(as specified by RFC2246 and SSL3.0 specification). In order to create required output, the function calls MTLSSesssion::PHash 
	with the following input string:
	@param iMd5DigestInput - the input data, 
	@param iShaDigestInput - the input data, 
	@param aActualFinishedMsg - the result of the operation - ServerFinished message,
	@param aStatus - Asynchronous request status value that can be checked by the client.
	*/
	IMPORT_C void VerifyServerFinishedMsgL(	
		CMessageDigest* aMd5DigestInput,
		CMessageDigest* aShaDigestInput,	
		const TDesC8& aActualFinishedMsg,  
		TRequestStatus& aStatus);

	/**
	Plain text, the overview for this function.
	@released optional further explanation may appear here
	@return Explanation of the object returned
	@param iMd5DigestInput - the input data, 
	@param iShaDigestInput - the input data,
	@param aOutput - the result of the operation - ServerFinished message,
	@param aStatus - Asynchronous request status value that can be checked by the client.
	@post CClassExample object is now fully initialised
	*/
	IMPORT_C void CertificateVerifySignatureL(
		CMessageDigest* aMd5DigestInput,
		CMessageDigest* aShaDigestInput,
		HBufC8*& aOutput, 
		TRequestStatus& aStatus);

	/**
	On receiving an input data, this method computes the MAC, appends it into the input and encrypts the whole block. 
	The encryption and decryption objects should have been created in an earlier call to ClientKeyExchange before calling this API
	@return An SSL/TLS spec alert code will be returned if for any error, KErrNone otherwise
	@param aInput - The data to be encrypted
	@param aOutput - The encrypted output
	@param aSeqNumber - The sequence number of the message packet, the value is used for computing the MAC.
	@param aType - The type of message (e.g Handshake, alert, application data, etc) , the value is used for computing the MAC.
	*/
	IMPORT_C TInt EncryptL(
		const TDesC8& aInput,
		HBufC8*& aOutput,
        TInt64& aSeqNumber,
		TRecordProtocol& aType);
	
	/**
	On receiving an input data, this method decrypts the data, parses the actual data from its MAC and verifies it.
	If the MAC is verified correctly the output will be returned
	The encryption and decryption objects should have been created in an earlier call to ClientKeyExchange before calling this API
	@return An SSL/TLS spec alert code will be returned if for any error, KErrNone otherwise
	@param aInput - The data to be decrypted
	@param aOutput - Decrypted  message data
	@param aSeqNumber - The sequence number of the message packet, the value is used for computing the MAC.
	@param aType - The type of message (e.g Handshake, alert, application data, etc) , the value is used for computing the MAC.
	*/
	IMPORT_C TInt DecryptAndVerifyL(
		const TDesC8& aInput,
		HBufC8*& aOutput,
		TInt64& aSeqNumber,
		TRecordProtocol& aType);

	/**
	The first call to CTLSProvider takes place before ClientHello is send, then as the handshake progress, the information relevant 
	for Provider and token will be gradually filled in the structure. The ownership will then be passed to the CTLSSession object. 
	This function returns the pointer to the structure. 
	@return A pointer to TTlsCryptoAttributes
	*/	
	IMPORT_C CTlsCryptoAttributes* Attributes() ;

	/**
	This synchronous method provides the EAP string that is derived or 
	computed from master secret key, "client key encryption" string (or any
	string from client), client and server hello random values. The EAP
	string returned would be of 128 + 64 bytes length. 
	@pre object should should have been initialised (by call to InitL) and master 
		 secret generated (by call to ClientKeyExchange) before call to this method
	@post session is cached in case of successful handshake 
	@param aLabel			   Contains the string "client key encryption".
	@param aMasterSecretInput  The structure containing "Client and Server Random" binary data.
	@param aKeyingMaterial     Contains the EAP 128 + 64 bytes string.
	@see CTlsSessionImpl::ClientKeyExchange
	@return TInt Returns an SSL/TLS specific Alert code in case of an error.
	*/
	IMPORT_C TInt KeyDerivation(
		const TDesC8& aLabel, 
		const TTLSMasterSecretInput& aMasterSecretInput, 
		TDes8& aKeyingMaterial);
		
	/**
	This method cancels all the asynchronous operations of CTLSSession 
	*/
	IMPORT_C void CancelRequest();
	IMPORT_C ~CTLSSession();
//private:
	/**
	Allocates and constructs a new CTlsSessionImpl object.
	@return a pointer to CTLSSession
	@param aSessionPtr - a session pointer to CTLsSessionImpl
	*/
	IMPORT_C static CTLSSession* NewL(CTlsSessionImpl* aSessionPtr);

	CTLSSession(CTlsSessionImpl* aSessionPtr);
private:
	CTlsSessionImpl* iTlsSessionImpl;
	
	};

/**
This class allows direct access to methods which are not specific to a particular token.
It also indirectly provides access to methods which calculate connection-specific settings. 
It enables the TLS protocol module to generate the ClientHello message without committing to use a specific token. 
Once the protocol module has enough information to select an appropriate token,
it can use this class as a factory to create a CTLSSession object. 
@internalComponent
@released
@see TLS Provider API  
*/
class CTLSProvider : CBase
	{
public:
	/**
	creates a new CTLSProvider object
	@return pointer to CTLSProvider.
	*/
	IMPORT_C static CTLSProvider* ConnectL();
	
	/**
	This synchronous method is used to request a number of randomly generated bytes from 
	the TLS Provider. This function will set a length of aBuffer to zero in case of any
	problems with random number generation.
	@param aBuffer - A buffer for the generated random value.
	@return A buffer of Random bytes in the aBuffer argument.
	*/
	IMPORT_C void GenerateRandom(TDes8& aBuffer);

	/**
	This method provides a CTLSSession object to the protocol when the handshake has reached
	the stage where ServerHelloDone has been recevied. The main process of this function is to
	select the token and initialize it.
	@param aTlsSession - A newly created session relating to the server.
	@param aStatus - The result of the server certificate verification.
	@return Void, as this is an asynchronous method. On completion of the asynchronous request, the result will be read from the aTlsSession, aClientKeyExch and aStatus parameters.
	*/
	IMPORT_C void CreateL( 
		CTLSSession*& aTlsSession,		
		TRequestStatus& aStatus);	
			
	/**
	This asynchronous method reads the list of supported cipher suites from the available tokens. This list is used within the SSL/TLS Protocol's ClientHello message. 
	@param aUserCipherSuiteList - This is used to pass back (by reference) a list of cipher suites that are 
	supported by the Security subsystem and the cryptographic tokens available in the device.
	@param aStatus - Asynchronous request status value that can be checked by the client.
	@return Void, as this is an asynchronous method. On completion of the asynchronous request, the results will be in the aCipherSuite and aStatus parameters.
	*/
	IMPORT_C void CipherSuitesL(
		RArray<TTLSCipherSuite>& aUserCipherSuiteList, 
		TRequestStatus& aStatus);

	/**
	This asynchronous method is used to validate a received Server certificate.
	@param aEncodedServerCerts A string with server certificates (read from ServerCertificate message).
	@param aServerCert - The server certificate returned in a X509 format
	@param aStatus - The result of the server certificate verification.
	@return Void, as this is an asynchronous method. If the dialog mode is set to true, then a dialog will be popped if the server certificate is invalid. The user then has the choice to close the connection or continue.
	*/
	IMPORT_C void VerifyServerCertificate(
		const TDesC8& aEncodedServerCerts, 
		CX509Certificate*& aServerCert,		  			
		TRequestStatus& aStatus);

	/**
	This asynchronous method uses the server's public key to ensure that the signature was indeed created by the server. The result of this operation will be written in the aResult parameter..
	@return Tbool Explanation of the object returned
	@param aServerPublicKey The server's public key; used to decrypt the signature created with the server's private key.
	@param aDigest - The data which we expect to extract from the server's signature when decrypted.
	@param aSig- The server's signature.
	@return ETrue if positively verified, otherwise EFalse
	*/
	IMPORT_C TBool VerifySignatureL(
		const CSubjectPublicKeyInfo& aServerPublicKey, 
		const TDesC8& aDigest, 
		const TDesC8& aSig);

	/**
	This asynchronous method will provide a session identifier object associated with a given server indicated by the aServerName argument
	@param aServerName - The name of the server the SSL/TLS protocol is intending to connect to.
	@param aSessionId - The respective session id from the session.
	@param aStatus - Asynchronous request status value that can be checked by the client.
	@return Void, as this is an asynchronous method. On completion of the asynchronous request, the result will be read from the aSessionId parameter.
	*/
	IMPORT_C void GetSessionL(	
		TTLSServerAddr& aServerName,
		TTLSSessionId& aSessionId,
		TRequestStatus& aStatus) ;

	/**
	This asynchronous method will clear the session identified by the ServerName and Session.iId in aServerNameAndId.This operation may fail if the session cached on a token is in use (this maybe possible if a hardware token, e.g. a WIM is used. It is unlikely in the case of a software token implementation). 
	@param aServerNameAndId - The name of the server and the corresponding session Id 
	@param aStatus - Asynchronous request status value , ETrue if the cache is cleared otherwise EFalse.
	@return Void, as this is an asynchronous method. On completion of the asynchronous request, the result will be read from the aStatus parameter.
	*/
	IMPORT_C void ClearSessionCacheL(
		TTLSSessionNameAndID& aServerNameAndId, 		
		TRequestStatus& aStatus);

	/**
	The first call to CTLSProvider takes place before ClientHello is send, then as the handshake progress, the information relevant for Provider and token will be gradually filled in the  structure returned by this API, If the structure already exists, then the pointer to the same structure is returned.
	@return A pointer to TTlsCryptoAttributes.
	*/
	IMPORT_C CTlsCryptoAttributes* Attributes();
	
	/**
	This sets the TLS session pointer
	@return pointer to the CTLSSession
	*/
	IMPORT_C CTLSSession* TlsSessionPtr();

	/**
	This method cancels all the asynchronous operations of CTLSProvider
	*/		
	IMPORT_C void CancelRequest();

	/**
	reconnect the connection if it fails at initial stage of conneciton 
	*/
	IMPORT_C void ReConnectL();

	IMPORT_C ~CTLSProvider();

private:
	/**
	An object of this class will be provided to the SSL/TLS Protocol client when it first requests a service from the TLS Provider token interface
	@param aProviderPtr 
	*/
	CTLSProvider(CTlsProviderImpl* aProviderPtr);
private:
	CTlsProviderImpl* iTlsProviderImpl;	
	CTLSSession** iTlsSession;
	MCTToken* iTokenInterface;
	};

#endif	
	
