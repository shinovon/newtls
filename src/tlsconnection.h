#ifndef _TLSCONNECTION_H_
#define _TLSCONNECTION_H_
 
#include <securesocketinterface.h>
#include <genericsecuresocket.h>
#include <ssl.h>
#include <tlsprovinterface.h> 
#include <tlstypedef.h>
#include <comms-infras/statemachine.h>
#include "LOGFILE.H"

class CMbedContext;

//Tls protocol Panics
enum TTlsPanic
{
	ETlsPanicClientHelloMsgNotSent = 0,
	ETlsPanicHandshakeMsgAlreadyExists,
	ETlsPanicChangeCipherMsgNotReceived,
	ETlsPanicServerHelloMsgNotReceived,
	ETlsPanicNullHandshakeMsg,
	ETlsPanicNullServerCertificate,
	ETlsPanicInvalidProcessState,
	ETlsPanicInvalidTlsSession,
	ETlsPanicNullTlsSession,
	ETlsPanicTlsProviderNotReady,
	ETlsPanicNoCA,
	ETlsPanicNoDataToProcess,
	ETlsPanicNoUserData,
	ETlsPanicUserDataAlreadySet,
	ETlsPanicNullPointerToHandshakeHeaderBuffer,
	ETlsPanicNullPointerToHandshakeRecordParser,
	ETlsPanicAppDataResumeButNotStarted,
	ETlsPanicHelloRequestRecWhileInAppData,
	ETlsPanicSignatureAlreadyExists,
	ETlsPanicNullStateMachineHistory,
	ETlsPanicNullStateMachine,
	ETlsPanicInvalidStateMachine,
	ETlsPanicStateMachineAlreadyExists,
	ETlsPanicStateMachineStopped,
	ETlsPanicInvalidStatus,
	ETlsPanicAlertReceived,
	ETlsPanicAlreadyActive,
};

// Constant values
const TInt KProtocolDescMinSize = 8;	//< Minimum size of the descriptor for the Protocol name

/*
In RFC2716 (PPP EAP TLS Authentication Protocol) section 3.5, label is defined as "client EAP encryption"

In draft-josefsson-pppext-eap-tls-eap-02 (Protected EAP Protocol (PEAP)) section 2.8, label is
defined as "client PEAP encryption". However, most of radius servers use "client EAP encryption" 
as the constant keying string.

In draft-ietf-pppext-eap-ttls-04 EAP Tunneled TLS Authentication Protocol (TTLS) section 7,
label is defined as "ttls keying material".

Following max size is sufficient to all those cases.
*/
const TInt KKeyingLabelMaxSize = 100;

// TlsConnection supported protocols 
_LIT( KProtocolVerSSL30, "SSL3.0" );	//< SSL 3.0 Protocol
_LIT( KProtocolVerTLS10, "TLS1.0" );	//< TLS 1.0 Protocol
_LIT( KProtocolVerTLS11, "TLS1.1" );	//< TLS 1.1 Protocol
_LIT( KProtocolVerTLS12, "TLS1.2" );	//< TLS 1.2 Protocol
_LIT( KProtocolVerTLS13, "TLS1.3" );	//< TLS 1.3 Protocol

class CTlsConnection : public CActive, public MSecureSocket, public MStateMachineNotify
/**
  * A secure (SSL v3.0 or TLS vl.0) connection.
  * Implements the MSecureSocket interface used by the SECURESOCKET.DLL to talk to 
  * the protocol implementation. Note that it only implements Client-mode support
  * for the SSL v3.0 and TLS v1.0 protocols.
  * Server-mode operation is NOT supported. 
  */
{
public:
	IMPORT_C static MSecureSocket* NewL(RSocket& aSocket, const TDesC& aProtocol);
	IMPORT_C static MSecureSocket* NewL(MGenericSecureSocket& aSocket, const TDesC& aProtocol);

	IMPORT_C static void UnloadDll(TAny* /*aPtr*/);

	 ~CTlsConnection();

	// MSecureSocket interface
	virtual TInt AvailableCipherSuites(TDes8& aCiphers);
	virtual void CancelAll();
	virtual void CancelHandshake();
	virtual void CancelRecv();
	virtual void CancelSend();
	virtual const CX509Certificate* ClientCert();
	virtual TClientCertMode ClientCertMode(); 
	virtual void Close();
	virtual TInt CurrentCipherSuite(TDes8& aCipherSuite);
	virtual TDialogMode	DialogMode(); 
	virtual void FlushSessionCache();
	virtual TInt GetOpt(TUint aOptionName,TUint aOptionLevel,TDes8& aOption);
	virtual TInt GetOpt(TUint aOptionName,TUint aOptionLevel,TInt& aOption);
	virtual TInt Protocol(TDes& aProtocol);
	virtual void Recv(TDes8& aDesc, TRequestStatus & aStatus);
	virtual void RecvOneOrMore(TDes8& aDesc, TRequestStatus& aStatus, TSockXfrLength& aLen);
	virtual void RenegotiateHandshake(TRequestStatus& aStatus);
	virtual void Send(const TDesC8& aDesc, TRequestStatus& aStatus);
	virtual void Send(const TDesC8& aDesc, TRequestStatus& aStatus, TSockXfrLength& aLen);
	virtual const CX509Certificate* ServerCert();
	virtual TInt SetAvailableCipherSuites(const TDesC8& aCiphers);
	virtual TInt SetClientCert(const CX509Certificate& aCert);
	virtual TInt SetClientCertMode(const TClientCertMode aClientCertMode);
	virtual TInt SetDialogMode(const TDialogMode aDialogMode);
	virtual TInt SetOpt(TUint aOptionName,TUint aOptionLevel, const TDesC8& aOption=KNullDesC8());
	virtual TInt SetOpt(TUint aOptionName,TUint aOptionLevel,TInt aOption);
	virtual TInt SetProtocol(const TDesC& aProtocol);
	virtual TInt SetServerCert(const CX509Certificate& aCert);
	virtual void StartClientHandshake(TRequestStatus& aStatus);
	virtual void StartServerHandshake(TRequestStatus& aStatus);

	// MStateMachineNotify interface
	virtual TBool OnCompletion(CStateMachine* aStateMachine); 
   
	CMbedContext&				MbedContext();

	// Retrieve or confirm the Connection states
	TBool IsHandshaking() const;
	TBool IsReNegotiating() const;
	TBool IsInDataMode() const;
	TBool IsIdle() const;

	// Methods from CActive
	void RunL();
	void DoCancel();
	
	void DoHandshake();

protected:
	CTlsConnection(); 
	void ConstructL(RSocket& aSocket, const TDesC& aProtocol);
	void ConstructL(MGenericSecureSocket& aSocket, const TDesC& aProtocol);
protected:
	TDialogMode			iDialogMode;
	CX509Certificate* iClientCert;
	CX509Certificate* iServerCert;
	
	CGenericSecureSocket<RSocket>* iGenericSocket; // owned
public:
	MGenericSecureSocket* iSocket;
protected:
	CMbedContext* iMbedContext;
	
};

inline CMbedContext& CTlsConnection::MbedContext()
{
	return *iMbedContext;
}

#endif
