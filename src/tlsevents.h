/**
 * Copyright (c) 2024 Arman Jussupgaliyev
 * Copyright (c) 2009 Nokia Corporation
 */

#ifndef TLSEVENTS_H
#define TLSEVENTS_H

#include <comms-infras/statemachine.h>
#include <comms-infras/asynchevent.h>

class MGenericSecureSocket;
class RSocket;

class CTlsConnection;
class CMbedContext;

class CRecvEvent;
class CSendEvent;
class CHandshakeEvent;

class CRecvData : public CStateMachine
{
public:
	static CRecvData* NewL(CTlsConnection& aTlsConnection); 
	~CRecvData();
	
	void Start(TRequestStatus* aClientStatus, MStateMachineNotify* aStateMachineNotify);
	
	void Suspend();
	void Resume();
	
	void SetSockXfrLength(TInt* aLen);

protected:
	CRecvData(CTlsConnection& aTlsConnection);
	void ConstructL(CTlsConnection& aTlsConnection);

	virtual void DoCancel();
	virtual void OnCompletion();

protected:
	CTlsConnection& iTlsConnection;
	CRecvEvent& iRecvEvent;
	
	TInt* iSockXfrLength;
};

inline void CRecvData::Start(TRequestStatus* aClientStatus, MStateMachineNotify* aStateMachineNotify)
{
	CStateMachine::Start(aClientStatus, NULL, aStateMachineNotify);
}

inline void CRecvData::SetSockXfrLength(TInt* aLen)
{
	iSockXfrLength = aLen;
}



class CRecvEvent : public CAsynchEvent
{
public:
	CRecvEvent(CMbedContext& aMbedContext, MGenericSecureSocket& aSocket);
	~CRecvEvent();
	
	virtual CAsynchEvent* ProcessL(TRequestStatus& aStatus);
	
	void SetUserData(TDes8* aData);
	void SetUserMaxLength(TInt aMaxLength);
	
	void CancelAll();
	void ReConstruct(CStateMachine* aStateMachine);
	
	TDes8* UserData();
	
	MGenericSecureSocket& iSocket;

protected:
	CMbedContext& iMbedContext;
	
	TDes8* iUserData;
	TInt iUserMaxLength;

	HBufC8* iHeaderData;
	
public:
	TPtr8 iPtrHBuf;
	TInt iReadState;
	TInt iBufferState;

protected:
	CRecvData& RecvData();

};

inline void CRecvEvent::SetUserData(TDes8* aData)
{
	iUserData = aData;
}

inline TDes8* CRecvEvent::UserData()
{
	return iUserData;
}

inline CRecvData& CRecvEvent::RecvData()
{
	return (CRecvData&) *iStateMachine;
}

inline void CRecvEvent::SetUserMaxLength(TInt aMaxLength) {
	iUserMaxLength = aMaxLength;
}

//

class CSendData : public CStateMachine
{
public:
	static CSendData* NewL(CTlsConnection& aTlsConnection); 
	~CSendData();
	
	void Start(TRequestStatus* aClientStatus, MStateMachineNotify* aStateMachineNotify);
	
	void Suspend();
	void Resume();
	
protected:
	CSendData(CTlsConnection& aTlsConnection);
	void ConstructL(CTlsConnection& aTlsConnection);

	virtual void DoCancel();
	virtual void OnCompletion();

protected:
	CTlsConnection& iTlsConnection;
	CSendEvent& iSendEvent;
};

inline void CSendData::Start(TRequestStatus* aClientStatus, MStateMachineNotify* aStateMachineNotify)
{
	CStateMachine::Start(aClientStatus, NULL, aStateMachineNotify);
}



class CSendEvent : public CAsynchEvent
{
public:
	CSendEvent(CMbedContext& aMbedContext);
	~CSendEvent();
	
	virtual CAsynchEvent* ProcessL(TRequestStatus& aStatus);
	
	void SetUserData(const TDesC8* aData);
	void SetSockXfrLength(TInt* aLen);
	
	void CancelAll();
	void ReConstruct(CStateMachine* aStateMachine);

protected:
	CMbedContext& iMbedContext;
	
	const TDesC8* iData;
	TInt* iSockXfrLength;
	TInt iCurrentPos;

};

inline void CSendEvent::SetSockXfrLength(TInt* aLen)
{
	iSockXfrLength = aLen;
}

inline void CSendEvent::SetUserData(const TDesC8* aData)
{
	iData = aData;
}

// handshake

class CHandshake : public CStateMachine
{
public:
	static CHandshake* NewL(CTlsConnection& aTlsConnection); 
	~CHandshake();
	
	void Start(TRequestStatus* aClientStatus, MStateMachineNotify* aStateMachineNotify);
	
	void Resume();

protected:
	CHandshake(CTlsConnection& aTlsConnection);
	void ConstructL();

	virtual void DoCancel();
	virtual void OnCompletion();

protected:
	CTlsConnection& iTlsConnection;
	CHandshakeEvent& iHandshakeEvent;
};

inline void CHandshake::Start(TRequestStatus* aClientStatus, MStateMachineNotify* aStateMachineNotify)
{
	CStateMachine::Start(aClientStatus, NULL, aStateMachineNotify);
}



class CHandshakeEvent : public CAsynchEvent
{
public:
	CHandshakeEvent(CMbedContext& aMbedContext);
	~CHandshakeEvent();
	
	virtual CAsynchEvent* ProcessL(TRequestStatus& aStatus);
	
	void CancelAll();
	void Set(CStateMachine* aStateMachine);

protected:
	CMbedContext& iMbedContext;
};

inline void CHandshakeEvent::Set(CStateMachine* aStateMachine)
{
	iStateMachine = aStateMachine;
}

#endif
