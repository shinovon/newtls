#ifndef TLSEVENTS_H
#define TLSEVENTS_H

#include <comms-infras/statemachine.h>
#include <comms-infras/asynchevent.h>

class MGenericSecureSocket;
class RSocket;

class CTlsConnection;
class CMbedContext;

class CRecvData;
class CRecvEvent;

class CRecvData : public CStateMachine
{
public:
	static CRecvData* NewL( CTlsConnection& aTlsConnection ); 
	~CRecvData();
	
	void Start( TRequestStatus* aClientStatus, MStateMachineNotify* aStateMachineNotify );
	
	void Suspend();
	void ResumeL( CTlsConnection& aTlsConnection );
	
	CTlsConnection& TlsConnection();
	
	void SetSockXfrLength(TInt* aLen);

protected:
	CRecvData( CTlsConnection& aTlsConnection );
	void ConstructL( CTlsConnection& aTlsConnection );

	virtual void DoCancel();
	virtual void OnCompletion();

protected:
	CTlsConnection& iTlsConnection;
	CRecvEvent& iRecvEvent;
	
	TInt* iSockXfrLength;
};

inline void CRecvData::Start( TRequestStatus* aClientStatus, MStateMachineNotify* aStateMachineNotify )
{
	CStateMachine::Start(aClientStatus, NULL, aStateMachineNotify);
}

inline CTlsConnection& CRecvData::TlsConnection()
{
	return iTlsConnection;
}

inline void CRecvData::SetSockXfrLength(TInt* aLen)
{
	iSockXfrLength = aLen;
}




class CRecvEvent : public CAsynchEvent
{
public:
	CRecvEvent( CMbedContext& aMbedContext, CStateMachine* aStateMachine, MGenericSecureSocket& aSocket );
	~CRecvEvent();
	
	virtual CAsynchEvent* ProcessL(TRequestStatus& aStatus);
	
	void SetData(TDes8* aData);
	void SetMaxLength(TInt aLen);
	
	void CancelAll();
	void Set(CStateMachine* aStateMachine);
	
	TDes8* Data();
	
	MGenericSecureSocket& iSocket;

protected:
	CMbedContext& iMbedContext;
	
	TDes8* iData;
	
	HBufC8* iDataIn;
	
public:
	TPtr8 iPtrHBuf;
	TInt iReadIdx;
	TInt iReadState;

protected:
	CRecvData& RecvData();

};

inline void CRecvEvent::SetData( TDes8* aData )
{
	iData = aData;
}

inline TDes8* CRecvEvent::Data()
{
	return iData;
}

inline CRecvData& CRecvEvent::RecvData()
{
	return (CRecvData&) *iStateMachine;
}


#endif
