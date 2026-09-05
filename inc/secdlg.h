/*
* Copyright (c) 1997-2009 Nokia Corporation and/or its subsidiary(-ies).
* All rights reserved.
* This component and the accompanying materials are made available
* under the terms of the License "Eclipse Public License v1.0"
* which accompanies this distribution, and is available
* at the URL "http://www.eclipse.org/legal/epl-v10.html".
*
* Initial Contributors:
* Nokia Corporation - initial contribution.
*
* Contributors:
*
* Description: 
*
*/


/**
 @file
 @publishedPartner
 @released
*/

#ifndef __SECDLG_H__
#define __SECDLG_H__

#include <ct.h>
#include <securitydefs.h>

/** Security Dialog API */


/** The maximum length of a PIN label */
const TInt KPINLabelMaxLength = 64;

/** TPINLabel is a human-readable name for the PIN to be entered. */
//64 = 255 bytes / poss 4bytes per unicode character
typedef TBuf<KPINLabelMaxLength> TPINLabel;


/**
 * Provides information associated with the PIN, 
 * to enable the dialog to display the name and do some basic correctness checking.
 */
class TPINParams
	{
public:
	/** The label that identifies the PIN */
	TPINLabel iPINLabel;
	/** The label of the token */
	TPINLabel iTokenLabel;
	/** The minimum length of the PIN */
	TInt iMinLength;
	/** The maximum length of the PIN */
	TInt iMaxLength;
	};

/** The max PIN length should not exceed 32, because this is the maximum
 *	size possible in the CEikSecretEditor class. */
const TInt KMaxPINLength = 32;

/** A PIN value */
typedef TBuf<KMaxPINLength> TPINValue;

/** Unblocking PINs can be up to 64 characters if they are entered in the clear. */
const TInt KMaxUnblockPINLength = 64;

/** An unblocking PIN value */
typedef TBuf<KMaxUnblockPINLength> TUnblockPINValue;

/**
 * Definition of the security dialog interface
 * @since 7.0
 */
class MSecurityDialog 
	{
public:
	/**
	 * TConnectionType defines the possible protocols used in EstablishSecureConnection
	 * which allows the type of the certificate to be derived.
	 */
	enum TConnectionType
		{
		/** WTLS */
		EWTLS,
		/** TLS */
		ETLS
		};


public:
	/**
	 * Prompts the user to enter a PIN. 
	 *
	 * @param aPINParams	Information about the PIN to enter.
	 * @param aRetry		Indicates whether the user is retrying.
	 * @param aPINValue		On return, the PIN the user entered: 
	 * @param aStatus		This will be set to KErrNotFound if no certificates could
	 * 						be presented to the user.
	 */
	virtual void EnterPIN( const TPINParams& aPINParams, TBool aRetry, TPINValue& aPINValue,
						   TRequestStatus& aStatus ) = 0;

	/**
	 * Prompts the user to change a PIN. 
	 * 
	 * @param aPINParams	Information about the PIN to change
	 * @param aRetry		Indicates whether the user is retrying
	 * @param aOldPINValue	On return, the old PIN the user entered 
	 * @param aNewPINValue	On return, the new PIN the user entered
	 * @param aStatus		This will be set to KErrNotFound if no certificates could
	 * 						be presented to the user.
	 */
	virtual void ChangePIN( const TPINParams& aPINParams, TBool aRetry,
							TPINValue& aOldPINValue, TPINValue& aNewPINValue,
							TRequestStatus& aStatus ) = 0;



	/**
	 * Prompts the user to enable a PIN. 
	 * 
	 * @param aPINParams	Information about the PIN to enable.
	 * @param aRetry		Indicates whether the user is retrying.
	 * @param aPINValue		On return, the PIN the user entered: 
	 * @param aStatus		This will be set to KErrNotFound if no certificates could
	 * 						be presented to the user.
	 */
	virtual void EnablePIN( const TPINParams& aPINParams, TBool aRetry, TPINValue& aPINValue,
							TRequestStatus& aStatus ) = 0;

	/**
	 * Prompts the user to disable a PIN. 
	 * 
	 * @param aPINParams	Information about the PIN to disable.
	 * @param aRetry		Indicates whether the user is retrying. 
	 * @param aPINValue		On return, the PIN the user entered: 
	 * @param aStatus		This will be set to KErrNotFound if no certificates could
	 * 						be presented to the user.
	 */
	virtual void DisablePIN( const TPINParams& aPINParams, TBool aRetry,
								TPINValue& aPINValue, TRequestStatus& aStatus ) = 0;
	/**
	 * Prompts the user to unblock a PIN. 
	 *
	 * The unblocking PIN is not displayed as it is entered, and can be a
	 * maximum of 32 characters long - hence it is passed back as a TPINValue.
	 * 
	 * @param aBlockedPINParams		Information about the PIN to unblock
	 * @param aUnblockingPINParams	Information about the unblocking PIN
	 * @param aRetry				Indicates whether the user is retrying
	 * @param aUnblockingPINValue	On return, the PIN the user entered
	 * @param aNewPINValue			On return, the new PIN the user entered
	 * @param aStatus				This will be set to KErrNotFound if no certificates could
	 * 								be presented to the user.
	 */	
	virtual void UnblockPIN( const TPINParams& aBlockedPINParams,
							 const TPINParams& aUnblockingPINParams, TBool aRetry,
							 TPINValue& aUnblockingPINValue, TPINValue& aNewPINValue,
							 TRequestStatus& aStatus ) = 0;

	/**
	 * Informs the user that the PIN has become blocked.
	 * 
	 * @param aPINParams	Information about the blocked PIN.
	 * @param aStatus		This will be set to KErrNotFound if no certificates could
	 * 						be presented to the user.
	 */
	virtual void PINBlocked( const TPINParams& aPINParams, TRequestStatus& aStatus ) = 0;
	
	
	/**
	 * Informs the user that a secure connection is being established with the given
	 * server, allowing them to proceed or cancel the operation.
	 * 
	 * @param aCertData					The certificate sent by the server.
	 * @param aCertHandleList			A selection of certificates to display to the user. All
	 *									certificates are displayed if this is empty.
	 * @param aConnectionType			This allows the type of certificate to be identified.
	 * @param aDoClientAuthentication	Determines whether the user is prompted to
	 * 									agree to authenticate themselves to the server.
	 * 									If this was true before the function was called, it
	 * 									will contain the result of the user's decision on return.
	 * @param aCertHandle				An identifier for the certificate the user selected.
	 * @param aStatus					This will be set to KErrNotFound if no certificates could
	 * 									be presented to the user.
	 */	
	virtual void EstablishSecureConnection( const TDesC8& aCertData,
						const RArray<TCTTokenObjectHandle>& aCertHandleList,
						MSecurityDialog::TConnectionType aConnectionType,
						TBool& aDoClientAuthentication, TCTTokenObjectHandle& aCertHandle,
						TRequestStatus& aStatus ) = 0;

	/**
	 * Signs some text.
	 * 
	 * @param aTextToSign		The text to be signed.
	 * @param aCertHandleList	A selection of certificates to display to the user.
	 *							All certificates are displayed if this is empty.
	 * @param aCertHandle		On return, an identifier for the certificate the user selected.
	 * 							aStatus - this will be set to KErrNotFound if no certificates
	 *							could be presented to the user.
	 * @param aStatus			This will be set to KErrNotFound if no certificates could
	 * 							be presented to the user.
	 */
	virtual void SignText( const TDesC& aTextToSign,
							const RArray<TCTTokenObjectHandle>& aCertHandleList, 
							TCTTokenObjectHandle& aCertHandle,
							TRequestStatus& aStatus ) = 0;

	/**
	 * Frees resources of the MSecurityDialog class
	 */
	virtual void Release()=0;
	/**
	 * Informs the user that the server authentication has failed.
	 *
	 * @param aServerName	 The name of the server.
	 * @param aFailurereason The server authentication failure reason
	 * @param aencodedCert	 The certificate sent by the server.
	 * @param aStatus		 This will be set to KErrNone or KErrAbort depending upon
	 *						 the EContinue or EStop.
	 *						 
	 */
	virtual void ServerAuthenticationFailure(const TDesC8& aServerName,
						const TValidationError& aFailureReason, const TDesC8& aEncodedCert,
						TRequestStatus& aStatus ) = 0;

protected:
	/**
	 * Destructor for the MSecurityDialog class
	 */
	inline virtual ~MSecurityDialog()=0;
 public:
	// This is at the end to preserve BC
	/**
	 * Informs the user that the unblock PIN has been blocked.
	 * 
	 * @param aPINParams	Information about the blocked PIN.
	 * @param aStatus		This will be set to KErrNotFound if no certificates could
	 * 						be presented to the user.
	 */
	virtual void TotalBlocked( const TPINParams& aPINParams, TRequestStatus& aStatus ) = 0;

	/**
	 * Prompts the user to unblock a PIN.
	 *
	 * The unblocking PIN is displayed to the user in the clear as it is
	 * entered, and can be a maximum of 64 characters long - it is passed back
	 * as a TUnblockPINValue.
	 * 
	 * @param aBlockedPINParams		Information about the PIN to unblock
	 * @param aUnblockingPINParams	Information about the unblocking PIN
	 * @param aRetry				Indicates whether the user is retrying
	 * @param aUnblockingPINValue	On return, the PIN the user entered
	 * @param aNewPINValue			On return, the new PIN the user entered
	 * @param aStatus				This will be set to KErrNotFound if no certificates could
	 * 								be presented to the user.
	 */
	virtual void UnblockPINInClear( const TPINParams& aBlockedPINParams,
									const TPINParams& aUnblockingPINParams, TBool aRetry,
									TUnblockPINValue& aUnblockingPINValue, TPINValue& aNewPINValue,
									TRequestStatus& aStatus ) = 0;

	/**
	 * Cancels an ongoing dialog.
	 */
	virtual void Cancel() = 0; 
	};

inline MSecurityDialog::~MSecurityDialog() {}

/**
 * Factory for creating the relevant concrete subclass of the security dialog
 */
class SecurityDialogFactory
	{
public:
	/**
	 * Creates an instance of a subclass of MSecurityDialog. Implement to create
	 * the appropriate security dialog
	 * 
	 * @return	An object that implements MSecurityDialog functions
	 */
	IMPORT_C static MSecurityDialog* CreateL();
	};


#endif
