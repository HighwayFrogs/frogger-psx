#include "NetPlay.h"
#include <windowsx.h>
#include <stdio.h>
#include <stdarg.h>
#include <mmsystem.h>
#include <dplobby.h>
// @doc M_NETPLAY
//
// @module M_NetPlay.c - Millennium API NetworkPlay Layer |
//
// This code sits on top of the DirectPlay 3 interface (as appears in DirectX 5).
// Hopefully the end user should be largely masked from the underlying complexities of DirectPlay.
//
// Original programming by Sparky.
//
// This documentation last updated <date>.
//
/* @comm 
 It will be necessary to generate a GUID for the master application. This will be used
 for amongst other things, identification of other sessions. To generate a GUID either ask somebody
 for one or run the tool on the tools menu. If you use the DEFINE_GUID type (as I do), then you will
 need to do something like the following:

  iex 

	#define INITGUID					// Very important, DEFINE_GUID will not work properly without this

	#include <windows.h>
	#include <windowsx.h>
	#include "resource.h"
	#include "main.h"

	// Let's now define our GUID
	// {D3EE8F73-D7EA-11d0-8069-0020AFF4866A}
	DEFINE_GUID(MY_GUID,0xd3ee8f73, 0xd7ea, 0x11d0, 0x80, 0x69, 0x0, 0x20, 0xaf, 0xf4, 0x86, 0x6a);

	LPGUID	glpGuid=(LPGUID)&MY_GUID;	// Here we have a handy global reference to our GUID

@comm
Note:
	There will be a problem when using RAS to dial up networks. If you aren't connected to a 
	network, the call network dialog will appear :(

@todo

  1. Service Provider Dialog Overrides
------------------------------------
Service Provider dialogs may be overridden using the following method.

Step 1. Choose which service provider is to be used. Either via
        DirectPlayEnumerate or by creating an IDirectPlay3 interface and
        calling EnumConnections.  The connection returned will need to have
        the service provider GUID parsed out of it using the
        IDirectPlayLobby2::EnumAddress method.
Step 2. Create an IDirectPlayLobby interface using DirectPlayLobbyCreate and
        query what address type the service provider will require.  The
        Help file will explain what address types are supported in the
        "DirectPlay Address" section.
Step 3. Obtain the information to satisfy the address types using whatever
        means you deem fit.
Step 4. Create a DirectPlay Address using either the CreateAddress or
        CreateCompoundAddress methods on the IDirectPlay2 interface.
Step 5. Call InitializeConnection using the DirectPlay Address created in
        Step 4.  If the address has been created correctly, there will be
        no service provider dialog.

*/
//
//
// @todo Join Sessions
// @todo Send data
// @todo Receive data
// @index | M_NETPLAY

// ************************************************************************************************
//@globalv Current Session Description
LPDPSESSIONDESC2	glpdpSD;		

//@globalv Direct Play Object Pointer
LPDIRECTPLAY2		glpDP		= NULL;	

//@globalv DIrectPlay 3 Interface to Object
LPDIRECTPLAY3A		glpDP3A		= NULL;

//@globalv DIrectPlay 3 Interface to Object
LPDIRECTPLAYLOBBY2A	glpDPL2A	= NULL;
LPDIRECTPLAYLOBBY	glpDPLobby	= NULL;
GUID*	TempGUID;
GUID*	TypeGUID;
LPVOID	lpNewConnection=NULL;		// Connection information including GUID (was LPGUID lpSPGuid)
DWORD	dwNewSize=0;				// Size of the above structure

//@globalv Handle to the debug console
HANDLE				MNConsole=0;

//@globalv Pointer to Service Provider list!
SPLIST*				glpSPList=0;

//@globalv Pointer to Session list!
SESSIONLIST*		glpSessionList;	

//@globalv Pointer to Player list!
PLAYERLIST*			glpPlayerList=0;

DPSESSIONDESC2		dpHostSessionDesc;
DPSESSIONDESC2*		lpdpCurrentSessionDesc=NULL;


LPGUID				glpGuid=0;

char				BlankName[]="No Name Specified";
char				BlankSession[]="No Session Name Specified";


LPVOID				glpvReceiveBuffer = NULL;	// buffer to store received messages
DWORD				gdwReceiveBufferSize = 0;	// size of buffer
DPID				gOurID;						// our player id
DPID				gHostID;					// our player id
UINT				guiPlayer=MN_INVALID;		// Simple Player number

HWND				hwndCurrent=NULL;

UINT				MNTimerID=0;

BOOL				gbHost=FALSE;


#define TARGET_RESOLUTION		0			// 1 millisecond target resolution
#define TARGET_MAXIMUM			10			// 10 millisecond target resolution max

WORD				MNTimerRes;
TIMECAPS			MNTimeCaps;

BOOL				gbAllowPoll=FALSE;
BOOL				gbNetGame=FALSE;
UINT				uiPlayersInGame;

BOOL				gbSystemInitialised=FALSE;

VOID	(*MNGameMessageHandlerCallBack)(LPMNGAMEMSG_GENERIC lpMsg, DWORD dwMsgSize, DPID idFrom, DPID idTo)=0;
// VOID (*TimerFunction)()=0;
//	if (TimerFunction)
//		(TimerFunction)();

char* lpszLocalPlayerName=NULL;


// ************************************************************************************************
// *** Private functions ***
BOOL MNStartPolling(UINT);
void MNStopPolling();
HRESULT MNSend(DPID, DPID, DWORD, LPVOID, DWORD);
HRESULT MNReceive(LPDPID, LPDPID , DWORD , LPVOID , LPDWORD );
void MNSendMNSystemMessage(DPID,BYTE);
HRESULT MNCreateLobbyObject();

// ************************************************************************************************

// ************************************************************************************************

// ************************************************************************************************
// @func Finds out how many registered players are in this game session
// @rdesc Number of players
UINT MNPlayersInGame()
{
	return (uiPlayersInGame);
}
// ************************************************************************************************
// @func Signals to all players that the game is about to start. The message MNM_START_GAME will be sent to the WndProc of the registered window.
// It is up to the program to decide what to do with this message.
// @comm This will only work if the calling player happens to be the host

void MNSignalGameStart()
{
	if (gbHost)
		MNSendMNSystemMessage(DPID_ALLPLAYERS,MNRM_START_GAME);
}
// ************************************************************************************************
// @func Use to specify a function to handle game network messages of type 	MNRM_GAME_BROADCAST and MNRM_GAME_BROADCAST_GUARANTEED.
// @comm Function must be defined as something like void GameMessageHandlerCallBack(LPMNGAMEMSG_GENERIC lpMsg, DWORD dwMsgSize, DPID idFrom, DPID idTo)
void MNSetGameMessageHandlerCallback(void (*lpFunction)(LPMNGAMEMSG_GENERIC, DWORD, DPID, DPID))
{
	MNGameMessageHandlerCallBack=lpFunction;
}
// ************************************************************************************************
// @func Issues each player with a game player number from 0-n
// @comm This will only work if the calling player happens to be the host
// @xref <f MNGetPlayerNumber>
void MNIssuePlayerNumbers()
{
	MNMSG_PLAYERNUMBER	msgpnPlayerMessage;
	msgpnPlayerMessage.byType=MNRM_PLAYERNUMBER;

	if (gbHost)
	{
		// Get the player list for this session
		MNFindCurrentGamePlayers();
		{
			unsigned int	uiPlayerListSize;
			PLAYERLIST*	lpPlayerList=MNGetPlayerList();

			if (lpPlayerList)
			{
				// get number of entries in the SP list
				uiPlayerListSize=lpPlayerList->uiPlayerListSize;


				while(uiPlayerListSize)
				{
					uiPlayerListSize--;
					// Send the player number to all
					// but fill in for host

					if (lpPlayerList->lpPLPlayerData[uiPlayerListSize]->pidID==gOurID)
					{
						MNPrintf("(Host):   Issuing Player Number (%d) to %s\n",uiPlayerListSize,lpPlayerList->lpPLPlayerData[uiPlayerListSize]->Name.lpszShortNameA);
					  guiPlayer=uiPlayerListSize;
					}
					else
					{
						MNPrintf("(Client): Issuing Player Number (%d) to %s\n",uiPlayerListSize,lpPlayerList->lpPLPlayerData[uiPlayerListSize]->Name.lpszShortNameA);
					  msgpnPlayerMessage.uiPlayerNumber=uiPlayerListSize;
					  MNSend(	gOurID,
								lpPlayerList->lpPLPlayerData[uiPlayerListSize]->pidID , 
								DPSEND_GUARANTEED, 
								&msgpnPlayerMessage, 
								sizeof(MNMSG_PLAYERNUMBER));	
					}
				}
			}
		}
	}
}
// ************************************************************************************************
// @func Query to find if a network game is running
// @rdesc TRUE if running
BOOL MNIsNetGameRunning()
{
	return (gbNetGame);
}
// ************************************************************************************************
// @func Restarts the timer driven network message polling used for Dialog boxes
// @xref <f MNStopPoll>
void MNStartPoll()
{
	gbAllowPoll=TRUE;
}
// ************************************************************************************************
// @func Stops the timer driven network message polling used for Dialog boxes
// @xref <f MNStopPoll>
void MNStopPoll()
{
	gbAllowPoll=FALSE;
}
// ************************************************************************************************
// @func Query which player number is assigned to the player
// @rdesc The current player number or MN_INVALID
// @xref <f MNIssuePlayerNumbers>
UINT	MNGetPlayerNumber()
{
	return (guiPlayer);
}
// ************************************************************************************************
// @func Query to see if you are the host
// @rdesc TRUE if you are the host
BOOL	MNHost()
{
	return (gbHost);
}
// ************************************************************************************************
// @func Query our DplayID number
// @rdesc The DplayID number (DPID)
DPID	MNGetID()
{
	return (gOurID);
}
// ************************************************************************************************
// @func Used to tell the NetPlay system which window to send Windows messages to
// @comm This must be called to keep track of any window changes (e.g. when moving from Dialog boxes to the game window)
// @xref <f MNPostMessage> <f MNInvalidateWindow>
void MNRegisterWindow(HWND hWnd)
{
	hwndCurrent=hWnd;
}
// ************************************************************************************************
// @func Tells the NetPlay system that there are no current valid windows for message handling
// @xref <f MNRegisterWindow> <f MNPostMessage>
void MNInvalidateWindow()
{
	hwndCurrent=NULL;
}
// ************************************************************************************************
// @func Dispatches a message to the NetPlay registered window
// @xref <f MNRegisterWindow> <f MNInvalidateWindow>
void MNPostMessage(UINT uMsg,WPARAM wParam,LPARAM lParam)
{
	//PostMessage(hwndCurrent,uMsg,wParam,lParam);
	SendMessage(hwndCurrent,uMsg,wParam,lParam);
}
// ************************************************************************************************
// @func Checks to see if a local name is valid
// @comm If the name is invalid a canned name will be generated
// @xref <f MNSetLocalPlayerName>
void MNValidateLocalPlayerName()
{

	DWORD dwSize=199;

	if(lpszLocalPlayerName==NULL)
	{
		char Buffer[200];
		GetComputerName((char*)&Buffer,&dwSize);
		if (gbHost)
			strcat(Buffer," (Host)");


		lpszLocalPlayerName=malloc(strlen(Buffer)+1);
		strcpy(lpszLocalPlayerName,Buffer);

		//lpszLocalPlayerName=malloc(strlen(BlankName)+1);
		//strcpy(lpszLocalPlayerName,BlankName);
	}
}
// ************************************************************************************************
// @func Sets the local player name
void MNSetLocalPlayerName(LPSTR lpszPlayerName)
{
	int iPlayerNameLength=strlen(lpszPlayerName);

	MNDeleteLocalPlayerName();

	if (iPlayerNameLength)
	{
		lpszLocalPlayerName=malloc(iPlayerNameLength+1);
		strcpy(lpszLocalPlayerName,lpszPlayerName);
	}
	else
		MNValidateLocalPlayerName();	
}
// ************************************************************************************************
// @func Destroys the local player name
void MNDeleteLocalPlayerName()
{
	if (lpszLocalPlayerName)
		free(lpszLocalPlayerName);	//Player name already exists so destroy

	lpszLocalPlayerName=NULL;
}
// ************************************************************************************************
// @func Generates and then opens a new console and stores the StdHandle of this Console
//@xref <f MNKillDebugConsole> 
void	MNCreateDebugConsole()
{
	MNConsole	= 0;

	if(AllocConsole())
	{
		MNConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	}
}
// ************************************************************************************************
// @func Kills the Debug Console
//@xref <f MNCreateDebugConsole> 
void MNKillDebugConsole()
{
	if(MNConsole)
		FreeConsole();
}
// ************************************************************************************************
// @func Internal printf that dispatches output to debugger and console (if available)
void __cdecl MNPrintf(
						char *format,	//@parm String to format
						...)			
{
	unsigned long	num_written;
	char			text_buffer[256];
	va_list			ap;

	// build thing
	va_start(ap, format);			
	vsprintf(text_buffer, format, ap);
	va_end(ap);
	
	// Output to the debugger (always)
	OutputDebugString(text_buffer);	

	if(MNConsole)
	{
		WriteConsole(MNConsole, text_buffer, strlen(text_buffer), &num_written, NULL);
	}
}
// ************************************************************************************************
// @func Returns a pointer to the DirectPlay 3 Interface.
LPDIRECTPLAY3A MNGetDirectPlayInterface()
{
	return (glpDP3A);
}
// ************************************************************************************************
// @func Returns a pointer to the DirectPlay 3 Interface.
SPLIST* MNGetServiceProviderList()
{
	return (glpSPList);
}
// ************************************************************************************************
// @func Returns a pointer to the Session list
SESSIONLIST* MNGetSessionList()
{
	return (glpSessionList);
}
// ************************************************************************************************
// @func Returns a pointer to the Player list
//@xref <f MNFindSessionPlayers> <f MNDeletePlayerList> 
PLAYERLIST* MNGetPlayerList()
{
	return (glpPlayerList);
}
// ************************************************************************************************
// @func Initialises the Network Layer
//@xref <f MNClose> 
HRESULT MNInitialise(LPGUID lpGUID)
{
	HRESULT		hResult	= E_FAIL;

	// Keep the session GUID
	glpGuid=lpGUID;

	//MNCreateDebugConsole();
	CoInitialize( NULL );

	// Do we already have a DirectPlay object?
	if (glpDP3A)
	{
		// It would appear that we have already initialised an object
		// So let's try to kill it all off
		hResult=MNClose();
		// If I can remember what the vtbl->Release codes are I will check here
	}


	MNPrintf("Initialising DirectPlay Object\n");
	// Now we attempt to create the Direct Play Object!
	hResult	= CoCreateInstance(	&CLSID_DirectPlay,			//Class identifier (CLSID) of the object
								NULL,						//Pointer to whether object is or isn’t part of an aggregate
								CLSCTX_INPROC_SERVER,		//Context for running executable code
								&IID_IDirectPlay3A, 		//Reference to the identifier of the interface
								(LPVOID *) &glpDP3A );		//Indirect pointer to requested interface 



	MNCreateLobbyObject();

	gbSystemInitialised=TRUE;

	return (hResult);
}
// ************************************************************************************************
HRESULT MNCreateLobbyObject()
{
	HRESULT		hResult	= E_FAIL;
	if (!glpDPLobby)	// Does an interface already exist?
	{
		hResult=DirectPlayLobbyCreate(	(LPGUID)NULL,		// LPGUID Reserved, must set to NULL
										&glpDPLobby,			// Pointer of our interface to be setup
										NULL,				// Pointer to IUNKNOWN interface, must be NULL at the moment
										(LPVOID)NULL,		// Pointer to extra data, must be set to NULL
										0);					// Size of the above, must be zero!
		if (hResult==DP_OK)
		{
			// Okay, now let's create the DPlayLobby2A interface
			IDirectPlayLobby_QueryInterface(	glpDPLobby,
												&IID_IDirectPlayLobby2A,
												(LPVOID*) &glpDPL2A);

			return (hResult);
		}	
	}
	return (hResult);
}
// ************************************************************************************************
// @func Closes the network layer
//@xref <f MNInitialise> 
HRESULT MNClose()
{
	HRESULT	hResult;

	MNStopPolling();
	if (gbSystemInitialised)
	{
		MNPrintf("Removing DirectPlay Object\n");
			
		if (glpDP3A)
		{
			hResult = IDirectPlay3_Release(glpDP3A);
			glpDP3A = NULL;		
		}

		MNPrintf("CoUninitialize()\n");
		CoUninitialize();

		MNKillDebugConsole();

		gbSystemInitialised=FALSE;

		return (hResult);
	}
	else
		return(FALSE);
}
// ************************************************************************************************
// *** History ***
// SPK 20051997 Created
// SPK 21051997 Completely changed to provide proper support for DX 5 shortcuts (original saved elsewhere)
//
// *** Functionality and notes ***
// @func
// Internal function
// Callback to add additional Service Providers to the SP list
BOOL FAR PASCAL MNCallBack(
#ifndef _DX5BETA1
						LPCGUID			lpguidSP,		//@parm Bastards added this in DX5Beta2b
#endif
						LPVOID			lpConnection,	//@parm Wibble
						DWORD			dwSize,			//@parm b
						LPCDPNAME		lpName,			//@parm c
						DWORD			dwFlags,		//@parm d
						SPLIST			**lpContext)	//@parm e
{

	unsigned int	uiSPListSize=0;

	SPLIST*			lpNewSPList=0;
	SPLIST*			lpSPList=*lpContext;

	// Get the size of the original SPList
	uiSPListSize=lpSPList->uiSPListSize;

	// Now create a nice new SPList
	lpNewSPList=malloc(sizeof(unsigned int)+(uiSPListSize+1)*(sizeof (SP)));
	
	// Copy the original list into the new one
	memcpy(lpNewSPList,lpSPList,sizeof(unsigned int)+uiSPListSize*(sizeof (SP)));

	// Allocate some memory to hold the GUID and get a copy of it
	(void*)lpNewSPList->spSPList[uiSPListSize].lpConnection=malloc(dwSize);
	memcpy((void*)lpNewSPList->spSPList[uiSPListSize].lpConnection,lpConnection,dwSize);
	// Also make a note of the declared "Connection" size, this is new in DX5
	lpNewSPList->spSPList[uiSPListSize].dwSize=dwSize;

	// Allocate some memory to hold the Friendly string and get a copy of it
	(void*)lpNewSPList->spSPList[uiSPListSize].lpszSPName=malloc(strlen(lpName->lpszShortNameA)+1);	
	strcpy((void*)lpNewSPList->spSPList[uiSPListSize].lpszSPName,lpName->lpszShortNameA);

	MNPrintf("Found SP %s\n",lpName->lpszShortNameA);

	// Increase the size of the list
	lpNewSPList->uiSPListSize++;

	// Lets delete the old list
	free(lpSPList);
  
	// And finally Make the new one the live one
	*lpContext=lpNewSPList;

	return (TRUE);
}
// ************************************************************************************************
// *** History ***
// SPK 21051997 Created
//
// *** Functionality and notes ***
// @func
// Used to destroy the Service Provider list
//
void	MNDeleteServiceProviderList(
										SPLIST* lpSPList)	//@parm An SPList
{
	unsigned int	uiSPListSize;

	if (lpSPList)
	{
		// get number of entries in the SP list
		uiSPListSize=lpSPList->uiSPListSize;

		while(uiSPListSize)
		{
			uiSPListSize--;	// Remember the list size is 0 for 0 items !
			free((void*)lpSPList->spSPList[uiSPListSize].lpConnection);
			free((void*)lpSPList->spSPList[uiSPListSize].lpszSPName);
		}

		free(lpSPList);
	}
}
// ************************************************************************************************
// *** History ***
// SPK 20051997 Created
//
// *** Functionality and notes ***
// @func
// Returns a pointer to a SPLIST
// An SPLIST contains
//		uiSPListSize		// Number of service providers in list
//		spSPlist[]			// An array of SP entries which contain...
//			lpConnection	// A pointer to the SP Connection information (including GUID) and
//			lpszSPName		// A pointer to the service providers friendly name
// 
// Once finished with, destroy using MNDeleteServiceProviderList
// For instance:
//
//			MNDeleteServiceProviderList(MNFindServiceProviders())
//
// Would find and then destroy the list, pointless really ;-)
// 
// Anyway interesting bit time!
// If you specify an application GUID then only shortcuts with the correct GUID or no spplication GUID
// will be returned, this is so that you can explicitly set a connection type for a given game.
// Is this neat or what!
SPLIST*	MNFindServiceProviders()
{
	
	glpSPList=malloc(sizeof(unsigned int));

	if (glpSPList)
	{
		glpSPList->uiSPListSize=0;	// Initialise to zero service providers

		//DirectPlayEnumerate(MNCallBack,&lpSPList);
		IDirectPlay3_EnumConnections(	glpDP3A,			// Our DirectPlay Object
										(LPGUID)0,	//glpGuid,		// Pointer to game GUID
										MNCallBack,			// Internal enumeration callback to generate SP list
										&glpSPList,			// Pointer to basic Service provider list
										0);					// Flags, MUST BE ZERO!
	}

	return (glpSPList);	// Give back a pointer to our SP List structure
}
// ************************************************************************************************
BOOL FAR PASCAL MNEnumAddressTypeCallback(REFGUID guidDataType, LPVOID lpContext,DWORD dwFlags)
{
	if (IsEqualGUID(guidDataType,&DPAID_INet))
	{
		(REFGUID)TypeGUID=guidDataType;
		MNPrintf("DPAID_Inet\n");
	}

	if (IsEqualGUID(guidDataType,&DPAID_Phone))
	{
		(REFGUID)TypeGUID=guidDataType;
		MNPrintf("DPAID_Phone\n");
	}

	if (IsEqualGUID(guidDataType,&DPAID_Modem))
	{
		(REFGUID)TypeGUID=guidDataType;
		MNPrintf("DPAID_Modem\n");
	}

	if (IsEqualGUID(guidDataType,&DPAID_ComPort))
	{
		(REFGUID)TypeGUID=guidDataType;
		MNPrintf("DPAID_ComPort\n");
	}

	return (TRUE);

}
// ************************************************************************************************
BOOL FAR PASCAL MNEnumAddressCallback(REFGUID guidDataType,DWORD dwDataSize, LPCVOID lpData,LPVOID lpContext)
{

// Is it a TCP?
//	BOOL IsEqualGUID(
//						REFGUID rguid1,	//GUID to compare to rguid2
//					    REFGUID rguid2	//GUID to compare to rguid1
//					);						


// I really want to store this somewhere ;-)

	if (IsEqualGUID(guidDataType,&DPAID_TotalSize))
	{
		DWORD *AddressBufferSize=(DWORD*)lpData;
		MNPrintf("DPAID_TotalSize is %d\n",*AddressBufferSize);
	}
	

	if (IsEqualGUID(guidDataType,&DPAID_ServiceProvider))
	{
		MNPrintf("DPAID_ServiceProvider, SP GUID found\n");
		(REFGUID)TempGUID=lpData;	//guidDataType;
	}
	
	
	


	return (TRUE);
}
// ************************************************************************************************
HRESULT MNInitializeConnection(LPVOID lpConnection)
{
		MNPrintf("Initialising Connection\n");
		return(IDirectPlay3_InitializeConnection(glpDP3A,lpConnection,0));
}
// ************************************************************************************************
// *** History ***
// SPK 21051997 Created
//
// *** Functionality and notes
// @func Create Connection, explicitly using an SP list
BOOL MNCreateConnectionRaw(	
							SPLIST* lpSPList,		//@parm Pointer to a SPList
							unsigned int iSession)	//@parm The session you want to use
{
	LPVOID lpConnection;
	HRESULT hResult;
	MNPrintf("About to create connection\n");

	// Sanity check to see that the connection requested is within range
	if (iSession>lpSPList->uiSPListSize)
		return (FALSE);

	// Our default connection
	lpConnection=lpSPList->spSPList[iSession].lpConnection;

	MNPrintf("Connection type (%d)%s \n",iSession,lpSPList->spSPList[iSession].lpszSPName);



	// Now we must do a bit of address spoofing to get around the Service Provider dialogs
	// This is a bit of a problem, not the least being that we may not know how to handle the SP dialog
	// We will need to at least support TCP/IP, modem and serial
	// DPAID_ComPort
	// DPAID_INet
	// DPAID_INetW
	// DPAID_Modem
	// DPAID_ModemW
	// DPAID_Phone
	// DPAID_PhoneW	  memcmp

	//	Step 1. Choose which service provider is to be used. Either via
	//			DirectPlayEnumerate or by creating an IDirectPlay3 interface and
	//			calling EnumConnections.  The connection returned will need to have
	//			the service provider GUID parsed out of it using the
	//			IDirectPlayLobby2::EnumAddress method.

	// lpSPList->spSPList[iSession].lpConnection

	hResult=IDirectPlayLobby_EnumAddress(	glpDPL2A,
											MNEnumAddressCallback,
											lpSPList->spSPList[iSession].lpConnection,	//LPCVOID lpAddress, 
											lpSPList->spSPList[iSession].dwSize,		//DWORD dwAddressSize,
											NULL);										//LPVOID lpContext

	if (hResult!=DP_OK)
	{
		RESULT(DPERR_EXCEPTION);
		RESULT(DPERR_INVALIDOBJECT);
		RESULT(DPERR_INVALIDPARAMS);
		return (FALSE);
	}


	TypeGUID=NULL;

	hResult=IDirectPlayLobby_EnumAddressTypes(	glpDPL2A,
											MNEnumAddressTypeCallback,
											TempGUID,	//lpSPList->spSPList[iSession].lpConnection,	//LPCVOID lpAddress, 
											NULL,		//LPVOID lpContext
											0);			// Flags (reserved)



	if (hResult!=DP_OK)
	{
		RESULT(DPERR_EXCEPTION);
		RESULT(DPERR_INVALIDOBJECT);
		RESULT(DPERR_INVALIDPARAMS);
		return (FALSE);
	}


	//	Step 2.	Create an IDirectPlayLobby interface using DirectPlayLobbyCreate and
	//			query what address type the service provider will require.  The
	//			Help file will explain what address types are supported in the
	//			"DirectPlay Address" section.




	//	Step 3. Obtain the information to satisfy the address types using whatever
	//			means you deem fit.

	// *** I guess this means it's callback time ;-)

	//	Step 4. Create a DirectPlay Address using either the CreateAddress or
	//			CreateCompoundAddress methods on the IDirectPlay2 interface.

	if (TypeGUID)
	{
		LPCVOID	lpData=NULL;
		DWORD	dwDataSize=0;

		// Do we support this connection type?
		if (IsEqualGUID(TypeGUID,&DPAID_INet))
		{
			// Get the IP Address from the callback?
			char IPAddress[]="";

			dwDataSize=strlen(IPAddress)+1;
			lpData=malloc(dwDataSize);
			strcpy((void*)lpData,IPAddress);

		}				

		// Do some more...
		// Do some more...
		// Do some more...
		// Do some more...

		// If we have some data then we can create a new address
		if (lpData)
		{
			hResult=IDirectPlayLobby_CreateAddress(	glpDPL2A,
													TempGUID,				// REFGUID guidSP,
													TypeGUID,				//REFGUID guidDataType, 
													lpData,
													dwDataSize, 
													lpNewConnection,		//LPVOID lpAddress,
													&dwNewSize				//LPDWORD lpdwAddressSize
													);
			if (hResult!=DPERR_BUFFERTOOSMALL)
			{
				MNPrintf("Buffer Wasn't too small!!!\n");
				return (FALSE);
			}

			MNPrintf("Buffer of %d bytes required\n",dwNewSize);
			lpNewConnection=malloc(dwNewSize);

			hResult=IDirectPlayLobby_CreateAddress(	glpDPL2A,
													TempGUID,				// REFGUID guidSP,
													TypeGUID,				//REFGUID guidDataType, 
													"",						//LPCVOID lpData,
													1,						//WORD dwDataSize, 
													lpNewConnection,		//LPVOID lpAddress,
													&dwNewSize				//LPDWORD lpdwAddressSize
													);
			
			if (hResult!=DP_OK)
			{
				RESULT(DPERR_BUFFERTOOSMALL);
				RESULT(DPERR_INVALIDPARAMS);
				return (FALSE);
			}
		//	Step 5. Call InitializeConnection using the DirectPlay Address created in
		//			Step 4.  If the address has been created correctly, there will be
		//			no service provider dialog.

			lpConnection=lpNewConnection;

			free((void*)lpData);
		}
	}

	// Okay initialise the connection, this will either be the original one
	// or a generated one if we happen to support this type for dialog blanking
	hResult=MNInitializeConnection(lpConnection);

	if (hResult!=DP_OK)
	{
		RESULT(DPERR_ALREADYINITIALIZED);
		RESULT(DPERR_INVALIDFLAGS);
		RESULT(DPERR_INVALIDPARAMS);
		RESULT(DPERR_UNAVAILABLE);

		return (FALSE);
	}

	MNPrintf("Connection Created\n");
	

	return (TRUE);
}
// ************************************************************************************************
// *** History ***
// SPK 28051997 Created
//
// *** Functionality and notes
// @func Create Connection
BOOL MNCreateConnection(	
							unsigned int iSession)	//@parm The session you want to use
{
	return MNCreateConnectionRaw(glpSPList,iSession);
}
// ************************************************************************************************
BOOL WINAPI MNEnumPlayerCallBack(	
									DPID pidID, 
									DWORD dwPlayerType, 
									LPCDPNAME lpName,
									DWORD dwFlags, 
									PLAYERLIST **lpContext)
{
	unsigned int	uiPlayerListSize=0;
	PLAYERLIST*		lpNewPlayerList=0;
	PLAYERLIST*		lpPlayerList=*lpContext;

	// Get original size of the player list
	uiPlayerListSize=lpPlayerList->uiPlayerListSize;


	// Generate a new player list
	lpNewPlayerList=malloc(sizeof(unsigned int)+(uiPlayerListSize+1)*(sizeof (LPPLDATA)));

	// Copy the original list into the new one
	memcpy(lpNewPlayerList,lpPlayerList,sizeof(unsigned int)+uiPlayerListSize*(sizeof (LPPLDATA)));

	// generate a new PLDATA object
	lpNewPlayerList->lpPLPlayerData[uiPlayerListSize]=malloc(sizeof(PLDATA));
	
	// Okay now we want to transfer the relevant information into the new entry
	memcpy(&lpNewPlayerList->lpPLPlayerData[uiPlayerListSize]->Name,lpName,sizeof(DPNAME));
	lpNewPlayerList->lpPLPlayerData[uiPlayerListSize]->pidID=pidID;
	lpNewPlayerList->lpPLPlayerData[uiPlayerListSize]->dwPlayerType=dwPlayerType;
	lpNewPlayerList->lpPLPlayerData[uiPlayerListSize]->dwFlags=dwFlags;

	// Better now make a copy of the friendly and long names as these will be destroyed!
	if (lpName->lpszShortNameA)
	{
		(char*)lpNewPlayerList->lpPLPlayerData[uiPlayerListSize]->Name.lpszShortName=lpNewPlayerList->lpPLPlayerData[uiPlayerListSize]->Name.lpszShortNameA=malloc(strlen(lpName->lpszShortNameA)+1);
		strcpy(lpNewPlayerList->lpPLPlayerData[uiPlayerListSize]->Name.lpszShortNameA,lpName->lpszShortNameA);
	}
	else
		(char*)lpNewPlayerList->lpPLPlayerData[uiPlayerListSize]->Name.lpszShortName=lpNewPlayerList->lpPLPlayerData[uiPlayerListSize]->Name.lpszShortNameA=0;

	if (lpName->lpszLongNameA)
	{
		(char*)lpNewPlayerList->lpPLPlayerData[uiPlayerListSize]->Name.lpszLongName=lpNewPlayerList->lpPLPlayerData[uiPlayerListSize]->Name.lpszLongNameA=malloc(strlen(lpName->lpszLongNameA)+1);
		strcpy(lpNewPlayerList->lpPLPlayerData[uiPlayerListSize]->Name.lpszLongNameA,lpName->lpszLongNameA);
	}
	else
		(char*)lpNewPlayerList->lpPLPlayerData[uiPlayerListSize]->Name.lpszLongName=lpNewPlayerList->lpPLPlayerData[uiPlayerListSize]->Name.lpszLongNameA=0;

	// Increase the size of the list
	lpNewPlayerList->uiPlayerListSize++;

	// Lets delete the old list
	free(lpPlayerList);

	// And finally Make the new one the live one
	*lpContext=lpNewPlayerList;


	return TRUE;
}
// ************************************************************************************************
void MNSendClientHostID(DPID dpidPlayer)
{
	MNMSG_HOSTID HostIDMessage;

	MNPrintf("** Sending MNRM_HOSTID **\n");
	
	HostIDMessage.byType=MNRM_HOSTID;
	HostIDMessage.idHost=gOurID;

	MNSend(gOurID, dpidPlayer, DPSEND_GUARANTEED, (LPVOID)&HostIDMessage, sizeof(MNMSG_HOSTID));	

}
// ************************************************************************************************
void	MNSendHost(LPMNMSG_GENERIC lMsg,UINT uiSize)
{
	// MNPrintf("** Sending %d bytes to Host **\n",uiSize);

	MNSend(gOurID, gHostID, /*DPSEND_GUARANTEED*/0, lMsg, uiSize);	
}
// ************************************************************************************************
void	MNSendHostGuaranteed(LPMNMSG_GENERIC lMsg,UINT uiSize)
{
	// MNPrintf("** Sending %d bytes (Guaranteed)to Host **\n",uiSize);

	MNSend(gOurID, gHostID, DPSEND_GUARANTEED, lMsg, uiSize);	
}
// ************************************************************************************************
void	MNBroadcastGuaranteed(LPMNMSG_GENERIC lMsg,UINT uiSize)
{
	// MNPrintf("** Broadcasting %d bytes (Guaranteed) **\n",uiSize);

	MNSend(gOurID, DPID_ALLPLAYERS, DPSEND_GUARANTEED, lMsg, uiSize);	
}
// ************************************************************************************************
void	MNBroadcast(LPMNMSG_GENERIC lMsg,UINT uiSize)
{
	// MNPrintf("** Broadcasting %d bytes (Guaranteed) **\n",uiSize);

	MNSend(gOurID, DPID_ALLPLAYERS, 0, lMsg, uiSize);	
}
// ************************************************************************************************
void	MNDispatchGuaranteed(LPMNMSG_GENERIC lMsg,UINT uiSize)
{
	if (!gbNetGame)
		return;
	
	if (gbHost)
			MNBroadcastGuaranteed(lMsg,uiSize);
	else
			MNSendHostGuaranteed(lMsg,uiSize);
}
// ************************************************************************************************
void	MNDispatch(LPMNMSG_GENERIC lMsg,UINT uiSize)
{
	if (!gbNetGame)
		return;

	if (gbHost)
			MNBroadcast(lMsg,uiSize);
	else
			MNSendHost(lMsg,uiSize);
}
// ************************************************************************************************
void MNSendMNSystemMessage(DPID	dpidPlayer,BYTE byMessage)
{
	MNMSG_GENERIC		sysMessage;
	sysMessage.byType=byMessage;

	MNSend(gOurID, dpidPlayer, DPSEND_GUARANTEED, (LPVOID)&sysMessage, sizeof(MNMSG_GENERIC));	

}
// ************************************************************************************************
void MNRemoveRemotePlayer(UINT uiPlayer)
{
	DPID	dpidPlayer=glpPlayerList->lpPLPlayerData[uiPlayer]->pidID;

	// Just do a sanity check to prevent us being killed by our foolishness
	if (dpidPlayer!=gOurID)
	{
		MNPrintf("******** MNRemoveRemotePlayer ********\n");
		MNSendMNSystemMessage(dpidPlayer,MNRM_REJECTED);
	}
}
// ************************************************************************************************
void MNRemoveAllRemotePlayers()
{
	MNPrintf("******** MNRemoveAllRemotePlayers ********\n");
	MNSendMNSystemMessage(DPID_ALLPLAYERS,MNRM_REJECTED);
}
// ************************************************************************************************
void MNRemovePlayer(DPID dpidPlayer)
{
HRESULT hResult;

// This is how a player appears in the list!
// glpPlayerList->lpPLPlayerData[uiPlayer]->pidID


	MNPrintf("* MNRemovePlayer *\n");


	hResult= IDirectPlay3_DestroyPlayer(	glpDP3A,				// Our DirectPlay Object
											dpidPlayer);


	RESULT(DPERR_INVALIDOBJECT)
	RESULT(DPERR_ACCESSDENIED)
	RESULT(DPERR_INVALIDPLAYER)
}
// ************************************************************************************************
//@func Destroys the named Player List
void MNDeletePlayerList(PLAYERLIST* lpPlayerList)
{
	unsigned int	uiPlayerListSize;

	if (lpPlayerList)
	{
		// get number of entries in the SP list
		uiPlayerListSize=lpPlayerList->uiPlayerListSize;

		while(uiPlayerListSize)
		{
			uiPlayerListSize--;	// Remember the list size is 0 for 0 items !

			if (lpPlayerList->lpPLPlayerData[uiPlayerListSize]->Name.lpszLongNameA)
				free((void*)lpPlayerList->lpPLPlayerData[uiPlayerListSize]->Name.lpszLongNameA);

			if (lpPlayerList->lpPLPlayerData[uiPlayerListSize]->Name.lpszShortNameA)
				free((void*)lpPlayerList->lpPLPlayerData[uiPlayerListSize]->Name.lpszShortNameA);

			free((void*)lpPlayerList->lpPLPlayerData[uiPlayerListSize]);

		}

		free(lpPlayerList);
	}
}
// ************************************************************************************************
//@func finds the names of players in the session specified
//@comm The session specified is one that is valid within the master glpSessionList
PLAYERLIST* MNFindPlayers(LPGUID lpGuidInstance,DWORD dwFlags)
{
	HRESULT hResult;

	MNPrintf("* MNFindSessionPlayers()\n");

	if (glpPlayerList)
		MNDeletePlayerList(glpPlayerList);

	glpPlayerList=malloc(sizeof(unsigned int));

	glpPlayerList->uiPlayerListSize=0;	// Initialise to zero number of found sessions


	hResult= IDirectPlay3_EnumPlayers(	glpDP3A,				// Our DirectPlay Object
										lpGuidInstance,
										MNEnumPlayerCallBack,
										&glpPlayerList,
										dwFlags);

	
	RESULT(DPERR_INVALIDOBJECT)
	RESULT(DPERR_EXCEPTION)
	RESULT(DPERR_GENERIC)
	RESULT(DPERR_UNSUPPORTED)

	return (glpPlayerList);
}
// ************************************************************************************************
PLAYERLIST* MNFindSessionPlayers(int iSession)
{
	return (MNFindPlayers(&glpSessionList->lpDPSessionDesc[iSession]->guidInstance,DPENUMPLAYERS_SESSION));
}
// ************************************************************************************************
PLAYERLIST* MNFindCurrentGamePlayers()
{
	return (MNFindPlayers(&lpdpCurrentSessionDesc->guidInstance,DPENUMPLAYERS_ALL));
}
// ************************************************************************************************
// *** History ***
// SPK 21051997 Created
//
// *** Functionality and notes ***
// @func Internal function, do not call directly!
BOOL WINAPI MNSessionCallBack(	
								LPCDPSESSIONDESC2 lpDPSessionDesc,	//@parm	a
								LPDWORD lpdwTimeOut,				//@parm	b
								DWORD dwFlags,						//@parm	c
								SESSIONLIST **lpContext)			//@parm d
{
	if (lpDPSessionDesc)
	{
	
		unsigned int	uiSessionListSize=0;
		SESSIONLIST*	lpNewSessionList=0;
		SESSIONLIST*	lpSessionList=*lpContext;

		MNPrintf("Found Session %s\n",lpDPSessionDesc->lpszSessionNameA);

		// Get the size of the original SPList
		uiSessionListSize=lpSessionList->uiSessionListSize;

		// Now create a nice new SPList
		lpNewSessionList=malloc(sizeof(unsigned int)+(uiSessionListSize+1)*(sizeof (LPDPSESSIONDESC2)));
		
		// Copy the original list into the new one
		memcpy(lpNewSessionList,lpSessionList,sizeof(unsigned int)+uiSessionListSize*(sizeof (LPDPSESSIONDESC2)));

		// Allocate some memory to hold the Session List and get a copy of it
		(void*)lpNewSessionList->lpDPSessionDesc[uiSessionListSize]=malloc(sizeof(DPSESSIONDESC2));

		memcpy((void*)lpNewSessionList->lpDPSessionDesc[uiSessionListSize],lpDPSessionDesc,sizeof (DPSESSIONDESC2));



		// Make duplicates of the name if it exists!
		if (lpDPSessionDesc->lpszSessionNameA)
		{
			(char*)lpNewSessionList->lpDPSessionDesc[uiSessionListSize]->lpszSessionName=lpNewSessionList->lpDPSessionDesc[uiSessionListSize]->lpszSessionNameA=malloc(strlen(lpDPSessionDesc->lpszSessionNameA)+1);
			strcpy(lpNewSessionList->lpDPSessionDesc[uiSessionListSize]->lpszSessionNameA,lpDPSessionDesc->lpszSessionNameA);
		}
		else
			(char*)lpNewSessionList->lpDPSessionDesc[uiSessionListSize]->lpszSessionName=lpNewSessionList->lpDPSessionDesc[uiSessionListSize]->lpszSessionNameA=NULL;
		// And also duplicate passwords if they exist

		if (lpDPSessionDesc->lpszPasswordA)
		{
			(char*)lpNewSessionList->lpDPSessionDesc[uiSessionListSize]->lpszPassword=lpNewSessionList->lpDPSessionDesc[uiSessionListSize]->lpszPasswordA=lpSessionList->lpDPSessionDesc[uiSessionListSize]->lpszPasswordA=malloc(strlen(lpDPSessionDesc->lpszPasswordA)+1);
			strcpy(lpNewSessionList->lpDPSessionDesc[uiSessionListSize]->lpszPasswordA,lpDPSessionDesc->lpszPasswordA);
		}
		//else
		//	(char*)lpNewSessionList->lpDPSessionDesc[uiSessionListSize]->lpszPassword=lpNewSessionList->lpDPSessionDesc[uiSessionListSize]->lpszPasswordA=lpSessionList->lpDPSessionDesc[uiSessionListSize]->lpszPasswordA=NULL;

		// Increase the size of the list
		lpNewSessionList->uiSessionListSize++;

		// Lets delete the old list
		free(lpSessionList);
  
		// And finally Make the new one the live one
		*lpContext=lpNewSessionList;
  
		return (TRUE);	
	}
	else
	{
		MNPrintf("No more sessions found\n");
		return (FALSE);
	}
}
// ************************************************************************************************
// *** History ***
// SPK 21051997 Created
//
// *** Functionality and notes ***
SESSIONLIST*	MNFindSessions(LPGUID lpGuid,DWORD dwFlags)
{
	// Destroy the old one if it still exists
	if (glpSessionList)
		MNDeleteSessionList(glpSessionList);

	glpSessionList=malloc(sizeof(unsigned int));

	if (glpSessionList)
	{
		HRESULT hr = E_FAIL;
		DPSESSIONDESC2 dpDesc;

		glpSessionList->uiSessionListSize=0;	// Initialise to zero number of found sessions

		ZeroMemory(&dpDesc, sizeof(dpDesc));
		dpDesc.dwSize = sizeof(dpDesc);

		if (lpGuid)
			dpDesc.guidApplication = *lpGuid;
		else
			dpDesc.guidApplication = GUID_NULL;


		MNPrintf("Searching for sessions\n");

		IDirectPlay3_EnumSessions(		glpDP3A,				// Our DirectPlay Object
										&dpDesc,		
										0,						// Timeout, let DirectPlay decide this
										MNSessionCallBack,		// Internal enumeration callback to generate SP list
										&glpSessionList,			// Pointer to Session list
										dwFlags);	// Flags

		MNPrintf("Session search over\n");
	}


	return (glpSessionList);
}
// ************************************************************************************************
// @func Find all active game sessions on the currently initialised Service Provider (e.g TCP/IP or IPX)
SESSIONLIST*	MNFindActiveSessions()
{
	// Okay we will find all sessions that are for this game
	// AND we will get all active sessions (excluding passworded ones.
	return (MNFindSessions(glpGuid,DPENUMSESSIONS_ALL));
}
// ************************************************************************************************
// @func Destroy the named session list
// @rdesc Nothing
// @comm This is usually only used internally. Usually the function will get called with glpSessionList as the main parameter, but his does not have to be the case.
// 
void MNDeleteSessionList(
						 SESSIONLIST* lpSessionList	//@parm Session to destroy, if this is NULL then nothing will happen.
						 )
{
	unsigned int	uiSessionListSize;

	if (lpSessionList)
	{
		// get number of entries in the SP list
		uiSessionListSize=lpSessionList->uiSessionListSize;

		while(uiSessionListSize)
		{
			uiSessionListSize--;	// Remember the list size is 0 for 0 items !
			if (lpSessionList->lpDPSessionDesc[uiSessionListSize]->lpszSessionNameA)
				free((void*)lpSessionList->lpDPSessionDesc[uiSessionListSize]->lpszSessionNameA);

			if (lpSessionList->lpDPSessionDesc[uiSessionListSize]->lpszPasswordA)
				free((void*)lpSessionList->lpDPSessionDesc[uiSessionListSize]->lpszPasswordA);

			free((void*)lpSessionList->lpDPSessionDesc[uiSessionListSize]);
		}

		free(lpSessionList);
	}
}
// ************************************************************************************************
// @func Get's the Session Description for the current session
// @rdesc Nothing
void MNGetSessionDescription()
{
	HRESULT hResult;
	DWORD	dwDataSize=0;	//Initial value to fool the system
	//LPVOID	lpData;			// This should be cast to DPSESSIONDESC2 to read data
	
	MNPrintf("* MNGetSessionDescription()\n");


	if (lpdpCurrentSessionDesc)
		free(lpdpCurrentSessionDesc);
	
	hResult=IDirectPlay3_GetSessionDesc(	glpDP3A,
											0,
											&dwDataSize);	// First request the size of the data!

	if (hResult!=DP_OK && hResult!=DPERR_BUFFERTOOSMALL) goto Error;


	lpdpCurrentSessionDesc=malloc(dwDataSize);

	hResult=IDirectPlay3_GetSessionDesc(	glpDP3A,
											lpdpCurrentSessionDesc,
											&dwDataSize);	// Now actually get the data


	if (hResult==DP_OK) goto Error;


	return;

Error:
	RESULT(DPERR_BUFFERTOOSMALL)
	RESULT(DPERR_INVALIDOBJECT)
	RESULT(DPERR_INVALIDPARAMS)
	RESULT(DPERR_NOCONNECTION)
	RESULT(DPERR_NOSESSIONS)
}
// ************************************************************************************************
void				MNCloseSession()
{
HRESULT hResult;
// gOurID
	MNPrintf("* MNCloseSession()\n");

	hResult=IDirectPlay3_Close(glpDP3A);
											
	RESULT(DPERR_INVALIDOBJECT)
	RESULT(DPERR_INVALIDPARAMS)
	RESULT(DPERR_NOSESSIONS)

	gbHost=FALSE;
	
}
// ************************************************************************************************
BOOL MNOpenSession(LPDPSESSIONDESC2 lpDPSessionDesc,DWORD dwFlags)
{
	HRESULT hResult;

	MNPrintf("* MNOpenSession()\n");

	hResult=IDirectPlay3_Open(	glpDP3A,
								lpDPSessionDesc,
								dwFlags);
								
	if (hResult==DP_OK)
		return TRUE;

	RESULT(DPERR_ACTIVEPLAYERS)
	RESULT(DPERR_ALREADYINITIALIZED)
	RESULT(DPERR_GENERIC)
	RESULT(DPERR_INVALIDFLAGS)
	RESULT(DPERR_INVALIDOBJECT)
	RESULT(DPERR_INVALIDPARAMS)
	RESULT(DPERR_UNAVAILABLE)
	RESULT(DPERR_UNSUPPORTED)
	RESULT(DPERR_USERCANCEL)

	return FALSE;
}
// ************************************************************************************************
BOOL MNJoinGame(int iSession)
{
	gbHost=FALSE;
	return MNOpenSession(	glpSessionList->lpDPSessionDesc[iSession],
							DPOPEN_JOIN);
}
// ************************************************************************************************
BOOL MNNewGame(LPSTR lpszSessionName)
{

	ZeroMemory(&dpHostSessionDesc, sizeof(dpHostSessionDesc));
	dpHostSessionDesc.dwSize = sizeof(dpHostSessionDesc);
	dpHostSessionDesc.guidApplication = *glpGuid;
	dpHostSessionDesc.dwMaxPlayers=100;
	dpHostSessionDesc.lpszSessionNameA=lpszSessionName;

	MNPrintf("* Attempting to create a new session\n");

	gbHost=TRUE;

	return MNOpenSession(	&dpHostSessionDesc,
							DPOPEN_CREATE);
}
// ************************************************************************************************
BOOL MNCreatePlayer()
{
	HRESULT hResult;
	DPID	idPlayer;
	HANDLE	hEvent=NULL;
	LPVOID	lpData=NULL;
	DWORD	dwDataSize=0;
	DWORD	dwFlags=0;
	DPNAME	dpName;

	MNValidateLocalPlayerName();	// Just make sure the caller has actually set up a name!

	ZeroMemory(&dpName,sizeof(DPNAME));
	dpName.dwSize=sizeof(DPNAME);
	dpName.dwFlags=0;
	dpName.lpszShortNameA=lpszLocalPlayerName;

	MNPrintf("* Attempting to create a new player\n");


	hResult= IDirectPlay3_CreatePlayer(	glpDP3A,
										&idPlayer,
										&dpName,	//lpszLocalPlayerName,
										hEvent,
										lpData,
										dwDataSize,
										dwFlags);
			


	if (hResult==DP_OK)
	{
		gOurID=idPlayer;
		MNStartPolling(10);
		gbNetGame=TRUE;
		return (TRUE);
	}

	RESULT(DPERR_GENERIC)
	RESULT(DPERR_INVALIDOBJECT)
	RESULT(DPERR_INVALIDPARAMS)
	RESULT(DPERR_CANTADDPLAYER)
	RESULT(DPERR_CANTCREATEPLAYER)
	RESULT(DPERR_NOCONNECTION)
	return (FALSE);
}
// ************************************************************************************************
HRESULT MNReceive(LPDPID lpidFrom, LPDPID lpidTo, DWORD dwFlags, LPVOID lpData, LPDWORD lpdwDataSize)
{
	HRESULT hResult = E_FAIL;

	if (glpDP3A)
		hResult = IDirectPlay3_Receive(	glpDP3A,
										lpidFrom,
										lpidTo,
										dwFlags,
										lpData,
										lpdwDataSize);

	RESULT(DPERR_GENERIC)
	//RESULT(DPERR_BUFFERTOOSMALL)
	RESULT(DPERR_INVALIDOBJECT)
	RESULT(DPERR_INVALIDPARAMS)
	RESULT(DPERR_INVALIDPLAYER)
	//RESULT(DPERR_NOMESSAGES)
	

	return hResult;
}
// ************************************************************************************************
HRESULT MNSend(DPID idFrom, DPID idTo, DWORD dwFlags, LPVOID lpData, DWORD dwDataSize)
{
	HRESULT hResult = E_FAIL;

	if (glpDP3A)
		hResult = IDirectPlay3_Send(	glpDP3A, 
										idFrom, 
										idTo, 
										dwFlags, 
										lpData, 
										dwDataSize);

	RESULT(DPERR_INVALIDOBJECT)
	RESULT(DPERR_INVALIDPARAMS)
	RESULT(DPERR_INVALIDPLAYER)
	RESULT(DPERR_SENDTOOBIG)
	
	return hResult;
}
// ************************************************************************************************
/*
 * DoSystemMessage
 *
 * Evaluates system messages and performs appropriate actions
 */
void MNDPlaySystemMessage( LPDPMSG_GENERIC lpMsg, DWORD dwMsgSize, DPID idFrom, DPID idTo )
{
    switch( lpMsg->dwType)
    {
    case DPSYS_CREATEPLAYERORGROUP:
        {
        	LPDPMSG_CREATEPLAYERORGROUP lpAddMsg = (LPDPMSG_CREATEPLAYERORGROUP) lpMsg;
			MNPrintf("** DPSYS_CREATEPLAYERORGROUP **\n");
			MNPostMessage(MNM_NEW_PLAYER,0,0L);


			if (gbHost)	// Tell them who the host is on joining
			{
				MNSendClientHostID(idFrom);
			}

			//
			//
			//
			//
			//
		
		
		}
		break;

    case DPSYS_DESTROYPLAYERORGROUP:
        {
        	LPDPMSG_DESTROYPLAYERORGROUP lpDestroyMsg = (LPDPMSG_DESTROYPLAYERORGROUP) lpMsg;

			if (gOurID!=lpDestroyMsg->dpId)
			{
				MNPrintf("** (NOT ME THOUGH) LPDPMSG_DESTROYPLAYERORGROUP **\n");
			}
			else
			{
				MNPrintf("** LPDPMSG_DESTROYPLAYERORGROUP **\n");

				if (!gbHost && (idTo==gOurID))
				{
					//MNRemovePlayer(idTo);
					MNCloseSession();
				}
			}

			MNPostMessage(MNM_PLAYER_LOST,0,0L);
			//
			//
			//
			//
			//
        }
		break;

	case DPSYS_HOST:
        {	    	
			MNPrintf("** DPSYS_HOST **\n");
            gbHost = TRUE;            
			//UpdateTitle();*/
        }

		break;

    case DPSYS_SESSIONLOST:
			MNPrintf("** DPSYS_SESSIONLOST **\n");
		/*
        // inform user that session was lost
        ShowError(IDS_DPLAY_ERROR_SL);
        gbSessionLost = TRUE;*/
        break;
    }
}
// ************************************************************************************************
void MNSystemMessage( LPMNMSG_GENERIC lpMsg, DWORD dwMsgSize, DPID idFrom, DPID idTo )
{
    switch( lpMsg->byType)
    {
		// -----------------
		case MNRM_START_GAME:
			MNPrintf("** MNRM_START_GAME **\n");
			MNPostMessage(MNM_START_GAME,0,0L);
			{
			PLAYERLIST*	lpPlayerList=MNGetPlayerList();

				if (lpPlayerList)
				{
					// get number of entries in the SP list
					uiPlayersInGame=lpPlayerList->uiPlayerListSize;				
				}
			}
			break;
		// -----------------
		case MNRM_REJECTED:
			MNPrintf("** MNRM_REJECTED **\n");
			MNPostMessage(MNM_REJECTED,0,0L);

			break;
		// -----------------
		case MNRM_PLAYERNUMBER:
			{
	        	LPMNMSG_PLAYERNUMBER lpmsgpnPlayerMessage = (LPMNMSG_PLAYERNUMBER) lpMsg;
				MNPrintf("** MNRM_PLAYERNUMBER **\n");

				guiPlayer=lpmsgpnPlayerMessage->uiPlayerNumber;

			}
			break;
		// -----------------
		case MNRM_HOSTID:
			{
	        	LPMNMSG_HOSTID lpHostIDMsg = (LPMNMSG_HOSTID) lpMsg;
				MNPrintf("** MNRM_HOSTID **\n");

				gHostID=lpHostIDMsg->idHost;
			}
			break;

		// -----------------
		// This section is for testing
		case MNRM_BROADCAST:
			{
	        	LPMNMSG_BLOCK lpBlockMsg = (LPMNMSG_BLOCK) lpMsg;
		
				// If we are the host we will retransmit this
				if (gbHost)
					MNBroadcast((LPMNMSG_GENERIC)lpMsg,dwMsgSize);

				// We also want to use it
				if(lpBlockMsg->uMsg)
				{
					void* Temp=malloc(dwMsgSize);
					memcpy(Temp,(void*)lpBlockMsg,dwMsgSize);
					MNPostMessage(lpBlockMsg->uMsg,(unsigned int)Temp,0L);
				}
			}
			break;
			
		// -----------------
		case MNRM_BROADCAST_GUARANTEED:
			{
	        	LPMNMSG_BLOCK lpBlockMsg = (LPMNMSG_BLOCK) lpMsg;
		
				// If we are the host we will retransmit this
				if (gbHost)
					MNBroadcastGuaranteed((LPMNMSG_GENERIC)lpMsg,dwMsgSize);

				// We also want to use it
				if(lpBlockMsg->uMsg)
				{
					void* Temp=malloc(dwMsgSize);
					memcpy(Temp,(void*)lpBlockMsg,dwMsgSize);
					MNPostMessage(lpBlockMsg->uMsg,(unsigned int)Temp,0L);
				}
			}
			break;
			
		// -----------------
		case MNRM_GAME_BROADCAST:
			{
				// If we are the host we will retransmit this
				if (gbHost)
					MNBroadcast((LPMNMSG_GENERIC)lpMsg,dwMsgSize);

				if (MNGameMessageHandlerCallBack)
					(MNGameMessageHandlerCallBack)((LPMNGAMEMSG_GENERIC)lpMsg,dwMsgSize,idFrom,idTo);

			}
			break;
		// -----------------
		case MNRM_GAME_BROADCAST_GUARANTEED:
			{
				// If we are the host we will retransmit this
				if (gbHost)
					MNBroadcastGuaranteed((LPMNMSG_GENERIC)lpMsg,dwMsgSize);

				if (MNGameMessageHandlerCallBack)
					(MNGameMessageHandlerCallBack)((LPMNGAMEMSG_GENERIC)lpMsg,dwMsgSize,idFrom,idTo);
			}
			break;
		// -----------------
		default:
				MNPrintf("** UNKNOWN MESSAGE TYPE RECEIVED **\n");
		// -----------------
	}
}
// ************************************************************************************************
/*
 * ReceiveGameMessages
 *
 * Checks if there are any messages for us and receives them
 */
HRESULT	MNReceiveMessages()
{
	DPID				idFrom, idTo;
	LPVOID				lpvMsgBuffer;
	DWORD				dwMsgBufferSize;
	HRESULT				hResult;


	{
		// Are there really any messages pending
		DWORD	dwMessageCount=0;

		hResult=IDirectPlay3_GetMessageCount(	glpDP3A,
												gOurID,
												&dwMessageCount);


		RESULT(DPERR_INVALIDOBJECT)
		RESULT(DPERR_INVALIDPARAMS)
		RESULT(DPERR_INVALIDPLAYER)

		if (!dwMessageCount)
			return (TRUE);

		if (dwMessageCount>10)
			MNPrintf("** Queue is %d **\n",dwMessageCount);
	}



	// read all messages in queue
	dwMsgBufferSize = gdwReceiveBufferSize;
	lpvMsgBuffer = glpvReceiveBuffer;
	
	while (TRUE)
	{
		// see what's out there
		idFrom = 0;
		idTo = 0;

		hResult = MNReceive(&idFrom, &idTo, DPRECEIVE_ALL, lpvMsgBuffer, &dwMsgBufferSize);
		if (hResult == DPERR_BUFFERTOOSMALL)
		{
			if (lpvMsgBuffer == NULL)
			{
				lpvMsgBuffer = GlobalAllocPtr(GHND, dwMsgBufferSize);
				if (lpvMsgBuffer == NULL)
					return (DPERR_NOMEMORY);
				glpvReceiveBuffer = lpvMsgBuffer;
				gdwReceiveBufferSize = dwMsgBufferSize;
			}
			else if (dwMsgBufferSize > gdwReceiveBufferSize)
			{
				lpvMsgBuffer = GlobalReAllocPtr(lpvMsgBuffer, dwMsgBufferSize, 0);
				if (lpvMsgBuffer == NULL)
					return (DPERR_NOMEMORY);
				glpvReceiveBuffer = lpvMsgBuffer;
				gdwReceiveBufferSize = dwMsgBufferSize;
			}
		}
		else if ((hResult == DP_OK) && 
                 ((dwMsgBufferSize >= sizeof(MNMSG_GENERIC)) || 
                  (dwMsgBufferSize >= sizeof(DPMSG_GENERIC))))
		{
			if (idFrom == DPID_SYSMSG)
            {
				MNDPlaySystemMessage((LPDPMSG_GENERIC) lpvMsgBuffer, dwMsgBufferSize, idFrom, idTo);
				//MNPrintf("** DPlay System Message **\n");
            }
			else
            {
				MNSystemMessage((LPMNMSG_GENERIC) lpvMsgBuffer, dwMsgBufferSize, idFrom, idTo);
				//MNPrintf("** MN System Message **\n");
            }
		}
		else
			break;
	};

    return hResult;
}
// ************************************************************************************************
void CALLBACK MNTimerEvent(	UINT	uiID,	// ID of this event
							UINT	uMsg,	// Reserved by Microsoft
							DWORD	dwUser,	// User instance data (not used here)
							DWORD	dw1,	// Reserved by Microsoft
							DWORD	dw2		// Reserved by Microsoft
							)
{
	if (gbAllowPoll)
		MNReceiveMessages();
}
// ************************************************************************************************
BOOL MNStartPolling(UINT uiInterval)	// Ticks per second
{
	MNStopPolling();
	if (!MNTimerRes)
	{
		if(timeGetDevCaps(&MNTimeCaps,sizeof(TIMECAPS))==TIMERR_NOERROR)
		{
			MNTimerRes = __min(__max(MNTimeCaps.wPeriodMin, TARGET_RESOLUTION),MNTimeCaps.wPeriodMax);

			MNPrintf("+Requested:	%u with max %u\n+Received:	%u\n",TARGET_RESOLUTION,TARGET_MAXIMUM,MNTimerRes);

			if(MNTimerRes>TARGET_MAXIMUM)
			{
				MNPrintf("++++++ WARNING: Timer useless ++++++");
				return FALSE;
			}
		}
	}
	if (MNTimerRes)
	{
		timeBeginPeriod(MNTimerRes);
		MNTimerID=timeSetEvent(	1000/uiInterval, 
								MNTimerRes, 
								MNTimerEvent, 
								0, 
								TIME_PERIODIC);
	}

	gbAllowPoll=TRUE;
}
//void (__stdcall *)(void *,unsigned int ,unsigned int ,unsigned long )' 
//void (__stdcall *)(unsigned int ,unsigned int ,unsigned long ,unsigned long ,unsigned long )'
// ************************************************************************************************
void MNStopPolling()
{
	if (MNTimerID)
	{
		timeKillEvent(MNTimerID);
		timeEndPeriod(MNTimerRes);
	}

	MNTimerID=0;
	gbAllowPoll=FALSE;
}
// ************************************************************************************************
