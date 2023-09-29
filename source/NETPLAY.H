#define IDIRECTPLAY2_OR_GREATER
#include <dplay.h>
#ifndef _M_NETPLAY_H
#define _M_NETPLAY_H
// ************************************************************************************************
// Structures

// *** Service provider information ***
typedef struct 
{
	LPVOID				lpConnection;		// Connection information including GUID (was LPGUID lpSPGuid)
	DWORD				dwSize;				// Size of the above structure
	LPTSTR				lpszSPName;			// Short name of the SP
} SP;

// *** Service Provider List ***
typedef struct
{
	unsigned int		uiSPListSize;
	SP					spSPList[];
} SPLIST;

// *** Session Description List ***
typedef struct
{
	unsigned int		uiSessionListSize;
	DPSESSIONDESC2*		lpDPSessionDesc[];
} SESSIONLIST;

// *** Player Description List ***
typedef struct
{
	DPID	pidID;
	DWORD	dwPlayerType;
	DPNAME	Name;
	DWORD	dwFlags;
} PLDATA, *LPPLDATA;

typedef struct
{
	unsigned int	uiPlayerListSize;
	LPPLDATA		lpPLPlayerData[];

} PLAYERLIST;

// *** Stock Message Structure
typedef struct _MNMSG_GENERIC
{
    BYTE        byType;
} MNMSG_GENERIC, *LPMNMSG_GENERIC;

typedef struct _MNGAMEMSG_GENERIC
{
    BYTE        byType;
	UINT		uMsg;
} MNGAMEMSG_GENERIC, *LPMNGAMEMSG_GENERIC;

typedef struct _MNMSG_HOSTID
{
    BYTE        byType;
	DPID		idHost;
} MNMSG_HOSTID, *LPMNMSG_HOSTID;

typedef struct _MNMSG_PLAYERNUMBER
{
    BYTE        byType;
	UINT		uiPlayerNumber;
} MNMSG_PLAYERNUMBER, *LPMNMSG_PLAYERNUMBER;


typedef struct _MNMSG_BLOCK
{
    BYTE        byType;
	UINT		uMsg;

	UINT		uiSize;
	char		cBlock[];
} MNMSG_BLOCK, *LPMNMSG_BLOCK;



#define RESULT(a) if (hResult==(a)) MNPrintf("*** Error: %s ***\n",#a);

#define MN_INVALID 0xffffffff
// ************************************************************************************************
// Public functions
extern HRESULT			MNClose();
extern HRESULT			MNInitialise(LPGUID);
extern SPLIST*			MNFindServiceProviders();
extern void				MNDeleteServiceProviderList(SPLIST*);
extern void				MNDeleteSessionList(SESSIONLIST*);
extern LPDIRECTPLAY3A	MNGetDirectPlayInterface();
extern BOOL				MNCreateConnection(unsigned int);
extern BOOL				MNCreateConnectionRaw(SPLIST*,unsigned int);
extern SESSIONLIST*		MNFindActiveSessions();
extern void				MNGetSessionDescription();
extern SPLIST*			MNGetServiceProviderList();
extern SESSIONLIST*		MNGetSessionList();
extern BOOL				MNJoinGame(int);
extern BOOL				MNNewGame(LPSTR);
extern PLAYERLIST*		MNFindSessionPlayers(int);
extern PLAYERLIST*		MNGetPlayerList();
extern void				MNSetLocalPlayerName(LPSTR);
extern void				MNDeleteLocalPlayerName();
extern PLAYERLIST*		MNFindCurrentGamePlayers();
extern BOOL				MNCreatePlayer();
extern HRESULT			MNReceiveMessages();
extern void				MNRegisterWindow(HWND);
extern void				MNInvalidateWindow();
extern void				MNRemoveRemotePlayer(UINT);
extern void				MNRemoveAllRemotePlayers();
extern void				MNRemovePlayer(DPID);
extern void				MNCloseSession();
extern void				MNSendHost(LPMNMSG_GENERIC,UINT);
extern void				MNSendHostGuaranteed(LPMNMSG_GENERIC,UINT);
extern BOOL				MNHost();
extern DPID				MNGetID();
extern void				MNBroadcastGuaranteed(LPMNMSG_GENERIC,UINT);
extern void				MNBroadcast(LPMNMSG_GENERIC,UINT);
extern UINT				MNGetPlayerNumber();
extern void				MNIssuePlayerNumbers();
extern void				MNStartPoll();
extern void				MNStopPoll();
extern BOOL				MNIsNetGameRunning();
extern void				MNSetGameMessageHandlerCallback(void (*)(LPMNGAMEMSG_GENERIC, DWORD, DPID, DPID));
extern void				MNDispatchGuaranteed(LPMNMSG_GENERIC,UINT);
extern void				MNDispatch(LPMNMSG_GENERIC,UINT);
extern void				MNSignalGameStart();
extern UINT				MNPlayersInGame();


enum{
		MNM_BASE = WM_USER+123,
		MNM_NEW_PLAYER,
		MNM_PLAYER_LOST,
		MNM_REJECTED,
		MNM_START_GAME,



		MNM_USER
} MN_MESSAGES;

enum{
	MNRM_REJECTED,
	MNRM_HOSTID,
	MNRM_BROADCAST,
	MNRM_BROADCAST_GUARANTEED,
	MNRM_GAME_BROADCAST,
	MNRM_GAME_BROADCAST_GUARANTEED,
	MNRM_PLAYERNUMBER,
	MNRM_START_GAME,
	MNRM_SYNC,

} MN_REMOTE_MESSAGES;


extern void __cdecl MNPrintf(char *format, ...);

// ************************************************************************************************
#endif