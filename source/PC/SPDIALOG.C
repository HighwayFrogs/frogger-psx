#include "NetPlay.h"
#include "SPDialog.h"
#include "resource.h"
#include <stdio.h>

#define WIBBLE MNM_USER+1

// ************************************************************************************************
void GetPlayers(HWND hwndDlg)
{
	MNFindCurrentGamePlayers();
	{
		unsigned int	uiPlayerListSize;
		PLAYERLIST*	lpPlayerList=MNGetPlayerList();

		if (lpPlayerList)
		{
			// get number of entries in the SP list
			uiPlayerListSize=lpPlayerList->uiPlayerListSize;


			SendMessage(	GetDlgItem(hwndDlg,IDC_LIST1),
							LB_RESETCONTENT,
							0,
							0L);

			while(uiPlayerListSize)
			{
				uiPlayerListSize--;
				// Fill out the list box
				SendMessage(	GetDlgItem(hwndDlg,IDC_LIST1),
								LB_INSERTSTRING,
								0,
								(DWORD)lpPlayerList->lpPLPlayerData[uiPlayerListSize]->Name.lpszShortName);
			}
		}
	}
}
// ************************************************************************************************
BOOL CALLBACK HostSessionDialogProc(
							HWND hwndDlg,		// handle to dialog box 
							UINT uMsg,			// message 
							WPARAM wParam,		// first message parameter 
							LPARAM lParam		// second message parameter 
						)
{
	switch (uMsg)
	{
	case MNM_PLAYER_LOST:
	case MNM_NEW_PLAYER:
		GetPlayers(hwndDlg);
		return TRUE;
	// ----------------------------
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		// ++++++++++++++++++++++++
		case IDC_REMOVE:
			{
			DWORD dwReturned=SendMessage(	GetDlgItem(hwndDlg,IDC_LIST1),
											LB_GETCURSEL,
											0,0L);

			MNRemoveRemotePlayer(dwReturned);
			}
			return TRUE;
		// ++++++++++++++++++++++++
		case IDCANCEL:
			MNRemoveAllRemotePlayers();
			MNCloseSession();
			EndDialog(hwndDlg,2);
			return TRUE;
		// ++++++++++++++++++++++++
		case IDOK:
			{
				PLAYERLIST*	lpPlayerList=MNGetPlayerList();

				if (lpPlayerList)
				{
					// get number of entries in the SP list
					if (lpPlayerList->uiPlayerListSize<=1)
						return FALSE;

				}
				else
					return FALSE;
			}
			MNSignalGameStart();
			EndDialog(hwndDlg,1);
			return TRUE;
		// ++++++++++++++++++++++++
		}
		break;
	// ----------------------------
	case WM_INITDIALOG:
		SetWindowText(hwndDlg,"New Session");
		GetPlayers(hwndDlg);
		MNRegisterWindow(hwndDlg);
		return TRUE;
	// ----------------------------
	case WM_DESTROY:
		EndDialog(hwndDlg,0);
		return TRUE;

	}
	return FALSE;
}
// ************************************************************************************************
BOOL CALLBACK ClientSessionDialogProc(
							HWND hwndDlg,		// handle to dialog box 
							UINT uMsg,			// message 
							WPARAM wParam,		// first message parameter 
							LPARAM lParam		// second message parameter 
						)
{
	switch (uMsg)
	{
	case WIBBLE:
		{
			//LPMNMSG_BLOCK lpBlockMsg = (LPMNMSG_BLOCK) wParam;			
			//SetDlgItemText(	hwndDlg,
			//				IDC_EDIT1,
			//				(char*)lpBlockMsg->cBlock
			//				);
			//free((void*)lpBlockMsg);
			return TRUE;
		}
	case MNM_REJECTED:
		MNCloseSession();
		EndDialog(hwndDlg,2);
		return TRUE;
	case MNM_START_GAME:
		EndDialog(hwndDlg,1);
		return TRUE;

	case MNM_PLAYER_LOST:
	case MNM_NEW_PLAYER:
		GetPlayers(hwndDlg);
		return TRUE;
	// ----------------------------
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		// ++++++++++++++++++++++++
		case IDCANCEL:
			MNCloseSession();
			EndDialog(hwndDlg,2);
			return TRUE;
		// ++++++++++++++++++++++++
		case MNM_START_GAME:
		case IDOK:
			EndDialog(hwndDlg,1);
			return TRUE;
		// ++++++++++++++++++++++++
		}
		break;
	// ----------------------------
	case WM_INITDIALOG:
		SetWindowText(hwndDlg,"Client Session");
		GetPlayers(hwndDlg);
		MNRegisterWindow(hwndDlg);
		return TRUE;
	// ----------------------------
	case WM_DESTROY:
		EndDialog(hwndDlg,0);
		return TRUE;

	}
	return FALSE;
}
// ************************************************************************************************
void GetSessions(HWND hwndDlg)
{
			unsigned int	uiSessionListSize;
			SESSIONLIST*	lpSessionList=MNFindActiveSessions();

			if (lpSessionList)
			{
				SetWindowText(hwndDlg,"Select Session");

				// get number of entries in the SP list
				uiSessionListSize=lpSessionList->uiSessionListSize;

				SendMessage(	GetDlgItem(hwndDlg,IDC_LIST1),
								LB_RESETCONTENT,
								0,
								0L);

				while(uiSessionListSize)
				{
					uiSessionListSize--;
					// Fill out the list box
					SendMessage(	GetDlgItem(hwndDlg,IDC_LIST1),
									LB_INSERTSTRING,
									0,
									(DWORD)lpSessionList->lpDPSessionDesc[uiSessionListSize]->lpszSessionNameA);
				}
			}
			else
				SetWindowText(hwndDlg,"No sessions found");

}
// ************************************************************************************************
BOOL CALLBACK SessionDialogProc(
							HWND hwndDlg,		// handle to dialog box 
							UINT uMsg,			// message 
							WPARAM wParam,		// first message parameter 
							LPARAM lParam		// second message parameter 
						)
{
	switch (uMsg)
	{
	// ----------------------------
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		// ++++++++++++++++++++++++
		case IDC_REFRESH:
			GetSessions(hwndDlg);
			return TRUE;
		// ++++++++++++++++++++++++
		case IDC_NEW:
			{
				char Buffer[200];

				
				GetDlgItemText(	hwndDlg,
								IDC_SESSIONNAME,
								(char*)&Buffer,
								199);

				MNPrintf("Want to create session %s",Buffer);
				MNNewGame(Buffer);

				EndDialog(hwndDlg,-1);
			}
			return TRUE;
		case IDC_JOIN:
		case IDOK:
			{
				DWORD dwReturned=SendMessage(	GetDlgItem(hwndDlg,IDC_LIST1),
												LB_GETCURSEL,
												0,0L);

				if (dwReturned==LB_ERR)
					dwReturned=0;
				else
					dwReturned++;	//Adjust so that the return code can see what the return value was!

				MNPrintf("SessionDialog returns %d\n",dwReturned);

				EndDialog(hwndDlg,dwReturned);
			}
			return TRUE;
		// ++++++++++++++++++++++++
		case IDCANCEL:
			EndDialog(hwndDlg,0);
			return TRUE;
		// ++++++++++++++++++++++++
		case IDC_LIST1:
			switch (HIWORD(wParam))
			{
			case LBN_SELCHANGE:
				{
					char Buffer[256];
					// Just changed a selection so let's find the number of players!
					DWORD dwReturned=SendMessage(	(HWND) lParam,
													LB_GETCURSEL,
													0,0L);

					sprintf(Buffer,"Players %d (%d)",MNGetSessionList()->lpDPSessionDesc[dwReturned]->dwCurrentPlayers,MNGetSessionList()->lpDPSessionDesc[dwReturned]->dwMaxPlayers);
					SetWindowText(GetDlgItem(hwndDlg,IDC_PLAYERS),Buffer);

					//MNJoinGame(dwReturned);
					//MNGetSessionDescription();
					MNFindSessionPlayers(dwReturned);
					{
						unsigned int	uiPlayerListSize;
						PLAYERLIST*	lpPlayerList=MNGetPlayerList();

						if (lpPlayerList)
						{
							// get number of entries in the SP list
							uiPlayerListSize=lpPlayerList->uiPlayerListSize;


							SendMessage(	GetDlgItem(hwndDlg,IDC_LIST2),
											LB_RESETCONTENT,
											0,
											0L);


				
							while(uiPlayerListSize)
							{
								uiPlayerListSize--;
								// Fill out the list box
								SendMessage(	GetDlgItem(hwndDlg,IDC_LIST2),
												LB_INSERTSTRING,
												0,
												(DWORD)lpPlayerList->lpPLPlayerData[uiPlayerListSize]->Name.lpszShortName);
							}
						}
					}

					return TRUE;
				}
			}
			return TRUE;
		// ++++++++++++++++++++++++
		}
		break;
	// ----------------------------
	case WM_INITDIALOG:
		GetSessions(hwndDlg);
		return TRUE;
	// ----------------------------
	case WM_DESTROY:
		EndDialog(hwndDlg,0);
		return TRUE;
	// ----------------------------
	default:
		break;
	}
	return FALSE;
}
// ************************************************************************************************
BOOL CALLBACK SPDialogProc(
							HWND hwndDlg,		// handle to dialog box 
							UINT uMsg,			// message 
							WPARAM wParam,		// first message parameter 
							LPARAM lParam		// second message parameter 
						)
{
	switch (uMsg)
	{
	// ----------------------------
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		// ++++++++++++++++++++++++
		case IDOK:
			{
				DWORD dwReturned=SendMessage(	GetDlgItem(hwndDlg,IDC_LIST1),
												LB_GETCURSEL,
												0,0L);

				if (dwReturned==LB_ERR)
					dwReturned=0;
				else
					dwReturned++;	//Adjust so that the return code can see what the return value was!

				MNPrintf("SPDialog returns %d\n",dwReturned);

				EndDialog(hwndDlg,dwReturned);
			}
			return TRUE;
		// ++++++++++++++++++++++++
		case IDCANCEL:
			EndDialog(hwndDlg,0);
			return TRUE;
		// ++++++++++++++++++++++++
		}
		break;
	// ----------------------------
	case WM_INITDIALOG:
		{
			unsigned int	uiSPListSize;
			SPLIST*			lpSPList=MNGetServiceProviderList();

			SetWindowText(hwndDlg,"Select Service Provider");

			if (lpSPList)
			{
				// get number of entries in the SP list
				uiSPListSize=lpSPList->uiSPListSize;

				while(uiSPListSize)
				{
					uiSPListSize--;
					// Fill out the list box
					SendMessage(	GetDlgItem(hwndDlg,IDC_LIST1),
									LB_INSERTSTRING,
									0,
									(DWORD)lpSPList->spSPList[uiSPListSize].lpszSPName);
				}
			}


		}
		return TRUE;
	// ----------------------------
	case WM_DESTROY:
		EndDialog(hwndDlg,0);
		return TRUE;
	// ----------------------------
	default:
		break;
	}
	return FALSE;
}
// ************************************************************************************************
