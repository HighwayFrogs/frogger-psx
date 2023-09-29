#ifndef _SPDIALOGH
#define _SPDIALOGH

BOOL CALLBACK SPDialogProc(
							HWND hwndDlg,		// handle to dialog box 
							UINT uMsg,			// message 
							WPARAM wParam,		// first message parameter 
							LPARAM lParam		// second message parameter 
						  );

BOOL CALLBACK SessionDialogProc(
							HWND hwndDlg,		// handle to dialog box 
							UINT uMsg,			// message 
							WPARAM wParam,		// first message parameter 
							LPARAM lParam		// second message parameter 
						  );

BOOL CALLBACK HostSessionDialogProc(
							HWND hwndDlg,		// handle to dialog box 
							UINT uMsg,			// message 
							WPARAM wParam,		// first message parameter 
							LPARAM lParam		// second message parameter 
						  );

BOOL CALLBACK ClientSessionDialogProc(
							HWND hwndDlg,		// handle to dialog box 
							UINT uMsg,			// message 
							WPARAM wParam,		// first message parameter 
							LPARAM lParam		// second message parameter 
						  );

#endif