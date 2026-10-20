/*
 * (C) 2026- TeraTerm Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * FIDO セキュリティキーによる署名 (sk-ssh-ed25519@openssh.com)
 *
 * 管理者権限のないプロセスは FIDO デバイスに直接アクセスできないため、
 * Windows WebAuthn API (webauthn.dll, Windows 10 1903 以降) を使う。
 * 古い Windows でも起動できるよう、DLL は動的に読み込む。
 *
 * 署名データの形式は OpenSSH の PROTOCOL.u2f を参照。
 *   rpId       = 鍵の application (通常 "ssh:")
 *   clientData = 署名対象データ (WebAuthn API が SHA-256 したものを署名する)
 *   SSH の署名 = string "sk-ssh-ed25519@openssh.com"
 *                string signature
 *                byte   flags
 *                uint32 counter
 */

#include "key.h"
#include "ssherr.h"
#include "sk-webauthn.h"

#include <process.h>
#include <webauthn.h>

#define SSH_SK_USER_VERIFICATION_REQD	0x04

#define SK_WEBAUTHN_TIMEOUT_MS	(60 * 1000)

// authenticatorData = rpIdHash(32) || flags(1) || signCount(4) [|| extensions]
#define AUTHDATA_FLAGS_OFFSET	32
#define AUTHDATA_COUNTER_OFFSET	33
#define AUTHDATA_MIN_LEN	37

typedef DWORD (WINAPI *PFN_WebAuthNGetApiVersionNumber)(void);
typedef HRESULT (WINAPI *PFN_WebAuthNAuthenticatorGetAssertion)(
	HWND hWnd, LPCWSTR pwszRpId, PCWEBAUTHN_CLIENT_DATA pWebAuthNClientData,
	PCWEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS pWebAuthNGetAssertionOptions,
	PWEBAUTHN_ASSERTION *ppWebAuthNAssertion);
typedef void (WINAPI *PFN_WebAuthNFreeAssertion)(PWEBAUTHN_ASSERTION pWebAuthNAssertion);
typedef PCWSTR (WINAPI *PFN_WebAuthNGetErrorName)(HRESULT hr);

static struct {
	BOOL tried;
	HMODULE dll;
	PFN_WebAuthNGetApiVersionNumber GetApiVersionNumber;
	PFN_WebAuthNAuthenticatorGetAssertion AuthenticatorGetAssertion;
	PFN_WebAuthNFreeAssertion FreeAssertion;
	PFN_WebAuthNGetErrorName GetErrorName;
} webauthn;

static BOOL load_webauthn(void)
{
	if (webauthn.tried) {
		return webauthn.AuthenticatorGetAssertion != NULL && webauthn.FreeAssertion != NULL;
	}
	webauthn.tried = TRUE;

	webauthn.dll = LoadLibraryExW(L"webauthn.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
	if (webauthn.dll == NULL) {
		logprintf(LOG_LEVEL_ERROR, "%s: webauthn.dll is not available (error %lu)",
		          __FUNCTION__, GetLastError());
		return FALSE;
	}
	webauthn.GetApiVersionNumber = (PFN_WebAuthNGetApiVersionNumber)
		GetProcAddress(webauthn.dll, "WebAuthNGetApiVersionNumber");  // API version 2 以降
	webauthn.AuthenticatorGetAssertion = (PFN_WebAuthNAuthenticatorGetAssertion)
		GetProcAddress(webauthn.dll, "WebAuthNAuthenticatorGetAssertion");
	webauthn.FreeAssertion = (PFN_WebAuthNFreeAssertion)
		GetProcAddress(webauthn.dll, "WebAuthNFreeAssertion");
	webauthn.GetErrorName = (PFN_WebAuthNGetErrorName)
		GetProcAddress(webauthn.dll, "WebAuthNGetErrorName");

	if (webauthn.AuthenticatorGetAssertion == NULL || webauthn.FreeAssertion == NULL) {
		logprintf(LOG_LEVEL_ERROR, "%s: webauthn.dll does not export the required functions",
		          __FUNCTION__);
		return FALSE;
	}
	return TRUE;
}

// OS が対応している WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS の版 (webauthn.h の表を参照)
static DWORD assertion_options_version(DWORD api_version)
{
	if (api_version >= WEBAUTHN_API_VERSION_9)
		return WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_9;
	if (api_version >= WEBAUTHN_API_VERSION_8)
		return WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_8;
	if (api_version >= WEBAUTHN_API_VERSION_7)
		return WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_7;
	if (api_version >= WEBAUTHN_API_VERSION_4)
		return WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6;
	if (api_version >= WEBAUTHN_API_VERSION_3)
		return WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_5;
	if (api_version >= WEBAUTHN_API_VERSION_2)
		return WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_4;
	return WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_1;
}

typedef struct {
	HWND parent;	// Tera Term のウィンドウ (位置合わせ用)
	HWND hwnd;	// WebAuthn のダイアログの親にするウィンドウ
	LPCWSTR rp_id;
	PCWEBAUTHN_CLIENT_DATA client_data;
	PCWEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS opt;
	PWEBAUTHN_ASSERTION assertion;
	HRESULT hr;
} get_assertion_req_t;

#define SK_OWNER_WINDOW_CLASS	L"TTSSHSecurityKeyOwner"

static unsigned __stdcall get_assertion_thread(void *arg)
{
	get_assertion_req_t *req = (get_assertion_req_t *)arg;

	req->hr = webauthn.AuthenticatorGetAssertion(req->hwnd, req->rp_id, req->client_data,
	                                             req->opt, &req->assertion);
	return 0;
}

// WebAuthn のダイアログの親にする、見えない小さなウィンドウを Tera Term の中央に作る
static HWND create_owner_window(HWND parent)
{
	static ATOM atom = 0;
	HINSTANCE hinst = GetModuleHandleW(NULL);
	RECT rect;
	int x = 0, y = 0;
	HWND hwnd;

	if (atom == 0) {
		WNDCLASSW wc;
		ZeroMemory(&wc, sizeof(wc));
		wc.lpfnWndProc = DefWindowProcW;
		wc.hInstance = hinst;
		wc.lpszClassName = SK_OWNER_WINDOW_CLASS;
		atom = RegisterClassW(&wc);
		if (atom == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
			return NULL;
		}
	}
	if (parent != NULL && GetWindowRect(parent, &rect)) {
		x = (rect.left + rect.right) / 2;
		y = (rect.top + rect.bottom) / 2;
	}
	hwnd = CreateWindowExW(WS_EX_TOOLWINDOW | WS_EX_LAYERED, SK_OWNER_WINDOW_CLASS, L"",
	                       WS_POPUP, x, y, 1, 1, NULL, NULL, hinst, NULL);
	if (hwnd == NULL) {
		return NULL;
	}
	SetLayeredWindowAttributes(hwnd, 0, 0, LWA_ALPHA);  // 完全に透明
	ShowWindow(hwnd, SW_SHOW);
	SetForegroundWindow(hwnd);
	return hwnd;
}

/*
 * ダイアログの親ウィンドウを持つスレッド。
 * 親ウィンドウのメッセージをすべて処理しながら、
 * WebAuthNAuthenticatorGetAssertion() を呼ぶスレッドの完了を待つ。
 */
static unsigned __stdcall owner_thread(void *arg)
{
	get_assertion_req_t *req = (get_assertion_req_t *)arg;
	HWND owner;
	HANDLE thread;
	MSG msg;

	owner = create_owner_window(req->parent);
	req->hwnd = owner != NULL ? owner : req->parent;

	thread = (HANDLE)_beginthreadex(NULL, 0, get_assertion_thread, req, 0, NULL);
	if (thread == NULL) {
		get_assertion_thread(req);
	}
	else {
		for (;;) {
			DWORD ret = MsgWaitForMultipleObjects(1, &thread, FALSE, INFINITE, QS_ALLINPUT);
			if (ret != WAIT_OBJECT_0 + 1) {
				break;
			}
			while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
				TranslateMessage(&msg);
				DispatchMessageW(&msg);
			}
		}
		WaitForSingleObject(thread, INFINITE);
		CloseHandle(thread);
	}

	if (owner != NULL) {
		DestroyWindow(owner);
	}
	return 0;
}

/*
 * WebAuthNAuthenticatorGetAssertion() は完了まで戻らない。
 * Tera Term のウィンドウのスレッドで呼ぶと、そのスレッドがメッセージを処理できず、
 * 別プロセスが表示する「セキュリティキーをタッチ」のダイアログが
 * Tera Term のウィンドウの後ろに隠れてしまう。
 * 一方で Tera Term のウィンドウのメッセージをすべて処理すると、
 * ソケット通知などで SSH の処理が再入してしまう。
 * そこでダイアログの親には専用のウィンドウを別スレッドで用意し、
 * Tera Term のスレッドは他スレッド/プロセスから SendMessage された
 * メッセージだけを配送しながら待つ (キューのメッセージは取り出さない)。
 */
static HRESULT get_assertion(get_assertion_req_t *req)
{
	HANDLE thread;
	MSG msg;

	thread = (HANDLE)_beginthreadex(NULL, 0, owner_thread, req, 0, NULL);
	if (thread == NULL) {
		req->hwnd = req->parent;
		get_assertion_thread(req);
		return req->hr;
	}

	for (;;) {
		DWORD ret = MsgWaitForMultipleObjects(1, &thread, FALSE, 100, QS_SENDMESSAGE);
		if (ret == WAIT_OBJECT_0 || ret == WAIT_FAILED) {
			break;
		}
		// 送信されたメッセージだけを配送する(キューのメッセージは取り出さない)。
		// 定期的に呼ぶことで「応答なし」扱いにもならない。
		PeekMessageW(&msg, NULL, 0, 0, PM_NOREMOVE | PM_QS_SENDMESSAGE);
	}
	WaitForSingleObject(thread, INFINITE);
	CloseHandle(thread);

	if (req->parent != NULL) {
		SetForegroundWindow(req->parent);
	}
	return req->hr;
}

static wchar_t *utf8_to_wide(const char *s)
{
	int len = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
	wchar_t *w;

	if (len <= 0) {
		return NULL;
	}
	w = malloc(len * sizeof(wchar_t));
	if (w == NULL) {
		return NULL;
	}
	MultiByteToWideChar(CP_UTF8, 0, s, -1, w, len);
	return w;
}

int sk_webauthn_sign(Key *key, HWND hwnd, const char *data, int datalen, char **sigp, int *lenp)
{
	WEBAUTHN_CLIENT_DATA client_data;
	WEBAUTHN_CREDENTIAL cred;
	WEBAUTHN_CREDENTIAL_EX cred_ex;
	PWEBAUTHN_CREDENTIAL_EX cred_ex_list[1];
	WEBAUTHN_CREDENTIAL_LIST allow_list;
	LPCWSTR hints[1] = { WEBAUTHN_CREDENTIAL_HINT_SECURITY_KEY };
	WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS opt;
	get_assertion_req_t req;
	PWEBAUTHN_ASSERTION assertion = NULL;
	wchar_t *rp_id = NULL;
	buffer_t *b = NULL;
	DWORD api_version;
	HRESULT hr;
	const u_char *authdata;
	u_char flags;
	u_int counter;
	int len, r = SSH_ERR_INTERNAL_ERROR;

	if (key == NULL || key->type != KEY_ED25519_SK ||
	    key->sk_application == NULL || key->sk_key_handle == NULL) {
		return SSH_ERR_INVALID_ARGUMENT;
	}
	if (!load_webauthn()) {
		return SSH_ERR_FEATURE_UNSUPPORTED;
	}
	api_version = webauthn.GetApiVersionNumber != NULL
		? webauthn.GetApiVersionNumber() : WEBAUTHN_API_VERSION_1;

	rp_id = utf8_to_wide(key->sk_application);
	if (rp_id == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	ZeroMemory(&client_data, sizeof(client_data));
	client_data.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
	client_data.cbClientDataJSON = (DWORD)datalen;
	client_data.pbClientDataJSON = (PBYTE)data;
	client_data.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;

	ZeroMemory(&cred, sizeof(cred));
	cred.dwVersion = WEBAUTHN_CREDENTIAL_CURRENT_VERSION;
	cred.cbId = (DWORD)key->sk_key_handle_len;
	cred.pbId = key->sk_key_handle;
	cred.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;

	// transports とヒントでセキュリティキーに絞ると、
	// 「iPhone/Android かセキュリティキーか」の選択画面を省略できる
	ZeroMemory(&cred_ex, sizeof(cred_ex));
	cred_ex.dwVersion = WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION;
	cred_ex.cbId = cred.cbId;
	cred_ex.pbId = cred.pbId;
	cred_ex.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
	cred_ex.dwTransports = WEBAUTHN_CTAP_TRANSPORT_USB | WEBAUTHN_CTAP_TRANSPORT_NFC;
	cred_ex_list[0] = &cred_ex;
	allow_list.cCredentials = 1;
	allow_list.ppCredentials = cred_ex_list;

	ZeroMemory(&opt, sizeof(opt));
	opt.dwVersion = assertion_options_version(api_version);
	opt.dwTimeoutMilliseconds = SK_WEBAUTHN_TIMEOUT_MS;
	opt.CredentialList.cCredentials = 1;
	opt.CredentialList.pCredentials = &cred;
	opt.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
	opt.dwUserVerificationRequirement = (key->sk_flags & SSH_SK_USER_VERIFICATION_REQD)
		? WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED
		: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED;
	if (opt.dwVersion >= WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_4) {
		opt.pAllowCredentialList = &allow_list;  // CredentialList より優先される
	}
	if (opt.dwVersion >= WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_8) {
		opt.cCredentialHints = 1;
		opt.ppwszCredentialHints = hints;
	}

	if (hwnd == NULL) {
		hwnd = GetForegroundWindow();
	}

	logprintf(LOG_LEVEL_VERBOSE, "%s: requesting assertion (api version %lu, options version %lu, application %s)",
	          __FUNCTION__, api_version, opt.dwVersion, key->sk_application);
	logprintf(LOG_LEVEL_VERBOSE, "%s: parent window %p, foreground window %p",
	          __FUNCTION__, (void *)hwnd, (void *)GetForegroundWindow());

	// 「セキュリティキーをタッチ」のダイアログは別プロセスが表示するので、
	// 前面に出られるよう許可しておく。
	AllowSetForegroundWindow(ASFW_ANY);

	ZeroMemory(&req, sizeof(req));
	req.parent = hwnd;
	req.rp_id = rp_id;
	req.client_data = &client_data;
	req.opt = &opt;
	hr = get_assertion(&req);
	assertion = req.assertion;
	if (FAILED(hr) || assertion == NULL) {
		logprintf(LOG_LEVEL_ERROR, "%s: WebAuthNAuthenticatorGetAssertion failed: 0x%08lx (%ls)",
		          __FUNCTION__, (unsigned long)hr,
		          webauthn.GetErrorName != NULL ? webauthn.GetErrorName(hr) : L"");
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	if (assertion->cbAuthenticatorData < AUTHDATA_MIN_LEN ||
	    assertion->cbSignature != crypto_sign_ed25519_BYTES) {
		logprintf(LOG_LEVEL_ERROR, "%s: unexpected assertion (authenticator data %lu bytes, signature %lu bytes)",
		          __FUNCTION__, assertion->cbAuthenticatorData, assertion->cbSignature);
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	authdata = assertion->pbAuthenticatorData;
	flags = authdata[AUTHDATA_FLAGS_OFFSET];
	counter = ((u_int)authdata[AUTHDATA_COUNTER_OFFSET] << 24) |
	          ((u_int)authdata[AUTHDATA_COUNTER_OFFSET + 1] << 16) |
	          ((u_int)authdata[AUTHDATA_COUNTER_OFFSET + 2] << 8) |
	          (u_int)authdata[AUTHDATA_COUNTER_OFFSET + 3];

	b = buffer_init();
	if (b == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (buffer_put_cstring(b, get_ssh2_hostkey_type_name(KEY_ED25519_SK)) != 0 ||
	    buffer_put_string(b, assertion->pbSignature, assertion->cbSignature) != 0 ||
	    buffer_put_char(b, flags) != 0 ||
	    buffer_put_int(b, counter) != 0) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	len = buffer_len(b);
	*sigp = malloc(len);
	if (*sigp == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	memcpy(*sigp, buffer_ptr(b), len);
	*lenp = len;

	logprintf(LOG_LEVEL_VERBOSE, "%s: signed by security key (flags 0x%02x, counter %u)",
	          __FUNCTION__, flags, counter);
	r = 0;

out:
	if (assertion != NULL) {
		webauthn.FreeAssertion(assertion);
	}
	buffer_free(b);
	free(rp_id);
	return r;
}
