// Copyright (C) 2016 Games
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "lib/sdk/amx/amx.h"
#include "lib/sdk/plugincommon.h"

#if defined(_WIN32)
	#include <iostream>
#else
#include <string.h>
#endif

#include "main.h"
#include "base32.h"
#include "hmac.h"

#define BITS_PER_BASE32_CHAR      5           // Base32 expands space by 8/5
#define VERIFICATION_CODE_MODULUS (1000*1000) // Six digits
#define SHA1_DIGEST_LENGTH 20
#define TIME_INTERVAL 30

typedef void(*logprintf_t)(char* format, ...);

logprintf_t logprintf;
extern void *pAMXFunctions;


int compute_code(const char *key, unsigned long tm)
{
	int secretLen = (strlen(key) + 7) / 8 * BITS_PER_BASE32_CHAR;

	if (secretLen <= 0 || secretLen > 100) return -1;

	uint8_t secret[100];
	if ((secretLen = base32_decode((const uint8_t *)key, secret, secretLen)) < 1) {
		return -1;
	}

	uint8_t val[8];
	for (int i = 8; i--; tm >>= 8) {
		val[i] = tm;
	}
	uint8_t hash[SHA1_DIGEST_LENGTH];
	hmac_sha1(secret, secretLen, val, 8, hash, SHA1_DIGEST_LENGTH);
	memset(val, 0, sizeof(val));
	int offset = hash[SHA1_DIGEST_LENGTH - 1] & 0xF;
	unsigned int truncatedHash = 0;

	for (int i = 0; i < 4; ++i) 
	{
		truncatedHash <<= 8;
		truncatedHash |= hash[offset + i];
	}

	memset(hash, 0, sizeof(hash));
	truncatedHash &= 0x7FFFFFFF;
	truncatedHash %= VERIFICATION_CODE_MODULUS;

	return truncatedHash;
}

cell AMX_NATIVE_CALL GoogleAuthenticatorCode(AMX* amx, cell* params)
{
	if (params[0] != 8)
	{
		logprintf("GoogleAuthenticatorCode: Incorrect number of arguments (%d). Expecting 2 parameters.", params[0] / sizeof(cell));
		return -1;
	}

	char *string;
	amx_StrParam(amx, params[1], string);

	return compute_code(string, static_cast<int>(params[2]) / TIME_INTERVAL);
}


PLUGIN_EXPORT unsigned int PLUGIN_CALL Supports()
{
	return SUPPORTS_VERSION | SUPPORTS_AMX_NATIVES;
}

PLUGIN_EXPORT bool PLUGIN_CALL Load(void **ppData)
{
	pAMXFunctions = ppData[PLUGIN_DATA_AMX_EXPORTS];
	logprintf = (logprintf_t)ppData[PLUGIN_DATA_LOGPRINTF];

	logprintf("TOTP plugin v%s by Games loaded.", TOTP_PLUGIN_VER);
	return true;
}

PLUGIN_EXPORT void PLUGIN_CALL Unload()
{
	logprintf("TOTP plugin v%s by Games unloaded.", TOTP_PLUGIN_VER);
}

AMX_NATIVE_INFO PluginNatives[] =
{
	{ "GoogleAuthenticatorCode", GoogleAuthenticatorCode },
	{ 0, 0 }
};

PLUGIN_EXPORT int PLUGIN_CALL AmxLoad(AMX *amx)
{
	return amx_Register(amx, PluginNatives, -1);
}


PLUGIN_EXPORT int PLUGIN_CALL AmxUnload(AMX *amx)
{
	return AMX_ERR_NONE;
}