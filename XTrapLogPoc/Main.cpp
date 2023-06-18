#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <conio.h>
#include <iostream>
#include <fstream>
#include <string>

#include "XTrapUniper.h"

struct XTrapLogDetectionInfo
{
	DWORD dwLogVersion;
	DWORD dwCodeField1;
	DWORD dwCodeField2;
	DWORD dwCodeField3;
	DWORD dwCodeField4;
	DWORD dwCodeField5;
	char szDetectProcessName[520];

	//น่าจะมีการแยกกันตรงนี้
	DWORD dwUnknow1;
	DWORD dwUnknow2;
	DWORD dwUnknow3;
	DWORD dwUnknow4;
	char szUnknow5[268];
	DWORD dwUnknow6;
	DWORD dwUnknow7;

	DWORD dwCodeField1p2;
	DWORD dwCodeField2p2;
	DWORD dwCodeField3p2;
	DWORD dwCodeField4p2;
	DWORD dwCodeField5p2;

	DWORD dwUnknow8;
	DWORD dwUnknow9;
	char szUnknow10[24];
	char szDetectInfo[216];
};

int GetDecryptKeyFromEntropy(DWORD *input, unsigned int inputSize, char *output, unsigned int outputSize)
{
	int result;
	int v5;
	DWORD *v6;
	int v7;
	char tmp_output[0x100];

	memset(tmp_output, 0, 0x100);

	result = outputSize;

	if (outputSize <= inputSize >> 2)
	{
		v5 = 0;
		if (outputSize)
		{
			v6 = input;
			
			do
			{
				v7 = (*v6 ^ 0xB97D34A2) % (inputSize + 1);
				if (v7 >= inputSize)
				{
					v7 = (*v6 ^ 0xB97D34A2) % (inputSize - 1);
				}

				tmp_output[v5] = *((BYTE *)input + v7);

				++v5;
				++v6;
			} while (v5 < outputSize);
		}
	}

	memcpy(output, tmp_output, result);
	return result;
}

__declspec(noinline) void parse_log(char *szFilename, int startOffset)
{
	char szEntropyKey[0x41] = "\x0";
	char szEncryptionKey[17] = "\x0";
	char szDetectionInfo[1200];
	BOOL bLoopBreak = FALSE;

	XTrapLogDetectionInfo xDetectInfo;
	ZeroMemory(&xDetectInfo, sizeof(XTrapLogDetectionInfo));

	FILE *f1 = fopen(szFilename, "rb");

	fseek(f1, startOffset + 20, SEEK_SET); //skip header 20 bytes
	fread(szEntropyKey, 1, 0x40, f1);

	GetDecryptKeyFromEntropy((DWORD *)szEntropyKey, 0x40, szEncryptionKey, 0x10);

	fread(szDetectionInfo, 1, 1104, f1);
	UniperDecFunc_Buf((unsigned char *)szDetectionInfo, 1104, (unsigned char *)szEncryptionKey, 16);

	memcpy(&xDetectInfo, szDetectionInfo, 1104);

	printf("Code Field: %02X-%04X-%04X%04X-%03X\n", xDetectInfo.dwCodeField1, xDetectInfo.dwCodeField2, xDetectInfo.dwCodeField3, xDetectInfo.dwCodeField4, xDetectInfo.dwCodeField5);
	printf("Detection Process: %s\n", xDetectInfo.szDetectProcessName);
	printf("Additional Detection: %s\n", xDetectInfo.szDetectInfo);
	printf("-- PROCESS LIST --\n");

	while (bLoopBreak == FALSE)
	{
		char szProcessInfo[297] = "\x0";
		char szTestBuffer[16] = "\x0";

		PROCESSENTRY32 xProcInfo;
		ZeroMemory(&xProcInfo, sizeof(PROCESSENTRY32));

		int readResult = fread(szProcessInfo, 1, 296, f1);
		if (readResult != 0)
		{
			if (memcmp(szProcessInfo, "XTRAP_LOG_DATA_V1.0", 19) == 0)
			{
				break;
			}

			UniperDecFunc_Buf((unsigned char *)szProcessInfo, 296, (unsigned char *)szEncryptionKey, 16);
			memcpy(&xProcInfo, szProcessInfo, 296);
			printf("[PID: %d][Parent PID: %d][Thread Count: %d] %s\n", xProcInfo.th32ProcessID, xProcInfo.th32ParentProcessID, xProcInfo.cntThreads, xProcInfo.szExeFile);
		}
		else
		{
			break;
		}
	}

	fclose(f1);
}

int get_log_count(char *szFilename)
{
	int iLogCount = 0;

	std::ifstream file(szFilename, std::ios::binary);
	if (file)
	{
		file.seekg(0, std::ios::end);
        size_t file_size = file.tellg();
        file.seekg(0, std::ios::beg);
        std::string file_content;
        file_content.reserve(file_size);

        char *buffer = (char *)malloc(file_size);

        std::streamsize chars_read;

		while (file.read(buffer, file_size), chars_read = file.gcount()) file_content.append(buffer, chars_read);

        if (file.eof())
        {
			file.close();

			for (std::string::size_type offset = 0, found_at; file_size > offset && (found_at = file_content.find("XTRAP_LOG_DATA_V1.0", offset)) != std::string::npos; offset = found_at + 19)
			{
				//std::cout << found_at << std::endl;
				printf("\nLOG NUMBER: %d\n\n", iLogCount);
				parse_log(szFilename, found_at);

				iLogCount++;
			}
        }

		free(buffer);

		return iLogCount;
	}
	else
	{
		printf("Cannot open file!\n");
		return 0;
	}
}

int main(int argc, char *argv[])
{
	printf("XTrap Log file parser v1.0\n");

	if (argc != 2)
	{
		printf("Usage: XTrapLogPoc.exe LogFile.log\n");
		getch();
		return 0;
	}

	get_log_count(argv[1]);
	getch();

	return 0;
}