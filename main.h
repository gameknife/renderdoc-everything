#include <Windows.h>
#include <Psapi.h>
#include <d3d11.h>
#include <iostream>
#include "renderdoc_app.h"

class dllentry {

public:
	dllentry()
	{
		AllocConsole();
		FILE* f;
		freopen_s(&f, "CONOUT$", "w", stdout);

		// if you want to attach debugger, give some time here
		//std::cout << "wait 5 second for debugger attach..." << std::endl;
		//Sleep(20000);

		RENDERDOC_API_1_1_2* rdoc_api = NULL;

		const auto mod = LoadLibrary("renderdoc.dll");
		if (mod)
		{
			pRENDERDOC_GetAPI RENDERDOC_GetAPI = (pRENDERDOC_GetAPI)GetProcAddress(mod, "RENDERDOC_GetAPI");
			if (RENDERDOC_GetAPI(eRENDERDOC_API_Version_1_1_2, (void**)&rdoc_api))
			{
				int major = 0, minor = 0, patch = 0;
				rdoc_api->GetAPIVersion(&major, &minor, &patch);

				SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_INTENSITY);
				std::cout << "injection works! RenderDoc API version: " << major << "." << minor << "." << patch << std::endl;
				SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
				std::cout << "\n\nconsole will be free after 1 seconds...\n";

				// for streamline games: rename sl.common.dll
				BOOL rename_result = MoveFileA("sl.common.dll", "sl.common.dll_");

				// endup
				Sleep(1000);
				FreeConsole();
				return;
			}
		}

		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_INTENSITY);
		std::cout << "injection failed! make sure placed the right renderdoc.dll." << std::endl;
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

		system("pause");
		ExitProcess(0);
	}
};


