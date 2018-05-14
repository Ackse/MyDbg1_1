#include "stdafx.h"
#include "Operate.h"
#define BEA_ENGINE_STATIC
#define BEA_USE_STDCALL
#include "BeaEngine_4.1/headers/BeaEngine.h"
#include <Strsafe.h>
#include <afxdlgs.h>
#include <tlhelp32.h>
#include "MyType.h"
#pragma comment(lib,"BeaEngine_4.1\\Win32\\Lib\\BeaEngine.lib")
#pragma comment(linker, "/NODEFAULTLIB:\"crt.lib\"")

// using std::list;

COperate::COperate ()
{
	// 	 HardBp[4] = { 0 };				//4个硬件断点信息
	HardBp[0].isActive = FALSE;
	HardBp[1].isActive = FALSE;
	HardBp[2].isActive = FALSE;
	HardBp[3].isActive = FALSE;

}


COperate::~COperate ()
{
}

// BOOL COperate::isSystemBreak = TRUE;

//注意静态成员变量的用法
//主函数
void COperate::DebugMain ()
{
	if( !AfxWinInit ( ::GetModuleHandle ( NULL ), NULL, ::GetCommandLine (), 0 ) )
	{
		printf ( "main-Error" );
		return;
	}

	 	// 	CStringA FilePathName;
	 	// 
	 	// 	CFileDialog dlg(TRUE);
	 	// 	dlg.m_ofn.lpstrTitle = L"PE";
	 	// 	dlg.m_ofn.lpstrFilter = L"PEFile(*.exe)\0*.exe\0(.dll)\0*.dll\0AllFile(*.*)\0*.*\0\0";
	 
	 	CString szPath;
	 	//弹框获取调试进程目标文件地址
	 // 	CFileDialog infdlg(TRUE, NULL, NULL, NULL, "*.exe|*.exe|All Files|*.*||");
	 	CFileDialog infdlg ( TRUE );
	 	infdlg.m_ofn.lpstrFilter = L"程序\0*.exe\0";
	 
	 	if( infdlg.DoModal () == IDOK )
	 	{
	 		szPath = infdlg.GetPathName ();
	 	}
	 	else
	 	{
	 		return;
	 	}

// 	szPath = L"D:/MyBackup/desktop/123A.exe";
// 	WCHAR szPath[] = L"D:/MyBackup/desktop/export-dllTest.dll";	
	STARTUPINFO startUpInfo = { sizeof ( STARTUPINFO ) };
	BOOL bStatus = CreateProcess ( szPath,
								   NULL,
								   NULL,
								   NULL,
								   FALSE,
								   DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,	//调试新建进程 | 拥有新控制台,不继承其父级控制台（默认）
								   NULL,
								   NULL,
								   &startUpInfo,
								   &m_pi );

	if( !bStatus )
	{
		printf ( "创建调试进程失败!\n" );
		return;
	}
	//1.2	初始化调试事件结构体
	DEBUG_EVENT DbgEvent;
	//  	DEBUG_EVENT DbgEvent;
	// 	LPDEBUG_EVENT lpDebugEvent = &DbgEvent;
	DWORD dwState = DBG_EXCEPTION_NOT_HANDLED;
	//2.等待目标Exe产生调试事件
	while( TRUE )
	{
		WaitForDebugEvent ( &DbgEvent, INFINITE );
		m_pDbgEvt = &DbgEvent;
		//2.1 根据调试事件类型,分别处理
		dwState = DispatchDbgEvent ( DbgEvent );
		ContinueDebugEvent ( DbgEvent.dwProcessId, DbgEvent.dwThreadId, dwState );
	}
	return;
}

//分发各种dbgEvent
DWORD COperate::DispatchDbgEvent ( DEBUG_EVENT &DebugEvent )
{
	//判断调试类型
	DWORD dwRet = DBG_EXCEPTION_NOT_HANDLED;
	switch( DebugEvent.dwDebugEventCode )
	{
		case CREATE_PROCESS_DEBUG_EVENT:	//进程调试
		dwRet = OnCreateProcess ( DebugEvent );
		break;
		case EXCEPTION_DEBUG_EVENT:			//异常调试
		dwRet = DispatchException ( DebugEvent );
		break;
		case CREATE_THREAD_DEBUG_EVENT:		//线程调试
		break;
		case EXIT_THREAD_DEBUG_EVENT:		//退出线程
		break;
		case EXIT_PROCESS_DEBUG_EVENT:		//退出进程
		printf ( "被调试进程退出\r\n" );
		break;
		case LOAD_DLL_DEBUG_EVENT:			//加载DLL
		dwRet = OnLoadDll ( DebugEvent );
		break;
		case UNLOAD_DLL_DEBUG_EVENT:		//卸载DLL
		dwRet = OnLoadDll ( DebugEvent );
		break;
		case OUTPUT_DEBUG_STRING_EVENT:		//输出调试字符串
		break;
		case RIP_EVENT:						//RIP调试(RIP异常事件,内部错误)
		return dwRet;	//不处理
	}
	return dwRet;
}

//创建进程
DWORD COperate::OnCreateProcess ( DEBUG_EVENT& DebugEvent )
{
	// 	DWORD dwRet = DBG_CONTINUE;
	WCHAR path[MAX_PATH] = { 0 };
	DWORD dwSize = MAX_PATH;
	m_lpBaseOfImage = DebugEvent.u.CreateProcessInfo.lpBaseOfImage;

	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////

	//输出OEP
	SetConsoleTextAttribute ( GetStdHandle ( STD_OUTPUT_HANDLE ), 0xa );
	/*				 以淡绿色输出
	SetConsoleTextAttribute是API设置控制台窗口字体颜色和背景色的函数
	GetStdHandle是一个Windows API函数。
	它用于从一个特定的标准设备（标准输入、标准输出或标准错误）中取得一个句柄（用来标识不同设备的数值）。可以嵌套使用。
	GetStdHandle（）返回标准的输入、输出或错误的设备的句柄，也就是获得输入、输出 / 错误的屏幕缓冲区的句柄。
	*/
	QueryFullProcessImageName ( DebugEvent.u.CreateProcessInfo.hProcess,
								0,
								path,
								&dwSize );

	printf ( "进程被创建:%S\n", path );

	//oep程序入口点
	printf ( "OEP: %p          IMAGEBASE: %p\r\n\r\n",
			 DebugEvent.u.CreateProcessInfo.lpStartAddress,
			 DebugEvent.u.CreateProcessInfo.lpBaseOfImage );

	m_pi.dwProcessId = DebugEvent.dwProcessId;
	m_pi.dwThreadId = DebugEvent.dwThreadId;
	// 	进程句柄，放心使用
	m_pi.hProcess = DebugEvent.u.CreateProcessInfo.hProcess;
	// 	这个线程句柄谨慎使用
	m_pi.hThread = DebugEvent.u.CreateProcessInfo.hThread;

	CmdSetInt3BP ( (DWORD)DebugEvent.u.CreateProcessInfo.lpStartAddress ,FALSE);
	// 	CloseHandle ( DebugEvent.u.CreateProcessInfo.hThread );

	return DBG_CONTINUE;
}

//异常处理
DWORD COperate::DispatchException ( DEBUG_EVENT &DebugEvent )
{
	//异常类型判断
	switch( DebugEvent.u.Exception.ExceptionRecord.ExceptionCode )
	{
		//int3异常
		case EXCEPTION_BREAKPOINT:
		{
			return OnExceptionInt3Bp ( DebugEvent );
		}
		//单步的处理
		case EXCEPTION_SINGLE_STEP:
		{
			return OnExceptionSingleStep ( DebugEvent );
		}
		//访问异常//my-内存断点?
		case EXCEPTION_ACCESS_VIOLATION:
		{
			return OnExceptionAccess ( DebugEvent );
// 			return DBG_EXCEPTION_NOT_HANDLED;
		}
	}
	return DBG_EXCEPTION_NOT_HANDLED;
}

//处理断点异常(int3等)
DWORD COperate::OnExceptionInt3Bp ( DEBUG_EVENT &DebugEvent )
{
	//第一次系统断点继续
	if( isSystemBreak )
	{
		isSystemBreak = FALSE;
		//用户输入
// 		return UserInput ( DebugEvent );
		return DBG_CONTINUE;
	}

	//检查是不是调试器断点
	list<INT3BPNODE>::iterator itInt3Bp;
	for( itInt3Bp = g_Int3BpList.begin (); itInt3Bp != g_Int3BpList.end (); itInt3Bp++ )
	{
		PINT3BPNODE pINT3BPNODE = &(*itInt3Bp);
		if( pINT3BPNODE->lpBpAddr == DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress )
		{
			//命中调试器设置的断点，防止有内存断点先修改内存属性
			DWORD	dwOldprotect;
			DWORD	dwRetCount;
			//修改内存保护属性,使其可改写
			if( !VirtualProtectEx ( m_pi.hProcess, pINT3BPNODE->lpBpAddr, 1, PAGE_READWRITE, &dwOldprotect ) )
			{
				DBGOUT ("%s\n", "OnExceptionBreakPoint函数中错误!" );
				return FALSE;
			}
			//临时还原断点为原值
			//WriteProcessMemory此函数能写入某一进程的内存区域。入口区必须可以访问，否则操作将失败。
			if( !WriteProcessMemory ( m_pi.hProcess, pINT3BPNODE->lpBpAddr, &pINT3BPNODE->OldByte, 1, &dwRetCount ) )
			{
				DBGOUT ( "%s\n", "OnExceptionBreakPoint函数中错误!" );
				VirtualProtectEx ( m_pi.hProcess, pINT3BPNODE->lpBpAddr, 1, dwOldprotect, &dwRetCount );
				return FALSE;
			}
			//还原保护属性
			if( !VirtualProtectEx ( m_pi.hProcess, pINT3BPNODE->lpBpAddr, 1, dwOldprotect, &dwRetCount ) )
			{
				DBGOUT ( "%s\n", "还原保护属性错误!" );
				return FALSE;
			}

			// 设置1个单步
			HANDLE hThread = OpenThread ( THREAD_ALL_ACCESS, NULL, m_pDbgEvt->dwThreadId );
			CONTEXT ct = {};
			ct.ContextFlags = CONTEXT_ALL;// 指定要获取哪些寄存器的信息，很重要
			GetThreadContext ( hThread, &ct );
			PEFLAGS pElg = (PEFLAGS)&ct.EFlags;
			// 	PDBG_REG6 pDr6 = (PDBG_REG6)&ct.Dr6;
// 			pElg->TF = 1;
			//恢复EIP
			ct.Eip--;			
			//因为触发异常后eip在发生异常的字节之后
			SetThreadContext ( hThread, &ct );
			if( pINT3BPNODE->isOnce == FALSE )
			{//命中的是永久断点需要恢复
				//设置断点为失效
				pINT3BPNODE->isActive = FALSE;
				//设置单步标志
				pElg->TF = 1;

// 				context.EFlags |= 0x100;
				// 				context.EFlags
								/*
								//my-按位或运算符“ | ”是双目运算符。其功能是参与运算的两数各对应的二进位相或。
								只要对应的二个二进位有一个为1时，结果位就为1。当参与运算的是负数时，参与两个数均以补码出现
								相当于  			  0x0000 0001 0000 0000
								而TF是flag的第八位
								调试器的标志寄存器中有一个陷阱标志位，名为Trap Flag，简称TF，当TF位为1时，
								CPU每执行完一条指令便会产生一个调试异常，中断到调试异常处理程序，调试器的单步执行功能大多依靠这一机制来实现的,
								因为CPU在进入异常处理例程前会自动清除TF标志，因此，当CPU中断到调试器中再观察TF标志，它的值总是0

								*/
								//设置恢复断点标志
				isResumeInt3Bp = TRUE;
			}
			//临时断点命中,临时断点使命完成清除该临时断点
			else
			{
				//当执行"g 地址"命令时,会有临时断点,才能执行到这里
				g_Int3BpList.erase ( itInt3Bp );
			}
			CloseHandle ( hThread );

			//用户单步清除
			isUserStep = FALSE;

			//用户输入
			printf ( "ON int3 Breakpoint\r\n" );
			return UserInput ( DebugEvent );
		}
	}
	//不是调试设置断点
	return DBG_EXCEPTION_NOT_HANDLED;
}

//显示寄存器值
void COperate::ShowRegInfo ( LPCONTEXT lpContext )
{
	// 	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0xD);

	printf ( "EAX=%p EBX=%p ECX=%p EDX=%p ESI=%p EDI=%p\r\n",
			 lpContext->Eax, lpContext->Ebx, lpContext->Ecx, lpContext->Edx,
			 lpContext->Esi, lpContext->Edi );
	printf ( "EIP=%p ESP=%p EBP=%p                OF DF IF SF ZF AF PF CF\r\n",
			 lpContext->Eip, lpContext->Esp, lpContext->Ebp );
	//my-堆栈信息
	printf ( "CS=%0.4X SS=%0.4X DS=%0.4X ES=%0.4X FS=%0.4X GS=%0.4X",
			 lpContext->SegCs, lpContext->SegSs, lpContext->SegDs, lpContext->SegEs,
			 lpContext->SegFs, lpContext->SegGs );
	printf ( "       %d  %d  %d  %d  %d  %d  %d  %d\r\n",
		(bool)(lpContext->EFlags & 0x0800),
			 (bool)(lpContext->EFlags & 0x0400),
			 (bool)(lpContext->EFlags & 0x0200),
			 (bool)(lpContext->EFlags & 0x0080),
			 (bool)(lpContext->EFlags & 0x0040),
			 (bool)(lpContext->EFlags & 0x0010),
			 (bool)(lpContext->EFlags & 0x0004),
			 (bool)(lpContext->EFlags & 0x0001)
	);
	return;
}

// 显示一条反汇编代码，返回代码长度，失败返回0
DWORD COperate::ShowDisasmOneCode ( LPVOID pCodeAddr )
{
	byte	szCodeBuf[20];		//代码段数据缓冲区
// 	char	szASM[128];			//反汇编字符串缓冲区
// 	char	szOpcode[64] = { 0 };	//反汇编之后单条指令机器码
	WCHAR	szOpcode[64] = { 0 };	//反汇编之后单条指令机器码
	UINT	nCodeSize;			//反汇编单条指令长度  

	DWORD	dwFirstProtect;		//内存分页保护属性//my-第一个位置
	DWORD	dwSecondProtect;	//内存分页保护属性//my-第二个位置
	DWORD	dwTmp;//my-temp排出不处理
	DWORD	dwReadCodeCount;	//实际读取的代码段数据长度
	DWORD	*pdwAddr = NULL;	//如果是间接call该指针为间接call指向“api”地址指针

	//防止有内存断点修改内存属性
	VirtualProtectEx ( m_pi.hProcess, pCodeAddr, 1, PAGE_READWRITE, &dwFirstProtect );

	/*
	VirtualProtectEx函数可以改变在特定进程中内存区域的保护属性
	函数原形：
	BOOL VirtualProtectEx(
	HANDLE m_pi.hProcess, // 要修改内存的进程句柄
	LPVOID lpAddress, // 要修改内存的起始地址
	DWORD dwSize, // 页区域大小
	DWORD flNewProtect, // 新访问方式
	PDWORD lpflOldProtect // 原访问方式 用于保存改变前的保护属性 易语言要传址
	);
	*/

	//my-为何szCodeBuf是20,可能只是大于实际实际长度的值就行
	VirtualProtectEx ( m_pi.hProcess, (LPVOID)((DWORD)pCodeAddr + sizeof ( szCodeBuf ) - 1), 1, PAGE_READWRITE, &dwSecondProtect );
	//my-读取远程进程内存数据,获取代码段实际长度
	if( !ReadProcessMemory ( m_pi.hProcess, pCodeAddr, szCodeBuf, sizeof ( szCodeBuf ), &dwReadCodeCount ) )
	{
		// 		printf ( "ShowDisasmOneCode函数内部出错!" );
		DBGOUT ( "%s\n", "读取内存失败!" );
		//my-如果出错把保护属性重新改回去再退出
		VirtualProtectEx ( m_pi.hProcess, (LPVOID)((DWORD)pCodeAddr + sizeof ( szCodeBuf ) - 1), 1, dwSecondProtect, &dwTmp );
		VirtualProtectEx ( m_pi.hProcess, pCodeAddr, 1, dwFirstProtect, &dwTmp );
		return FALSE;
	}

	//还原内存属性，先还原“第二”个分页（有可能第二和第一是同一个分页）
	VirtualProtectEx ( m_pi.hProcess, (LPVOID)((DWORD)pCodeAddr + sizeof ( szCodeBuf ) - 1), 1, dwSecondProtect, &dwTmp );
	VirtualProtectEx ( m_pi.hProcess, pCodeAddr, 1, dwFirstProtect, &dwTmp );

	//检查是否有设置的断点，如果有还原为原值
	for( int i = 0; i < dwReadCodeCount; i++ )
	{
		if( szCodeBuf[i] == 0xCC )//如果有
		{
			list<INT3BPNODE>::iterator itInt3Bp;
			//my-类中错误找不出原因,仔细看函数头部是否没有类名
			for( itInt3Bp = g_Int3BpList.begin (); itInt3Bp != g_Int3BpList.end (); itInt3Bp++ )
			{
				PINT3BPNODE pINT3BPNODE = &(*itInt3Bp);
				//从链表中找到断点对应项,恢复其代码
				if( pINT3BPNODE->lpBpAddr == (LPVOID)((DWORD)pCodeAddr + i) )
				{
					szCodeBuf[i] = pINT3BPNODE->OldByte;
				}
			}
		}
	}
	//反汇编
	DISASM objDiasm;
	objDiasm.EIP = (UIntPtr)szCodeBuf; // 起始地址
	objDiasm.VirtualAddr = (UINT64)pCodeAddr;     // 虚拟内存地址（反汇编引擎用于计算地址）
	objDiasm.Archi = 0;                     // AI-X86
	objDiasm.Options = 0x000;                 // MASM
	 // 3. 反汇编代码
	nCodeSize = Disasm ( &objDiasm );

	if( nCodeSize == -1 )
		return nCodeSize;
	// 4. 将机器码转码为字符串
	LPWSTR lpOPCode = szOpcode;
	PBYTE  lpBuffer = szCodeBuf;
	for( UINT i = 0; i < nCodeSize; i++ )
	{
		StringCbPrintf ( lpOPCode++, 50, L"%X", *lpBuffer & 0xF0 );
		StringCbPrintf ( lpOPCode++, 50, L"%X", *lpBuffer & 0x0F );
		lpBuffer++;
	}
	// 6. 保存反汇编出的指令
	WCHAR szASM[50] = { 0 };
	MultiByteToWideChar ( CP_ACP, 0, objDiasm.CompleteInstr, -1, szASM, _countof ( szASM ) );
	// 	StringCchCopy(pASM, 50, szASM);
	wprintf_s ( L"0x%08x %-16s%s\n", pCodeAddr, szOpcode, szASM );
	//szOpcode没有赋值都能识别成CC
// 	wprintf_s(L"0x%08x %-16s%s\n", (int)objDiasm.VirtualAddr, szOpcode, szASM);
	return nCodeSize;
}


/**************************************************************************************************************
用户输入表示是调试器设置的异常，并且被调试程序已经命中调试器设置的异常停了下来
UserInput返回值为DBG_CONTINUE或者FALSE
FALSE			表示命令执行过程有错误，调试无法继续工作这该函数把错误返回给调试循环、调试程序最终退出、q命令
退出调试这里也是采用返回FALSE实现
DBG_CONTINUE	对于 t p g 等使程序运行的命令（命令执行过程没有错误）该函数退出循环，返回DBG_CONTINUE
***************************************************************************************************************/
DWORD COperate::UserInput ( DEBUG_EVENT &DebugEvent )
{
	// 1.输出寄存器信息
	HANDLE hThread = OpenThread ( THREAD_ALL_ACCESS, 0, m_pDbgEvt->dwThreadId );
	CONTEXT ct;
	ct.ContextFlags = CONTEXT_ALL;
	GetThreadContext ( hThread, &ct );
	ShowRegInfo ( &ct );
	// 2.输出反汇编信息
	// 从!!!异常地址!!!开始反汇编5行信息，不要从eip开始
// 	DisasmAtAddr ( (DWORD)m_pDbgEvt->u.Exception.ExceptionRecord.ExceptionAddress, 1 );

	ShowDisasmOneCode ( m_pDbgEvt->u.Exception.ExceptionRecord.ExceptionAddress );
	printf ( "\n=================================================================\n" );

	CloseHandle ( hThread );
	BOOL		bCmdRet;
	CHAR szCommand[MAX_PATH] = {};

	while( TRUE )
	{
		/*
		for( int i = 0, j = 0; i < 4;)
		{
		// 			分割字符串
		/ *
		参数一是指存储分离后字符串的目标字符串，
		参数二是等待分离的原始字符串，
		3是提取第几段，
		参数4是指分离的标志是什么，在你这里，分离标志就是‘ ’空格
		* /
		//而且这是一个MFC中的函数要把"属性-常规-MFC的使用设置为在共享DLL中使用MFC"
		if( !AfxExtractSubString ( strSub[i], strInput, j, ' ' ) )
		{
		break;
		}
		else
		{
		if( !strSub[i].IsEmpty () )
		/ *
		在VC中，IsEmpty()可做成员函数（CString::IsEmpty），用来判断成员参数是否为空，如果为空则返回TRUE，否则返回FALSE。
		* /
		{
		i++;//my-为分离出第二个命令做准备,腾空间接其值
		}
		}
		j++;//my-分离第二个命令
		}
		*/

		gets_s ( szCommand, MAX_PATH );
		// 解析指令 前缀  地址 长度/IsOnce 类型(长度可省略)
		char seps[] = " ";
		// 	char *tempAddr=(char*)addr;
		char *token = NULL;
		char *bhAddr = NULL;
		char *bhType = NULL;
		char *bhLen = NULL;
		char *next_token = NULL;
		// token = 'u'
		token = strtok_s ( szCommand, seps, &next_token );

		bhAddr = strtok_s ( NULL, seps, &next_token );
		// 反汇编地址
		// token = address(123456)
		bhLen = strtok_s ( NULL, seps, &next_token );
		bhType = strtok_s ( NULL, seps, &next_token );
		DWORD dwAddress;
		if ( bhAddr )
		{
			dwAddress = strtol ( bhAddr, NULL, 16 );
		}
		DWORD dwOrder = dwAddress;//要删除的断点序号
		DWORD dwLen;
		if( bhLen )
		{
			dwLen = strtol ( bhLen, NULL, 16 );
		}
		DWORD dwIsAlways = dwLen;
		switch( szCommand[0] )
		{
			case 't':
			bCmdRet = CmdStepInto ();break;
			case 'p':
			bCmdRet = CmdStepOver ( DebugEvent ); break;
			case 'g':
			bCmdRet = CmdRun ( ); break;
			case 'u':
			bCmdRet = CmdShowAsmCode ( dwAddress, DebugEvent ); break;
			case 'd':
			bCmdRet = CmdShowData ( dwAddress, DebugEvent ); break;
			case 'r':
			bCmdRet = CmdShowReg (  ); break;
			case 'k':
			bCmdRet = CmdShowStack (); break;
			case 'h':
			bCmdRet = CmdShowHelp (); break;
			case 'b':
			{
				switch( szCommand[1] )
				{
					case 'p':
					{
						switch( szCommand[2] )
						{
							case 0:
							bCmdRet = CmdSetInt3BP ( dwAddress, dwIsAlways ); break;
							case 'l':
							bCmdRet = CmdShowGeneralBPList (); break;
							case 'c':
							bCmdRet = CmdDelGeneralBP ( dwOrder ); break;

							default:
							break;
						}
					}break;
					case 'i'://if前缀
					bCmdRet = CmdSetIfBp ( dwAddress, dwLen/*这里其实是EIP范围*/ );
					break;
					case 'h':
					{
						switch( szCommand[2] )
						{
							case 0:
							bCmdRet = CmdSetHardBP ( dwAddress, dwLen,bhType );
							break;
							case 'l':
							bCmdRet = CmdShowHardBPList ();
							break;
							case 'c':
							bCmdRet = CmdDelHardBP ( dwOrder );
							break;
							default:
							break;
						}
					}break;
					case 'm':
					{
						switch( szCommand[2] )
						{
							case 0:
							bCmdRet = CmdSetMemBP ( dwAddress, dwLen, bhType );
							break;
							case 'l':
							bCmdRet = CmdShowMemBPList (); 
							break;
							case 'p':
							{
								if( szCommand[3] == 'l' )
								{
									bCmdRet = CmdShowPagMemBPList ();
								}
							}break;
							case 'c':
							bCmdRet = CmdDelMemBP ( dwOrder); 
							break;

							default:
							break;
						}

					}break;
					default:
					break;
				}
			}break;
			case 'l':
			{
				if( szCommand[1] == 'm' )
				{
					bCmdRet = CmdShowMod ( DebugEvent );
				}
			}break;
			case 'i':
			{
				if( szCommand[1] == 't' )
				{
					bCmdRet = CmdShowImportTable ();
				}
			}break;
			case 'e':
			{
				if ( szCommand[1] == 't' )
				{
					bCmdRet = CmdShowExportTable ();
				}
			}break;
			case 'c':
			system ( "CLS" ); break;
			case 'q':
			return FALSE;
		}
		//执行命令
// 		bCmdRet = pFunCmd(strSub[1], strSub[2], strSub[3], lpDebugEvent);

		if( bCmdRet == MYCONTINUE )
		{
			//要显示的地址清0下次重新显示
// 			dwShowDataAddr = 0;//my-执行d命令时		g_dwShowDataAddr = dwShowAddr + 128;
// 			dwShowDisasmAddr = 0;//my-执行u命令时	g_dwShowDisasmAddr = dwShowDisasmAddr;
			return DBG_CONTINUE;			//用这个 g 命令程序脱缰自由跑,不再受调试限制
// 			return DBG_EXCEPTION_NOT_HANDLED;//用这个 g 命令会跑到断点处(如果有)触发int异常
		}
		//命令执行过程中出错终止调试并退出
		if( bCmdRet == FALSE )
		{
			return FALSE;
		}
	}
}


//显示寄存器的值 r
DWORD COperate::CmdShowReg (  )
{
// 	m_pDbgEvt->
	HANDLE hThread = OpenThread ( THREAD_ALL_ACCESS, 0, m_pDbgEvt->dwThreadId );
	CONTEXT ct;
	ct.ContextFlags = CONTEXT_ALL;
	GetThreadContext ( hThread, &ct );
	ShowRegInfo ( &ct );
	printf ( "\n=================================================================\n" );

// 	ShowRegInfo ( &context );
	return TRUE;
}

//堆栈信息
DWORD COperate::CmdShowStack ()
{
	HANDLE hThread = OpenThread ( THREAD_ALL_ACCESS, 0, m_pDbgEvt->dwThreadId );

	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_ALL;
	GetThreadContext ( hThread, &ct );
	BYTE buff[512];
	DWORD dwRead = 0;
	if( !ReadProcessMemory ( m_pi.hProcess, (LPVOID)ct.Esp, buff, 512, &dwRead ) )
	{
		DBGOUT ( "%s\n", "" );
		return FALSE;
	}
	printf ( "堆栈地址\t" );
	printf ( "保存信息\n" );

	for (int i=0;i<5;i++)
	{
		printf ( "%08X\t", ct.Esp +i*4 );
		printf ( "%08X\n", ((DWORD*)buff)[i] );
	}
	printf ( "\n=================================================================\n" );

	return TRUE;
}

/**************************************************************************************
处理单步异常
由于断点的恢复是在该异常事件中，而且各种异常的恢复设计成有可能同时出现的情况，所以该函
数设计成正常情况下只在函数末尾返回，有错误发生时函数会在中间返回。
**************************************************************************************/
DWORD COperate::OnExceptionSingleStep ( DEBUG_EVENT &DebugEvent )
{
	BOOL isDebugSetp = FALSE;
	//my-函数中间没有错误时isDebugSetp为TRUE
	//判断是否恢复普通断点
	if( isResumeInt3Bp )
	{
		list<INT3BPNODE>::iterator itInt3Bp;
		for( itInt3Bp = g_Int3BpList.begin (); itInt3Bp != g_Int3BpList.end (); itInt3Bp++ )
		{
			PINT3BPNODE pGeneralbp = &(*itInt3Bp);
			//属性为失效的永久断点才需要恢复
			//						   失效							永久
			if( pGeneralbp->isActive == FALSE && pGeneralbp->isOnce == FALSE )
			{
				DWORD	dwOldprotect;
				DWORD	dwRetCount;
				byte	int3 = 0xCC;
				if( !VirtualProtectEx ( m_pi.hProcess, pGeneralbp->lpBpAddr, 1, PAGE_READWRITE, &dwOldprotect ) )
				{
					printf ( "单步异常处理内出错" );
					return FALSE;
				}
				//还原cc断点
				if( !WriteProcessMemory ( m_pi.hProcess, pGeneralbp->lpBpAddr, &int3, 1, &dwRetCount ) )
				{
					printf ( "单步异常处理内出错" );
					VirtualProtectEx ( m_pi.hProcess, pGeneralbp->lpBpAddr, 1, dwOldprotect, &dwRetCount );
					return FALSE;
				}
				//还原保护属性
				if( !VirtualProtectEx ( m_pi.hProcess, pGeneralbp->lpBpAddr, 1, dwOldprotect, &dwRetCount ) )
				{
					printf ( "单步异常处理内出错" );
					return FALSE;
				}
				pGeneralbp->isActive = TRUE;
			}
		}

		//恢复标志失效
		isResumeInt3Bp = FALSE;
		isDebugSetp = TRUE;
	}

	//判断是否恢复内存断点
	if( isResumeMemBp )
	{
		DWORD	dwOldprotect;

		map<DWORD, DWORD>::iterator itMemPag;
		for( itMemPag = g_MemPagMap.begin (); itMemPag != g_MemPagMap.end (); itMemPag++ )
		{
			if( !VirtualProtectEx ( m_pi.hProcess, (LPVOID)itMemPag->first, 1, PAGE_NOACCESS, &dwOldprotect ) )
			{
				printf ( "处理单步异常出错!" );
				return FALSE;
			}
		}
		//恢复标志失效
		isResumeMemBp = FALSE;
		isDebugSetp = TRUE;
	}


	//////////////////////////////////////////////////////////////////////////
	//设置nDrNum硬件寄存器
	HANDLE hThread = OpenThread ( THREAD_ALL_ACCESS, NULL, m_pDbgEvt->dwThreadId );
	CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };
	ct.ContextFlags = CONTEXT_ALL;// 指定要获取哪写寄存器的信息，很重要
	GetThreadContext ( hThread, &ct );//获取线程环境块
// 	PDBG_REG7 pDR7 = (PDBG_REG7)&ct.Dr7;

	//判断是否恢复硬件断点
	if( isResumeHardBp )
	{
		for( int i = 0; i < 4; i++ )
		{
			//断点处于激活状态且需要恢复标志为真恢复硬件断点
			if( HardBp[i].isActive == TRUE && HardBp[i].isResume == TRUE )
			{
				switch( i )
				{
					case 0:

					ct.Dr7 |= 0x1;//0001
					break;
					case 1:
					ct.Dr7 |= 0x4;//0100   
					break;
					case 2:
					ct.Dr7 |= 0x10;//00010000
					break;
					case 3:
					ct.Dr7 |= 0x40;//01000000
					break;
				}

				HardBp[i].isResume = FALSE;
			}
		}

		//恢复标志失效
		isResumeHardBp = FALSE;
		isDebugSetp = TRUE;
	}

	//判断是否为硬件断点异常
	DWORD dwHardRet = ct.Dr6 & 0xF;
	/*
	my-按位与
	为何只有1,2,4,8可能是每次只到一个硬件断点处,
	只有四种情况,分别对应的lpContext->Dr6中的值也仅仅4个?
	0001		&1111
	0010
	0100
	1000
	*/
	//只有执行硬件断点才需要暂时还原在单步恢复
	DWORD dwDr7 = ct.Dr7;

	if( dwHardRet )
	{
		switch( dwHardRet )
		{
			case 1:
			if( HardBp[0].isActive )
			{
				//执行断点需要恢复，其他硬件断点不需要恢复
				if( ((dwDr7 >> 16) & 3) == 0 )//16位是0,17位是0才是写入
				{
					//暂时使硬件断点失效
					HardBp[0].isResume = TRUE;
					ct.Dr7 &= 0xFFFFFFFC;//L0,G0设成0
					//设置单步
					ct.EFlags |= 0x100;
					isResumeHardBp = TRUE;
				}

				//用户单步失效
				isUserStep = FALSE;
				//用户输入
				printf ( "ON 00 Hardware Breakpoint\r\n" );
				//该设计是为了保证没有错误发生时函数能处理各种同时出现的情况
				if( UserInput ( DebugEvent ) == FALSE )
				{
					return FALSE;
				}

				isDebugSetp = TRUE;
			}
			break;
			case 2:
			if( HardBp[1].isActive )
			{
				if( ((dwDr7 >> 20) & 3) == 0 )
				{
					//暂时使硬件断点失效
					HardBp[1].isResume = TRUE;
					ct.Dr7 &= 0xFFFFFFF3;
					//设置单步
					ct.EFlags |= 0x100;
					isResumeHardBp = TRUE;
				}

				//用户单步失效
				isUserStep = FALSE;
				//用户输入
				printf ( "ON 01 Hardware Breakpoint\r\n" );
				//该设计是为了保证没有错误发生时函数能处理各种同时出现的情况
				if( UserInput ( DebugEvent ) == FALSE )
				{
					return FALSE;
				}

				isDebugSetp = TRUE;
			}
			break;
			case 4:
			if( HardBp[2].isActive )
			{
				if( ((dwDr7 >> 24) & 3) == 0 )
				{
					//暂时使硬件断点失效
					HardBp[2].isResume = TRUE;
					ct.Dr7 &= 0xFFFFFFCF;
					//设置单步
					ct.EFlags |= 0x100;
					isResumeHardBp = TRUE;
				}

				//用户单步失效
				isUserStep = FALSE;
				//用户输入
				printf ( "ON 02 Hardware Breakpoint\r\n" );
				//该设计是为了保证没有错误发生时函数能处理各种同时出现的情况
				if( UserInput ( DebugEvent ) == FALSE )
				{
					return FALSE;
				}

				isDebugSetp = TRUE;
			}
			break;
			case 8:
			if( HardBp[3].isActive )
			{
				if( ((dwDr7 >> 28) & 3) == 0 )
				{
					//暂时使硬件断点失效
					HardBp[3].isResume = TRUE;
					ct.Dr7 &= 0xFFFFFF3F;
					//设置单步
					ct.EFlags |= 0x100;
					isResumeHardBp = TRUE;
				}

				//用户单步失效
				isUserStep = FALSE;
				//用户输入
				printf ( "ON 03 Hardware Breakpoint\r\n" );
				//该设计是为了保证没有错误发生时函数能处理各种同时出现的情况
				if( UserInput ( DebugEvent ) == FALSE )
				{
					return FALSE;
				}

				isDebugSetp = TRUE;
			}
			break;
		}
	}
	SetThreadContext ( hThread, &ct );
	CloseHandle ( hThread );

	//////////////////////////////////////////////////////////////////////////
	//判断是否为用户设置单步
	if( isUserStep )
	{
		//单步标志失效
		isUserStep = FALSE;

		//用户输入
		printf ( "ON UserStep Breakpoint\r\n" );
		//该设计是为了保证没有错误发生时函数能处理各种同时出现的情况
		if( UserInput ( DebugEvent ) == FALSE )
		{
			return FALSE;
		}
		isDebugSetp = TRUE;
	}

	//函数中间没有错误发生
	if( isDebugSetp )
	{
		//调试器的异常已经处理
		return DBG_CONTINUE;
	}
	else
	{
		//非调试器异常
		return DBG_EXCEPTION_NOT_HANDLED;
	}
}

//设置int3断点 bp 过程中有错误返回FALSE，上层的UserInput检测到错误继续往上层调试循环传递自定义的FALSE，调试程序退出
DWORD COperate::CmdSetInt3BP ( DWORD dwAddress, BOOL IsAlways )
{
	INT3BPNODE Generalbp;

	if( !dwAddress )
	{
		DBGOUT ("%s\n", "没有输入软件断点地址" );
		return MYERRCONTINUE;
	}

	//判断第二个参数不为空设置一次性断点
	if( !IsAlways )
	{
		Generalbp.isOnce = TRUE;
	}
	else
	{
		Generalbp.isOnce = FALSE;
	}
	//断点地址转数值类型
// 	wchar_t	*pRet = NULL;
// 	DWORD	dwBpAddr = wcstoul ( str1, &pRet, 16 );
	//strtoul将字符串转换成无符号长整型数,最后的16，表示自动识别str1是几进制
	LPVOID	lpBpAddr = (LPVOID)dwAddress;

	//转换失败
	//查询是否已经存在该断点,如果存在直接返回
// 	list<INT3BPNODE>::iterator itInt3Bp;
// 	for( itInt3Bp = g_Int3BpList.begin (); itInt3Bp != g_Int3BpList.end (); itInt3Bp++ )
// 	{
// 		if( (*itInt3Bp).lpBpAddr == lpBpAddr )
// 		{
// 			//相同的断点只需把临时断点改为永久断点
// 			//my-该点如果原本存在,怎么不是永久断点呢?
// 			if( Generalbp.isOnce == FALSE )
// 			{
// 				(*itInt3Bp).isOnce = FALSE;
// 			}
// 			return TRUE;
// 		}
// 	}
	//todo-my-检测设置的断点是否有效地址
	//查询该地址是否为有效内存地址

// 	MEMORY_BASIC_INFORMATION mbi = { 0 };
// 	if( sizeof ( mbi ) != VirtualQueryEx ( m_pi.hProcess, lpBpAddr, &mbi, sizeof ( mbi ) ) )
// 	{
// 		printf ( "设置断点出错" );
// 		return FALSE;
// 	}
// 	//该内存地址不能设置断点
// 	if( mbi.State != MEM_COMMIT )//MEM_COMMIT 指明已分配物理内存或者系统页文件。
// 	{
// 		printf ( "输入的断点地址无内存分页\r\n" );
// 		return MYERRCONTINUE;
// 	}

	//为防止该分页有内存断点先设置该分页的属性
	DWORD	dwOldprotect;
	DWORD	dwRetCount;
	byte	int3 = 0xCC;
	if( !VirtualProtectEx ( m_pi.hProcess, lpBpAddr, 1, PAGE_READWRITE, &dwOldprotect ) )
	{
		printf ( "修改保护属性出错\n" );
		return FALSE;
	}
	//读取地址处的值保存
	if( !ReadProcessMemory ( m_pi.hProcess, lpBpAddr, &(Generalbp.OldByte), 1, &dwRetCount ) )
	{
		printf ( "读取地址信息出错\n" );
		VirtualProtectEx ( m_pi.hProcess, lpBpAddr, 1, dwOldprotect, &dwRetCount );
		return FALSE;
	}
	//设置cc断点
	if( !WriteProcessMemory ( m_pi.hProcess, lpBpAddr, &int3, 1, &dwRetCount ) )
	{
		printf ( "写入CC断点出错\n" );
		VirtualProtectEx ( m_pi.hProcess, lpBpAddr, 1, dwOldprotect, &dwRetCount );
		return FALSE;
	}
	//还原保护属性
	if( !VirtualProtectEx ( m_pi.hProcess, lpBpAddr, 1, dwOldprotect, &dwRetCount ) )
	{
		printf ( "还原保护属性出错\n" );
		return FALSE;
	}
	//设置断点信息
	//断点信息各项值赋值后压入链表
	Generalbp.lpBpAddr = lpBpAddr;
	Generalbp.dwBpOrder = dwBpOrder++;
	Generalbp.isActive = TRUE;
	g_Int3BpList.push_back ( Generalbp );
	return TRUE;
}

//条件断点
DWORD COperate::CmdSetIfBp ( DWORD dwStartAddress, DWORD dwEndAdderss )
{
	LPVOID lpStartAddr = LPVOID ( dwStartAddress );
	LPVOID lpEndAddr = LPVOID ( dwEndAdderss );
	BOOL		bCmdRet;
	for (int i=0;i<=dwEndAdderss - dwStartAddress;i++)
	{
		bCmdRet = CmdSetInt3BP ( dwStartAddress + i, TRUE );
	}
	return bCmdRet;
}

//显示int3断点 bpl
DWORD COperate::CmdShowGeneralBPList ()
{
	printf ( "------------------------------------\r\n" );
	printf ( "ID    Breakpoint type    Address\r\n" );
	list<INT3BPNODE>::iterator itInt3Bp;
	for( itInt3Bp = g_Int3BpList.begin (); itInt3Bp != g_Int3BpList.end (); itInt3Bp++ )
	{
		PINT3BPNODE pGeneralbp = &(*itInt3Bp);
		printf ( "%03d   INT3 breakpoint    0x%p\r\n",
				 pGeneralbp->dwBpOrder, pGeneralbp->lpBpAddr );
	}
	printf ( "------------------------------------\r\n" );

	return TRUE;
}

//删除普通断点 bpc
DWORD COperate::CmdDelGeneralBP ( DWORD dwOrder )
{
	DWORD dwOldprotect;
	DWORD dwTmp;
	DWORD dwRetCount;

	list<INT3BPNODE>::iterator itInt3Bp;
	for( itInt3Bp = g_Int3BpList.begin (); itInt3Bp != g_Int3BpList.end (); itInt3Bp++ )
	{
		PINT3BPNODE pGeneralbp = &(*itInt3Bp);
		if( pGeneralbp->dwBpOrder == dwOrder )
		{
			//修改内存属性
			if( !VirtualProtectEx ( m_pi.hProcess, pGeneralbp->lpBpAddr, 1, PAGE_READWRITE, &dwOldprotect ) )
			{
				printf ( "bpc命令出错" );
				return FALSE;
			}
			//还原断点
			if( !WriteProcessMemory ( m_pi.hProcess, pGeneralbp->lpBpAddr, &(pGeneralbp->OldByte), 1, &dwRetCount ) )
			{
				printf ( "bpc命令出错" );
				VirtualProtectEx ( m_pi.hProcess, pGeneralbp->lpBpAddr, 1, dwOldprotect, &dwTmp );
				return FALSE;
			}
			//还原保护属性
			if( !VirtualProtectEx ( m_pi.hProcess, pGeneralbp->lpBpAddr, 1, dwOldprotect, &dwTmp ) )
			{
				printf ( "bpc命令出错" );
				return FALSE;
			}
			g_Int3BpList.erase ( itInt3Bp );

			return TRUE;
		}
	}
	if( itInt3Bp == g_Int3BpList.end () )
	{
		printf ( "没有找到该序号对应的断点\r\n" );
		return MYERRCONTINUE;
	}

	return FALSE;
}

//显示帮助 help or ?
DWORD COperate::CmdShowHelp ()
{

	printf ( "================================= 帮助 ===================================\r\n" );
	printf ( "序号 命令名      命令码    英文说明        参数1    参数2    参数3        \r\n"
			 "1    单步步入      t      step into       无                             \r\n"
			 "2    单步步过      p      step over       无                             \r\n"
			 "3    运行          g      run             地址或无                       \r\n"
			 "--------------------------------------------------------------------------\r\n"
			 "4    反汇编        u      assemble        地址或无                       \r\n"
			 "5    数据          d      data            地址或无                       \r\n"
			 "6    寄存器        r      register        无                             \r\n"
			 "--------------------------------------------------------------------------\r\n"
			 "7    一般断点      bp     breakpoint      地址    once(一次性)           \r\n"
			 "8    一般断点列表  bpl    bp list                                        \r\n"
			 "9   删除一般断点  bpc    clear bp        序号                           \r\n"
			 "--------------------------------------------------------------------------\r\n"
			 "10   硬件断点      bh 　  hard bp         地址     e/a/w    长度         \r\n"
			 "11   硬件断点列表  bhl    hard bp list                                   \r\n"
			 "12   删除硬件断点  bhc    clear hard bp   序号                           \r\n"
			 "--------------------------------------------------------------------------\r\n"
			 "13   内存断点      bm     memory bp       起始地址 a/w      长度         \r\n"
			 "14   内存断点列表  bml    Bp Memory List                                 \r\n"
			 "15   分页断点列表  bmpl   Bp Page List                                   \r\n"
			 "16   删除内存断点  bmc    clear memory bp 序号                           \r\n"
			 "--------------------------------------------------------------------------\r\n"
			 "17   查看模块      lm     List Module     无                             \r\n"
			 "18   查看导出表	   et    ShowExportTable  无                             \r\n"
			 "19   查看导入表	   it    ShowImportTable  无                             \r\n"
			 "--------------------------------------------------------------------------\r\n"
			 "20   退出          q      quit            无                             \r\n"
			 "21   帮助          ?      help            无                             \r\n"
			 "22   清屏          cls    CLS             无                             \r\n" );
	printf ( "===========================================================================\r\n" );
	return TRUE;
}


//单步 t 返回自定义的MYCONTINUE，上层的UserInput检测该值退出命令循环使调试程序继续运行
DWORD COperate::CmdStepInto ()
{
	// 设置单步
	HANDLE hThread = OpenThread ( THREAD_ALL_ACCESS, NULL, m_pDbgEvt->dwThreadId );
	CONTEXT ct = {};
	ct.ContextFlags = CONTEXT_ALL;// 指定要获取哪写寄存器的信息，很重要
	GetThreadContext ( hThread, &ct );
	PEFLAGS pElg = (PEFLAGS)&ct.EFlags;
	PDBG_REG6 pDr6 = (PDBG_REG6)&ct.Dr6;
	pElg->TF = 1;
	SetThreadContext ( hThread, &ct );
	CloseHandle ( hThread );
// 	context.EFlags |= 0x100;
	//my-将TF位设置为1引发单步中断
	//设置用户单步
	isUserStep = TRUE;

	return MYCONTINUE;
}

// 单步步过 p 返回自定义的MYCONTINUE
DWORD COperate::CmdStepOver ( DEBUG_EVENT &DebugEvent )
{

	//反汇编指令如果为call在call指令下一条设置临时断点，其他指令置单步
	CString szDisasm;
	CString szSub;
// 	CString strBpOnce = "once";
// 	CString szBpAddr;
	DWORD dwAddr = (DWORD)DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
	DWORD dwCodeSize = 0;
	// 	dwCodeSize =
	dwCodeSize = DisasmOneCode ( m_pi.hProcess, DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress, &szDisasm );
	if( dwCodeSize == FALSE )
	{
		return FALSE;
	}
	//分割字符串
	if( !AfxExtractSubString ( szSub, szDisasm, 0, ' ' ) )
	{
		printf ( "单步步过出错!\n" );
		return FALSE;
	}
	if( szSub == "call" )
	{
		//下一条指令设置临时断点//my-call函数尾部设置临时断点
		dwAddr += dwCodeSize;
// 		szBpAddr.Format ( L"%08X", dwAddr );
		if( CmdSetInt3BP ( dwAddr, FALSE ) != TRUE )
		{
			return FALSE;
		}
	}
	else
	{
		//如果不是当t-F7命令执行
		CmdStepInto ();
// 		context.EFlags |= 0x100;
// 		//设置用户单步
// 		isUserStep = TRUE;
	}

	return MYCONTINUE;
}


/***************************************************************
反汇编一条代码
返回该条代码长度，如果返回0表示函数执行错误
szDisasm	传出一条反汇编的结果
szDisasmAll	传出一条反汇编的详细结果包括地址、api等
****************************************************************/
DWORD COperate::DisasmOneCode ( HANDLE hProcess, LPVOID pCodeAddr, CString *szDisasm )
{
	byte	szCodeBuf[20];		//代码段数据缓冲区
	// 	char	szASM[128];			//反汇编字符串缓冲区
	// 	char	szOpcode[64] = { 0 };	//反汇编之后单条指令机器码
	WCHAR	szOpcode[64] = { 0 };	//反汇编之后单条指令机器码
	UINT	nCodeSize;			//反汇编单条指令长度  

	DWORD	dwFirstProtect;		//内存分页保护属性//my-第一个位置
	DWORD	dwSecondProtect;	//内存分页保护属性//my-第二个位置
	DWORD	dwTmp;//my-temp排出不处理
	DWORD	dwReadCodeCount;	//实际读取的代码段数据长度
	DWORD	*pdwAddr = NULL;	//如果是间接call该指针为间接call指向“api”地址指针

	//防止有内存断点修改内存属性
	VirtualProtectEx ( m_pi.hProcess, pCodeAddr, 1, PAGE_READWRITE, &dwFirstProtect );

	/*
	VirtualProtectEx函数可以改变在特定进程中内存区域的保护属性
	函数原形：
	BOOL VirtualProtectEx(
	HANDLE m_pi.hProcess, // 要修改内存的进程句柄
	LPVOID lpAddress, // 要修改内存的起始地址
	DWORD dwSize, // 页区域大小
	DWORD flNewProtect, // 新访问方式
	PDWORD lpflOldProtect // 原访问方式 用于保存改变前的保护属性 易语言要传址
	);
	*/

	//my-为何szCodeBuf是20,可能只是大于实际实际长度的值就行
	VirtualProtectEx ( m_pi.hProcess, (LPVOID)((DWORD)pCodeAddr + sizeof ( szCodeBuf ) - 1), 1, PAGE_READWRITE, &dwSecondProtect );
	//my-读取远程进程内存数据,获取代码段实际长度
	if( !ReadProcessMemory ( m_pi.hProcess, pCodeAddr, szCodeBuf, sizeof ( szCodeBuf ), &dwReadCodeCount ) )
	{
		printf ( "ShowDisasmOneCode函数内部出错!" );
		//my-如果出错把保护属性重新改回去再退出
		VirtualProtectEx ( m_pi.hProcess, (LPVOID)((DWORD)pCodeAddr + sizeof ( szCodeBuf ) - 1), 1, dwSecondProtect, &dwTmp );
		VirtualProtectEx ( m_pi.hProcess, pCodeAddr, 1, dwFirstProtect, &dwTmp );
		return FALSE;
	}

	//还原内存属性，先还原“第二”个分页（有可能第二和第一是同一个分页）
	VirtualProtectEx ( m_pi.hProcess, (LPVOID)((DWORD)pCodeAddr + sizeof ( szCodeBuf ) - 1), 1, dwSecondProtect, &dwTmp );
	VirtualProtectEx ( m_pi.hProcess, pCodeAddr, 1, dwFirstProtect, &dwTmp );

	//检查是否有设置的断点，如果有还原为原值
	for( int i = 0; i < dwReadCodeCount; i++ )
	{
		if( szCodeBuf[i] == 0xCC )//如果有
		{
			list<INT3BPNODE>::iterator itInt3Bp;
			//my-类中错误找不出原因,仔细看函数头部是否没有类名
			for( itInt3Bp = g_Int3BpList.begin (); itInt3Bp != g_Int3BpList.end (); itInt3Bp++ )
			{
				PINT3BPNODE pINT3BPNODE = &(*itInt3Bp);
				//从链表中找到断点对应项,恢复其代码
				if( pINT3BPNODE->lpBpAddr == (LPVOID)((DWORD)pCodeAddr + i) )
				{
					szCodeBuf[i] = pINT3BPNODE->OldByte;
				}
			}
		}
	}
	//反汇编
	DISASM objDiasm;
	objDiasm.EIP = (UIntPtr)szCodeBuf; // 起始地址
	objDiasm.VirtualAddr = (UINT64)pCodeAddr;     // 虚拟内存地址（反汇编引擎用于计算地址）
	objDiasm.Archi = 0;                     // AI-X86
	objDiasm.Options = 0x000;                 // MASM
	// 3. 反汇编代码
	nCodeSize = Disasm ( &objDiasm );

	if( nCodeSize == -1 )
		return nCodeSize;
	// 4. 将机器码转码为字符串
	LPWSTR lpOPCode = szOpcode;
	PBYTE  lpBuffer = szCodeBuf;
	for( UINT i = 0; i < nCodeSize; i++ )
	{
		StringCbPrintf ( lpOPCode++, 50, L"%X", *lpBuffer & 0xF0 );
		StringCbPrintf ( lpOPCode++, 50, L"%X", *lpBuffer & 0x0F );
		lpBuffer++;
	}
	// 6. 保存反汇编出的指令
	WCHAR szASM[50] = { 0 };
	MultiByteToWideChar ( CP_ACP, 0, objDiasm.CompleteInstr, -1, szASM, _countof ( szASM ) );
	// 	StringCchCopy(pASM, 50, szASM);
// 	wprintf_s(L"0x%08x %-16s%s\n", pCodeAddr, szOpcode, szASM);
	(*szDisasm) = szASM;
	//szOpcode没有赋值都能识别成CC
	// 	wprintf_s(L"0x%08x %-16s%s\n", (int)objDiasm.VirtualAddr, szOpcode, szASM);
	return nCodeSize;
}

//执行 g 返回自定义的MYCONTINUE
DWORD COperate::CmdRun (  )
{

// 	DWORD dwSetBpRet;
// 	if( str1.IsEmpty () )
		/*
		my-如果go后面没有地址,直接返回,后续没有异常触发,程序就会一直跑
		后面有地址,则会跑到地址处触发软件断点
		*/
// 	{
		return MYCONTINUE;
// 	}
// 	//在输入地址处设置临时断点
// // 	CString strBpOnce = "once";
// // 	dwSetBpRet = CmdSetInt3BP ( str1, FALSE );
// 	if( dwSetBpRet == TRUE )
// 	{
// 		return MYCONTINUE;
// 	}
// 	else
// 	{
// 		return dwSetBpRet;
// 	}
}


//反汇编代码 u//my-一次显示八条命令
DWORD COperate::CmdShowAsmCode ( DWORD dwAddr, DEBUG_EVENT &DebugEvent )
{
// 	DWORD	m_dwShowDisasmAddr;
	DWORD	m_dwCodeSize = 0;

// 	if( str1.IsEmpty () )
// 	{
// 		if( dwShowDisasmAddr )
// 		{
// 			//my-当执行过"u-空"后在执行"u-空"会进入
// 
// 			m_dwShowDisasmAddr = dwShowDisasmAddr;
// 		}
// 		else
// 		{
// 			m_dwShowDisasmAddr = (DWORD)DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
// 		}
// 	}
// 	else
// 	{
		//转换参数
// 		wchar_t	*pRet = NULL;
// 		m_dwShowDisasmAddr = wcstoul ( str1, &pRet, 16 );
// 		//转换失败
// 		if( *pRet != NULL )
// 		{
// 			printf ( "代码地址输入错误\r\n" );
// 			return MYERRCONTINUE;
// 		}
// 	}
	//调用反汇编显示反汇编代码
	for( int i = 0; i < 8; i++ )
	{
		m_dwCodeSize = ShowDisasmOneCode ( (LPVOID)dwAddr );
		if( m_dwCodeSize == 0 )
		{
			return FALSE;
		}
		dwAddr += m_dwCodeSize;
	}
	printf ( "\n=================================================================\n" );

// 	dwShowDisasmAddr = m_dwShowDisasmAddr;
	return TRUE;
}


//显示内存数据 d
DWORD COperate::CmdShowData ( DWORD dwAddr, DEBUG_EVENT &DebugEvent )
{
	byte	dbBuf[128] = { 0 };
	byte	dbFlg[128] = { 0 };	//0表示读取成功，1表示读取失败
	DWORD	m_dwFirstProtect;
	DWORD	m_dwSecondProtect;
	DWORD	m_dwTmp;
	DWORD	m_dwShowAddr;

// 	if( str1.IsEmpty () )
// 	{//若是空的,没给地址
// 		if( dwShowDataAddr )
// 		{
// 			//my-当执行过"d-空"后在执行"d-空"会进入
// 			m_dwShowAddr = dwShowDataAddr;
// 		}
// 		else
// 		{
// 			m_dwShowAddr = (DWORD)DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
// 		}
// 	}
// 	else
// 	{
// 		//转换参数
// 		wchar_t	*pRet = NULL;
// 		m_dwShowAddr = wcstoul ( str1, &pRet, 16 );
// 		//转换失败
// 		if( *pRet != NULL )
// 		{
// 			printf ( "数据地址输入错误\r\n" );
// 			return MYERRCONTINUE;
// 		}
// 	}
	//修改内存属性
	VirtualProtectEx ( m_pi.hProcess, (LPVOID)dwAddr, 1, PAGE_READWRITE, &m_dwFirstProtect );
	VirtualProtectEx ( m_pi.hProcess, (LPVOID)(dwAddr + 128 - 1), 1, PAGE_READWRITE, &m_dwSecondProtect );
	//读内存
	for( int i = 0; i < 128; i++ )
	{
		if( !ReadProcessMemory ( m_pi.hProcess, (LPVOID)(dwAddr + i), dbBuf + i, 1, &m_dwTmp ) )
		{//my-如果失败,进入这里
			dbFlg[i] = 1;
		}
	}
	//my-128=16*8,128并不是都显示出来

	//显示数据
	for( int i = 0; i < 8; i++ )//8是显示8行
	{
		printf ( "%p:  ", dwAddr + 0x10 * i );//地址加16偏移-每行地址
		for( int j = 0; j < 16; j++ )//my-一行显示16列16进制数据-HEX数据
		{
			if( dbFlg[i * 0x10 + j] == 1 )
			{//my-第几行第几列
				printf ( "%s ", "??" );
			}
			else
			{
				printf ( "%0.2X ", dbBuf[i * 0x10 + j] );
			}
		}
		for( int j = 0; j < 16; j++ )//my-一行显示-UNICODE数据
		{
			if( dbFlg[i * 0x10 + j] == 1 )
			{
				printf ( "%C", '?' );
			}
			else if( dbBuf[i * 0x10 + j] >= 127 || dbBuf[i * 0x10 + j] < 32 )
			{
				printf ( "." );
			}
			else
			{
				printf ( "%C", dbBuf[i * 0x10 + j] );
			}
		}
		printf ( "\r\n" );
	}
	printf ( "\n=================================================================\n" );

	//还原内存属性处理在同一分页的情况先还原第二个分页属性
	VirtualProtectEx ( m_pi.hProcess, (LPVOID)(dwAddr + 128), 1, m_dwSecondProtect, &m_dwTmp );
	VirtualProtectEx ( m_pi.hProcess, (LPVOID)dwAddr, 1, m_dwFirstProtect, &m_dwTmp );

// 	dwShowDataAddr = m_dwShowAddr + 128;
	return TRUE;
}


/************************************************************************
设置硬件断点 bh
1 找未被使用的硬件断点寄存器（Dr0-Dr3），把断点地址放入该寄存器
2 设置Dr7对应的GX或LX位为1。（如：断点设置在Dr0上则设置Dr7的G0或L0位为1）
3 设置Dr7对应的断点类型位（R/W0到R/W3其中之一）为执行、写入或访问
4 设置Dr7对应的断点长度位（LEN0到LEN3其中之一）为1、2或4字节
删除断点
把Dr7对应的GX或LX位设置为0（可全设置为0）
************************************************************************/
DWORD COperate::CmdSetHardBP ( DWORD dwAddr, DWORD dwLen, CHAR *pType)
{
	LPVOID	lpBpAddr = (LPVOID)dwAddr;
	if( !((*pType == 'a') || (*pType == 'w') || (*pType == 'e')) )
	{
		printf ( "硬件断点属性输入错误\r\n" );
		return MYERRCONTINUE;
	}
	if( !((dwLen == 1) || (dwLen == 2) || (dwLen == 4)) )
	{
		printf ( "硬件断点长度输入错误\r\n" );
		return MYERRCONTINUE;
	}
	//要设置断点的地址内存是否有效
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	if( sizeof ( mbi ) != VirtualQueryEx ( m_pi.hProcess, lpBpAddr, &mbi, sizeof ( mbi ) ) )
	{
		printf ( "设置硬件断点错误" );
		return FALSE;
	}
	//该内存地址不能设置断点
	if( mbi.State != MEM_COMMIT )
	{
		printf ( "输入的断点地址无内存分页\r\n" );
		return MYERRCONTINUE;
	}
	//检查硬件断点属性
	BP_RWE	enuRwe;
	if( *pType == 'a' )
	{
		enuRwe = ACCESS;
	}
	else if( *pType == 'w' )
	{
		enuRwe = WRITE;
	}
	else if( *pType == 'e' )
	{
		//硬件执行断点长度自动设置为1
		dwLen = 1;
		enuRwe = EXECUTE;
	}
	//检查是否已经存在该断点
	for( int i = 0; i < 4; i++ )
	{
		if( HardBp[i].isActive )
		{
			if( (HardBp[i].lpBpAddr == lpBpAddr) && (HardBp[i].enuBpRWE == enuRwe)
				&& (dwLen <= HardBp[i].dwBpLen) )
			{
				return TRUE;
			}
		}
	}
	//是否有寄存器
	int nDrNum = -1;
	for( int i = 0; i < 4; i++ )
	{
		/*
		my-检测四个寄存器,那个isActive是FALSE,就把断点信息放在该点
		*/
		if( HardBp[i].isActive == FALSE )
		{
			nDrNum = i;
			break;
		}
	}
	if( nDrNum == -1 )
	{
		printf ( "不能设置更多硬件断点\r\n" );
		return FALSE;
	}
	//设置g_HardBp[nDrNum]
	HardBp[nDrNum].dwBpLen = dwLen;
	HardBp[nDrNum].dwBpOrder = nDrNum;
	HardBp[nDrNum].enuBpRWE = enuRwe;
	HardBp[nDrNum].isActive = TRUE;
	HardBp[nDrNum].isResume = FALSE;
	HardBp[nDrNum].lpBpAddr = lpBpAddr;

	//设置nDrNum硬件寄存器
	HANDLE hThread = OpenThread ( THREAD_ALL_ACCESS, NULL, m_pDbgEvt->dwThreadId );
	CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };
	ct.ContextFlags = CONTEXT_ALL;// 指定要获取哪写寄存器的信息，很重要
	GetThreadContext ( hThread, &ct );//获取线程环境块
	PDBG_REG7 pDR7 = (PDBG_REG7)&ct.Dr7;

	switch( nDrNum )
	{
		case 0:
		{
			ct.Dr0 = (DWORD)HardBp[nDrNum].lpBpAddr;
// 			context.Dr7 |= 1;
			pDR7->L0 = 1;
// 			context.Dr7 &= 0xFFF0FFFF;		//16，17，18，19位置0
			pDR7->RW0 = 0;
			pDR7->LEN0 = 0;
			//LEN 长度设置									//my-将存储位置存数值1=与1按位或,存0与0按位与
			switch( HardBp[nDrNum].dwBpLen )
			{
				case 1:
				break;
				case 2:
// 				context.Dr7 |= 0x00040000;	//18位置1
				pDR7->LEN0 = 1;
				break;
				case 4:
// 				context.Dr7 |= 0x000C0000;	//18,19位同时置1
				pDR7->LEN0 = 3;
				break;
			}
			//R/W 属性设置
			switch( HardBp[nDrNum].enuBpRWE )
			{
				case EXECUTE:
				break;
				case WRITE:
// 				context.Dr7 |= 0x00010000;	//16位置1
				pDR7->RW0 = 1;
				break;
				case ACCESS:
// 				context.Dr7 |= 0x00030000;	//16,17位同时置1
				pDR7->RW0 = 3;
				break;
			}
			break;
		}
		break;
		case 1:
		{
			ct.Dr1 = (DWORD)HardBp[nDrNum].lpBpAddr;
// 			context.Dr7 |= 4;
			pDR7->L1 = 1;
// 			context.Dr7 &= 0xFF0FFFFF;		//20，21，22，23位置0
			pDR7->RW1 = 0;
			pDR7->LEN1 = 0;
			//LEN 长度设置
			switch( HardBp[nDrNum].dwBpLen )
			{
				case 1:
				break;
				case 2:
// 				p.Dr7 |= 0x00400000;	//22位置1
				pDR7->LEN1 = 1;
				break;
				case 4:
// 				context.Dr7 |= 0x00C00000;	//22,23位同时置1
				pDR7->LEN1 = 3;
				break;
			}
			//R/W 属性设置
			switch( HardBp[nDrNum].enuBpRWE )
			{
				case EXECUTE:
				break;
				case WRITE:
// 				context.Dr7 |= 0x00100000;	//20位置1
				pDR7->RW1 = 1;
				break;
				case ACCESS:
				pDR7->RW1 = 3;
				break;
			}
			break;
		}
		break;
		case 2:
		{
			ct.Dr2 = (DWORD)HardBp[nDrNum].lpBpAddr;
// 			context.Dr7 |= 0x10;
			pDR7->L2 = 1;
// 			context.Dr7 &= 0xF0FFFFFF;		//24，25，26，27位置0
			pDR7->RW2 = 0;
			pDR7->LEN2 = 0;
			//LEN 长度设置
			switch( HardBp[nDrNum].dwBpLen )
			{
				case 1:
				break;
				case 2:
// 				context.Dr7 |= 0x04000000;	//26位置1
				pDR7->LEN2 = 1;
				break;
				case 4:
				pDR7->LEN2 = 3;
				break;
			}
			//R/W 属性设置
			switch( HardBp[nDrNum].enuBpRWE )
			{
				case EXECUTE:
				break;
				case WRITE:
				pDR7->RW2 = 1;
				break;
				case ACCESS:
				pDR7->RW2 = 3;
				break;
			}
			break;
		}
		break;
		case 3:
		{
			ct.Dr3 = (DWORD)HardBp[nDrNum].lpBpAddr;
// 			context.Dr7 |= 0x40;
			pDR7->L3 = 1;

// 			context.Dr7 &= 0x0FFFFFFF;		//28，29，30，31位置0
			pDR7->RW3 = 0;
			pDR7->LEN3 = 0;
			//LEN 长度设置
			switch( HardBp[nDrNum].dwBpLen )
			{
				case 1:
				break;
				case 2:
				pDR7->LEN3 = 1;
				break;
				case 4:
				pDR7->LEN3 = 3;
				break;
			}
			//R/W 属性设置
			switch( HardBp[nDrNum].enuBpRWE )
			{
				case EXECUTE:
				break;
				case WRITE:
				pDR7->RW3 = 1;
				break;
				case ACCESS:
				pDR7->RW3 = 3;
				break;
			}
			break;
		}
		break;
	}
	SetThreadContext ( hThread, &ct );
	CloseHandle ( hThread );
	return TRUE;
}


// 显示硬件断点 bhl
DWORD COperate::CmdShowHardBPList ()
{
	HANDLE hThread = OpenThread ( THREAD_ALL_ACCESS, NULL, m_pDbgEvt->dwThreadId );
	CONTEXT ct = {};
	ct.ContextFlags = CONTEXT_ALL;// 指定要获取哪写寄存器的信息，很重要
	GetThreadContext ( hThread, &ct );
// 	PDBG_REG7 pDr7 = (PDBG_REG7)&ct.Dr7;
	CloseHandle ( hThread );

	DWORD dwDr7 = ct.Dr7;
	printf ( "------------------------------------------------------------\r\n" );
	printf ( "ID    Breakpoint type       Address     Access type   Length\r\n" );
	for( int i = 0; i < 4; i++ )
	{
		if( HardBp[i].isActive == TRUE )
		{
			printf ( "%d     Hardware breakpoint   ", i );
			//地址输出
			switch( i )
			{
				case 0:
				printf ( "0x%p", ct.Dr0 );
				break;
				case 1:
				printf ( "0x%p", ct.Dr1 );
				break;
				case 2:
				printf ( "0x%p", ct.Dr2 );
				break;
				case 3:
				printf ( "0x%p", ct.Dr3 );
				break;
			}
			//属性输出
			//my-右移16+i*4位 再与11按位与
			switch( (dwDr7 >> (i * 4 + 16)) & 3 )
			{
				case 0:
				printf ( "  EXECUTE" );
				break;
				case 1:
				printf ( "  WRITE  " );
				break;
				case 3:
				printf ( "  ACCESS " );
				break;
			}
			printf ( "       " );
			//长度输出
			//my-右移18+i*4位 再与11按位与
			switch( (dwDr7 >> (i * 4 + 18)) & 3 )
			{
				case 0:
				printf ( "1" );
				break;
				case 1:
				printf ( "2" );
				break;
				case 3:
				printf ( "4" );
				break;
			}
			printf ( "\r\n" );
		}
	}
	printf ( "------------------------------------------------------------\r\n" );

	return TRUE;
}


//删除硬件断点 bhc
DWORD COperate::CmdDelHardBP ( DWORD dwOrder )
{
	HANDLE hThread = OpenThread ( THREAD_ALL_ACCESS, NULL, m_pDbgEvt->dwThreadId );
	CONTEXT ct = {};
	ct.ContextFlags = CONTEXT_ALL;// 指定要获取哪写寄存器的信息，很重要
	GetThreadContext ( hThread, &ct );
	// 	PDBG_REG7 pDr7 = (PDBG_REG7)&ct.Dr7;
	CloseHandle ( hThread );


	if( dwOrder < 0 || dwOrder >3 )
	{
		printf ( "序号输入错误\r\n" );
		return MYERRCONTINUE;
	}
	//删除硬件断点
	HardBp[dwOrder].isActive = FALSE;
	//设置寄存器标志位使断点失效
	switch( dwOrder )
	{
		case 0:
		ct.Dr7 &= 0xFFFFFFFC;//...1100
		break;
		case 1:
		ct.Dr7 &= 0xFFFFFFF3;//...0011
		break;
		case 2:
		ct.Dr7 &= 0xFFFFFFCF;//...11001111
		break;
		case 3:
		ct.Dr7 &= 0xFFFFFF3F;//...00111111
		break;
	}

	return TRUE;
}


//设置内存断点 bm
DWORD COperate::CmdSetMemBP ( DWORD dwAddr, DWORD dwLen, CHAR *pType )
{
	BP_RWE	enuMemBpRwe;		//断点属性
	LPVOID	lpBpAddr = (LPVOID)dwAddr;
	if( dwLen == 0 )
	{
		printf ( "断点长度输入错误\r\n" );
		return MYERRCONTINUE;
	}
	if( !((*pType == 'a') || (*pType == 'w')) )
	{
		printf ( "断点属性输入错误\r\n" );
		return MYERRCONTINUE;
	}
	//获取断点属性
	if( *pType == 'w' )
	{
		enuMemBpRwe = WRITE;
	}
	else
	{
		enuMemBpRwe = ACCESS;
	}
	//内存断点长度不能大于一个分页
	if( dwLen > 0x1000 )
	{
		printf ( "断点长度不能大于一个分页大小\r\n" );
		return MYERRCONTINUE;
	}
	//要设置的内存断点是否跨两个内存分页，如果跨两个则自动分为两个内存断点
	if( (dwAddr & 0xFFFFF000) == ((dwAddr + dwLen) & 0xFFFFF000) )
	{//				 my- 0x1000之内相等
		if( !SetMemBpOnOnePag ( lpBpAddr, dwLen, enuMemBpRwe ) )
		{
			return FALSE;
		}
	}
	else
	{
		DWORD dwSecondPagStart = (dwAddr + dwLen) & 0xFFFFF000;
		//my-变成0xFFFF1XXX
		DWORD dwFirstLen = dwSecondPagStart - dwAddr;
		//my-0xFFFF1000-0xFFFFFXXX
		DWORD dwSecondLen = dwLen - dwFirstLen;

		if( !SetMemBpOnOnePag ( lpBpAddr, dwFirstLen, enuMemBpRwe ) )
		{//my-设置第一页内存断点
			return FALSE;
		}

		if( !SetMemBpOnOnePag ( (LPVOID)dwSecondPagStart, dwSecondLen, enuMemBpRwe ) )
		{//my-设置第二页内存断点
			return FALSE;
		}
	}

	return TRUE;
}

//设置在一个分页以内的内存断点
DWORD COperate::SetMemBpOnOnePag ( LPVOID lpBpAddr, DWORD dwLen, BP_RWE enuMemBpRwe )
{
	DWORD	dwMemBpAddr = (DWORD)lpBpAddr;				//内存断点地址
	DWORD	dwMemBpPagAddr = dwMemBpAddr & 0xFFFFF000;	//内存断点所在分页起始地址
	BPNODE	MemBpNode;		//内存断点节点
	//检查内存分页的有效性
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	if( sizeof ( mbi ) != VirtualQueryEx ( m_pi.hProcess, lpBpAddr, &mbi, sizeof ( mbi ) ) )
	{//virtualQueryEx查询其他进程内存状态
		printf ( "SetMemBpOnOnePag函数出错!" );
		return FALSE;
	}
	//该内存地址不能设置断点
	if( mbi.State != MEM_COMMIT )
	{
		printf ( "输入的断点地址无内存分页\r\n" );
		return MYERRCONTINUE;
	}

	//检查是不是已经存在的内存断点,内存断点不同于其他,有重叠就算已经存在
	list<BPNODE>::iterator itMemBp;
	for( itMemBp = g_MemBplist.begin (); itMemBp != g_MemBplist.end (); itMemBp++ )
	{
		PBPNODE pMemBp = &(*itMemBp);

		//已存在内存断点开始地址
		LPVOID lpMemBpAddr = pMemBp->lpBpAddr;
		//已存在内存断点结束地址
		LPVOID lpMemBpAddrEnd = (LPVOID)((DWORD)lpMemBpAddr + pMemBp->dwBpLen - 1);

		//和已经存在的断点重叠
		if( (lpMemBpAddr <= lpBpAddr) && (lpBpAddr <= lpMemBpAddrEnd) )
		{
			printf ( "%03d   STARTADDR: %p  ENDADDR: %p  TYPE: ",
					 pMemBp->dwBpOrder, lpMemBpAddr, lpMemBpAddrEnd );
			if( pMemBp->enuBpRWE == WRITE )
			{
				printf ( "WRITE  " );
			}
			else
			{
				printf ( "ACCESS  " );
			}
			printf ( "LEN: %d\r\n", pMemBp->dwBpLen );
			printf ( "和以上内存断点有重叠\r\n" );
			return MYERRCONTINUE;
		}
	}

	//设置新内存断点 判断该断点所在分页是否已经存在内存断点
	DWORD dwOldProtect = g_MemPagMap[dwMemBpPagAddr];
	//该断点所在分页不存在其他断点设置该分页属性
	if( dwOldProtect == 0 )
	{
		if( !VirtualProtectEx ( m_pi.hProcess, lpBpAddr, 1, PAGE_NOACCESS, &dwOldProtect ) )
		{
			printf ( "SetMemBpOnOnePag函数出错!" );
			return FALSE;
		}
		g_MemPagMap[dwMemBpPagAddr] = dwOldProtect;
	}

	MemBpNode.dwBpLen = dwLen;
	MemBpNode.dwBpOrder = g_dwBpOrder++;
	MemBpNode.enuBpRWE = enuMemBpRwe;
	MemBpNode.isActive = TRUE;
	MemBpNode.lpBpAddr = lpBpAddr;
	MemBpNode.dwOldProtect = dwOldProtect;
	g_MemBplist.push_back ( MemBpNode );

	return TRUE;
}


//显示内存断点 bml
DWORD COperate::CmdShowMemBPList ()
{
	printf ( "------------------------------------------------------------\r\n" );
	printf ( "ID    Breakpoint type       Address     Access type   Length\r\n" );
	list<BPNODE>::iterator itMemBp;
	for( itMemBp = g_MemBplist.begin (); itMemBp != g_MemBplist.end (); itMemBp++ )
	{
		PBPNODE pMemBpNode = &(*itMemBp);
		printf ( "%03d   Memory breakpoint     0x%p",
				 pMemBpNode->dwBpOrder, pMemBpNode->lpBpAddr );
		if( pMemBpNode->enuBpRWE == WRITE )
		{
			printf ( "  WRITE " );
		}
		else
		{
			printf ( "  ACCESS" );
		}
		printf ( "        0x%x\r\n", pMemBpNode->dwBpLen );
	}
	printf ( "------------------------------------------------------------\r\n" );
	return TRUE;
}

//显示分页断点列表 bmpl
DWORD COperate::CmdShowPagMemBPList ()
{
	printf ( "-----------------------------------------------------------------------\r\n" );
	printf ( "MemPagBase     MemBpID    MemBpAddress    MemBpAccesstype   MemBpLength\r\n" );

	map<DWORD, DWORD>::iterator itMemPag;
	for( itMemPag = g_MemPagMap.begin (); itMemPag != g_MemPagMap.end (); itMemPag++ )
	{
		list<BPNODE>::iterator itMemBp;
		for( itMemBp = g_MemBplist.begin (); itMemBp != g_MemBplist.end (); itMemBp++ )
		{
			PBPNODE pMemBpNode = &(*itMemBp);
			/*
						map是模板，一个map变量key和value两个值，你在这里是想用类似map<int, int> m_map的变量来表示背包里的东西，
						m_map->first可以取得key值，m_map->second可以取得value值；
						map自动按照key值按升序排列，key的值不能修改，可以修改value的值。类似的写法：
			*/
			if( (((DWORD)pMemBpNode->lpBpAddr) & 0xFFFFF000) == itMemPag->first )
			{
				printf ( "%p       %04d        0x%p",
						 itMemPag->first, pMemBpNode->dwBpOrder, pMemBpNode->lpBpAddr );
				if( pMemBpNode->enuBpRWE == WRITE )
				{
					printf ( "        WRITE " );
				}
				else
				{
					printf ( "        ACCESS" );
				}
				printf ( "         0x%x\r\n", pMemBpNode->dwBpLen );
			}
		}
	}
	printf ( "-----------------------------------------------------------------------\r\n" );
	return TRUE;
}

//删除内存断点 bmc
DWORD COperate::CmdDelMemBP ( DWORD dwOrder )
{
	DWORD	dwDelMemPagAddr;	//被删除内存节点的内存分页起始地址
	DWORD	dwTmp;
// 	if( str1.IsEmpty () )
// 	{
// 		printf ( "输入命令缺少参数\r\n" );
// 		return MYERRCONTINUE;
// 	}
// 	//转换
// 	wchar_t	*pRet = NULL;
// 	DWORD	dwOrder = wcstoul ( str1, &pRet, 10 );
// 	//转换失败
// 	if( *pRet != NULL )
// 	{
// 		printf ( "要删除的断点序号输入错误\r\n" );
// 		return MYERRCONTINUE;
// 	}

	//删除内存断点列表中的节点
	list<BPNODE>::iterator itMemBp;
	for( itMemBp = g_MemBplist.begin (); itMemBp != g_MemBplist.end (); itMemBp++ )
	{
		//找到了该节点
		PBPNODE pMemBpNode = &(*itMemBp);
		if( pMemBpNode->dwBpOrder == dwOrder )
		{
			//保存删除内存节点的内存分页起始地址
			dwDelMemPagAddr = (DWORD)pMemBpNode->lpBpAddr & 0xFFFFF000;
			//删除节点
			g_MemBplist.erase ( itMemBp );
			//重新查找断点链表是否还有存在该内存页面的断点
			for( itMemBp = g_MemBplist.begin (); itMemBp != g_MemBplist.end (); itMemBp++ )
			{
				pMemBpNode = &(*itMemBp);
				if( ((DWORD)(pMemBpNode->lpBpAddr) & 0xFFFFF000) == dwDelMemPagAddr )
				{
					break;
				}
			}
			//该内存分页已经不存在其他内存断点
			if( itMemBp == g_MemBplist.end () )
			{
				//内存分页表恢复该内存分页属性并在表中删除该分页记录
				DWORD dwOldProtect = g_MemPagMap[dwDelMemPagAddr];
				if( dwOldProtect )
				{
					//恢复内存属性
					if( !VirtualProtectEx ( m_pi.hProcess, (LPVOID)dwDelMemPagAddr, 1, dwOldProtect, &dwTmp ) )
					{
						printf ( "bmc命令出错" );
						return FALSE;
					}
					//删除分页记录
					map<DWORD, DWORD>::iterator itMemPag = g_MemPagMap.find ( dwDelMemPagAddr );
					g_MemPagMap.erase ( itMemPag );
				}

				return TRUE;
			}
			//该分页还有其他内存断点
			else
			{
				return TRUE;
			}
		}
	}

	printf ( "没有找到该序号对应的内存断点\r\n" );
	return MYERRCONTINUE;
}

//处理访问异常
DWORD COperate::OnExceptionAccess ( DEBUG_EVENT &DebugEvent )
{
	DWORD	dwAccessFlg = DebugEvent.u.Exception.ExceptionRecord.ExceptionInformation[0];
	DWORD	dwAccessAddr = DebugEvent.u.Exception.ExceptionRecord.ExceptionInformation[1];
	DWORD	dwAccessPagAddr = dwAccessAddr & 0xFFFFF000;
	DWORD	dwTmp;

	// 	printf("Addr:%p Flg:%p\r\n",dwAccessAddr,dwAccessFlg);

	//判断是不是调试器设置的内存断点，首先判断是否命中分页
	DWORD dwOldProtect = g_MemPagMap[dwAccessPagAddr];
	//所在内存分页有内存断点
	if( dwOldProtect )
	{
		//暂时还原该分页内存属性
		if( !VirtualProtectEx ( m_pi.hProcess, (LPVOID)dwAccessAddr, 1, dwOldProtect, &dwTmp ) )
		{
			printf ( "处理访问异常出错!" );
			return FALSE;
		}
		//设置恢复内存断点标志
		isResumeMemBp = TRUE;
		// 设置1个单步
		HANDLE hThread = OpenThread ( THREAD_ALL_ACCESS, NULL, m_pDbgEvt->dwThreadId );
		CONTEXT ct = {};
		ct.ContextFlags = CONTEXT_ALL;// 指定要获取哪写寄存器的信息，很重要
		GetThreadContext ( hThread, &ct );
		PEFLAGS pElg = (PEFLAGS)&ct.EFlags;
		pElg->TF = 1;
		SetThreadContext ( hThread, &ct );
		CloseHandle ( hThread );

		//接着判断是否命中内存断点
		list<BPNODE>::iterator itMemBp;
		for( itMemBp = g_MemBplist.begin (); itMemBp != g_MemBplist.end (); itMemBp++ )
		{
			PBPNODE pMemBpNode = &(*itMemBp);
			DWORD dwMemBpAddr = (DWORD)pMemBpNode->lpBpAddr;

			//访问地址命中访问断点范围断点属性为访问即命中断点
			if( (dwAccessAddr >= dwMemBpAddr) && (dwAccessAddr < dwMemBpAddr + pMemBpNode->dwBpLen)
				&& (pMemBpNode->enuBpRWE == ACCESS) )
			{
				break;
			}
			//访问地址命中访问断点范围并且异常为写入异常即命中写入断点
			if( (dwAccessAddr >= dwMemBpAddr) && (dwAccessAddr < dwMemBpAddr + pMemBpNode->dwBpLen)
				&& (dwAccessFlg == 1) && (pMemBpNode->enuBpRWE == WRITE) )
			{
				break;
			}
		}
		//命中调试器设置的内存断点，这时让用户输入
		if( itMemBp != g_MemBplist.end () )
		{
			//用户单步清除
			isUserStep = FALSE;
			//用户输入
			printf ( "ON Memory Breakpoint\r\n" );
			return UserInput ( DebugEvent );
		}

		//断点所在分页有内存断点，但是没有命中用户地址
		return DBG_CONTINUE;
	}

	//所在分页没有内存断点
	return DBG_EXCEPTION_NOT_HANDLED;
}

//显示模块 lm
DWORD COperate::CmdShowMod ( DEBUG_EVENT &DebugEvent )
{
	if( GetCurrentModules ( DebugEvent ) == FALSE )
	{
		return FALSE;
	}
	//显示模块信息
	printf ( "Base      Size      Entry     Name          Path    \r\n" );
	list<DLLNODE>::iterator itDll;
	for( itDll = DllList.begin (); itDll != DllList.end (); itDll++ )
	{
		PDLLNODE pDllNode = &(*itDll);
		printf ( "%p  %p  %p  ", pDllNode->dwModBase, pDllNode->dwModSize, pDllNode->dwModEntry );
		// 		printf("%-14s", pDllNode->szModName);//用printf名字只显示第一个字符
		wprintf_s ( L"%-14s", pDllNode->szModName );
		// 		printf(pDllNode->szModPath);
		wprintf_s ( pDllNode->szModPath );
		printf ( "\r\n" );
	}
	printf ( "\r\n" );
	printf ( "\n=================================================================\n" );

	return TRUE;
}


//获取当前程序所有模块
BOOL COperate::GetCurrentModules ( DEBUG_EVENT &DebugEvent )
{
	DLLNODE DllNode;
	PDWORD	pdwOldProtect = NULL;
	byte	*pBuffer = NULL;
	DWORD	dwPagCount = 0;
	int		i = 0;
	DWORD	dwTmp = 0;
	PIMAGE_DOS_HEADER pPeDos = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	PIMAGE_OPTIONAL_HEADER pOptional = NULL;

	//win7
	DWORD dwOldProtect;

	//释放之前链表资源
	DllList.clear ();

	//遍历加载模块
	HANDLE hmodule = CreateToolhelp32Snapshot ( TH32CS_SNAPMODULE, DebugEvent.dwProcessId );
	if( hmodule == INVALID_HANDLE_VALUE )
	{
		printf ( "遍历模块时出错!" );
		goto ERROR_EXIT;
	}
	MODULEENTRY32 me;
	me.dwSize = sizeof ( MODULEENTRY32 );
	if( Module32First ( hmodule, &me ) )
	{
		do
		{

			DllNode.dwModBase = (DWORD)me.modBaseAddr;
			DllNode.dwModSize = me.modBaseSize;
			DllNode.szModName = me.szModule;
			DllNode.szModPath = me.szExePath;
			//解析pe结构拿入口点
			//注释部分为xp系统的做法，win7系统读取ntdll会失败，一般pe pOptional位于前1K位置后面紧跟text段
			//win7采用读取前1K数据分析入口点位置
			pBuffer = new byte[0x1000];
			if( pBuffer == NULL )
			{
				printf ( "遍历模块时出错!" );
				goto ERROR_EXIT;
			}
			VirtualProtectEx ( m_pi.hProcess, me.modBaseAddr, 1, PAGE_READWRITE, &dwOldProtect );
			if( !ReadProcessMemory ( m_pi.hProcess, me.modBaseAddr, pBuffer, 0x1000, &dwTmp ) )
			{
				printf ( "遍历模块时出错!" );
				goto ERROR_EXIT;
			}
			if( dwTmp != 0x1000 )
			{
				goto ERROR_EXIT;
			}
			//win7还原属性
			VirtualProtectEx ( m_pi.hProcess, me.modBaseAddr, 1, dwOldProtect, &dwTmp );
			//pe分析获取入口点
			pPeDos = (PIMAGE_DOS_HEADER)pBuffer;
			if( pPeDos->e_lfanew >= 0x1000 )
			{
				//读取长度不够无法解析入口点
				goto ERROR_EXIT;
			}
			pNtHeaders = (PIMAGE_NT_HEADERS)(pPeDos->e_lfanew + (UINT)pBuffer);
			pOptional = &(pNtHeaders->OptionalHeader);
			if( (UINT)pOptional - (UINT)pBuffer > 0x1000 )
			{
				//读取长度不够无法解析入口点
				goto ERROR_EXIT;
			}
			DWORD *pEntryPoint = &(pOptional->AddressOfEntryPoint);
			if( (UINT)pEntryPoint - (UINT)pBuffer > 0x1000 )
			{
				//读取长度不够无法解析入口点
				goto ERROR_EXIT;
			}

			DllNode.dwModEntry = pOptional->AddressOfEntryPoint + (DWORD)me.modBaseAddr;

			delete[] pBuffer;
			pBuffer = NULL;

			// 			//计算该模块占几个分页
			// 			dwPagCount = me.modBaseSize / 0x1000;
			// 			//申请空间保存旧属性
			// 			pdwOldProtect = new DWORD[dwPagCount];
			// 			if (pdwOldProtect == NULL)
			// 			{
			// 				ShowError();
			// 				goto ERROR_EXIT;
			// 			}
			// 
			// 			//防止有内存断点临时修改内存属性
			// 			for (i=0; i<dwPagCount; i++)
			// 			{
			// 				if (!VirtualProtectEx(m_pi.hProcess, me.modBaseAddr + i*0x1000, 1, PAGE_READWRITE, pdwOldProtect+i))
			// 				{
			// 					ShowError();
			// 					goto ERROR_EXIT;
			// 				}
			// 			}
			// 			//申请空间把对方模块读到调试器进程空间
			// 			pBuffer = new byte[me.modBaseSize];
			// 			if (pBuffer == NULL)
			// 			{
			// 				ShowError();
			// 				goto ERROR_EXIT;
			// 			}
			// 			if (!ReadProcessMemory(m_pi.hProcess, me.modBaseAddr, pBuffer, me.modBaseSize, &dwTmp))
			// 			{
			// 				ShowError();
			// 				goto ERROR_EXIT;
			// 			}
			// 			if (dwTmp != me.modBaseSize)
			// 			{
			// 				goto ERROR_EXIT;
			// 			}
			// 			//还原内存保护属性
			// 			for (i=0; i<dwPagCount; i++)
			// 			{
			// 				VirtualProtectEx(m_pi.hProcess, me.modBaseAddr + i*0x1000, 1, pdwOldProtect[i], &dwTmp);
			// 			}
			// 			//pe分析获取入口点
			// 			pPeDos = (PIMAGE_DOS_HEADER)pBuffer;
			// 			pNtHeaders = (PIMAGE_NT_HEADERS)(pPeDos->e_lfanew + (UINT)pBuffer);
			// 			pOptional = &(pNtHeaders->OptionalHeader);
			// 
			// 			DllNode.dwModEntry = pOptional->AddressOfEntryPoint + (DWORD)me.modBaseAddr;
			// 
			// 			//循环中释放一个节点处理过程中申请的资源
			// 			delete[] pdwOldProtect;
			// 			pdwOldProtect = NULL;
			// 			delete[] pBuffer;
			// 			pBuffer = NULL;

			//添加模块信息到模块链表
			DllList.push_back ( DllNode );

		}
		while( ::Module32Next ( hmodule, &me ) );
	}
	CloseHandle ( hmodule );
	hmodule = INVALID_HANDLE_VALUE;

	return TRUE;

	ERROR_EXIT:
	if( pdwOldProtect )
	{
		for( int j = 0; j < i; j++ )
		{
			VirtualProtectEx ( m_pi.hProcess, me.modBaseAddr + i * 0x1000, 1, pdwOldProtect[i], &dwTmp );
		}
		delete[] pdwOldProtect;
	}
	if( pBuffer )
	{
		delete[] pBuffer;
	}
	if( hmodule != INVALID_HANDLE_VALUE )
	{
		CloseHandle ( hmodule );
	}

	//win7还原属性
	VirtualProtectEx ( m_pi.hProcess, me.modBaseAddr, 1, dwOldProtect, &dwTmp );

	return FALSE;
}


//显示导出表
DWORD COperate::CmdShowExportTable ()
{
	// 	ofstream ofileTestApi;
	// 	ofileTestApi.open("TestApi.txt");
	// 	CString StrFormat;
	map<DWORD, CString>::iterator itApiNameMap;
	for( itApiNameMap = ApiExportNameMap.begin (); itApiNameMap != ApiExportNameMap.end (); itApiNameMap++ )
	{
		wprintf_s ( L"%p	%s\r\n", itApiNameMap->first, itApiNameMap->second );
		// 		StrFormat.Format("%p %s\r\n", itApiNameMap->first, itApiNameMap->second);
		// 		ofileTestApi << StrFormat.GetBuffer(NULL);
	}
	// 	ofileTestApi.close();
	return TRUE;
}

//显示导入表
DWORD COperate::CmdShowImportTable ()
{
	HANDLE hFile = CreateFile ( szPath,
						  GENERIC_READ,
						  FILE_SHARE_READ,
						  NULL,
						  OPEN_EXISTING,
						  FILE_ATTRIBUTE_NORMAL,
						  NULL );
	if( hFile == INVALID_HANDLE_VALUE )
	{
		printf ( "文件不存在\n" );
		return 0;
	}

	DWORD dwFileSize = 0;
	dwFileSize = GetFileSize ( hFile, NULL );

	// 2. 申请内存空间
	BYTE* pBuf = new BYTE[dwFileSize];

	// 3. 将文件内容读取到内存中
	DWORD dwRead = 0;
	ReadFile ( hFile,
			   pBuf,
			   dwFileSize,
			   &dwRead,
			   NULL );

	// 将缓冲区当成DOS头结构体来解析
	// 1. 找到Dos头
	IMAGE_DOS_HEADER* pDosHdr;// DOS头
	pDosHdr = (IMAGE_DOS_HEADER*)pBuf;

	// 2. 找到Nt头
	IMAGE_NT_HEADERS* pNtHdr = NULL;
	pNtHdr = (IMAGE_NT_HEADERS*)(pDosHdr->e_lfanew + (DWORD)pDosHdr);

	// 3. 找到扩展头
	IMAGE_OPTIONAL_HEADER* pOptHdr = NULL;
	pOptHdr = &pNtHdr->OptionalHeader;

	// 4. 找到数据目录表
	IMAGE_DATA_DIRECTORY* pDataDir = NULL;
	pDataDir = pOptHdr->DataDirectory;
	// 5. 得到导入表的RVA
	DWORD dwImpRva = pDataDir[1].VirtualAddress;

	IMAGE_IMPORT_DESCRIPTOR* pImpArray;

	pImpArray = (IMAGE_IMPORT_DESCRIPTOR*)
		(RVAToOffset ( pDosHdr, dwImpRva ) + (DWORD)pDosHdr);

	// 导入表数组的个数并没有其它字段记录.
	// 结束的标志是以一个全0的元素作为结尾
	while( pImpArray->Name != 0 )
	{
		// 导入的Dll的名字(Rva)
		DWORD dwNameOfs = RVAToOffset ( pDosHdr, pImpArray->Name );
		// 		char* pDllName = (char*)(dwNameOfs - (DWORD)pDosHdr);//my-原程序错误地方
		char* pDllName = (char*)(dwNameOfs + (DWORD)pDosHdr);

		printf ( "DLL: [%s]\n", pDllName );

		// 解析,在这个dll中,一共导入哪些函数
		pImpArray->OriginalFirstThunk;
		// INT(导入名表)
		// 记录着一个从一个dll中导入了哪些函数
		// 这些函数要么是以名称导入,要么是以序号导入的
		// 到记录在一个数组中. 这个数组是IMAGE_THUNK_DATA
		// 类型的结构体数组.
		// FirstThunk保存着数组的RVA
		pImpArray->FirstThunk;
		DWORD INTOfs = RVAToOffset ( pDosHdr, pImpArray->FirstThunk );
		DWORD IATOfs = RVAToOffset ( pDosHdr, pImpArray->FirstThunk );
		IMAGE_THUNK_DATA* pInt = NULL;
		IMAGE_THUNK_DATA* pIat = NULL;
		/*
		这是一个只有4个字节的结构体.里面联合体中的每一个字段保存的
		值都是一样.
		这些值, 就是导入函数的信息.
		导入函数的信息有以下部分:
		1. 导入函数的序号
		2. 导入函数的名称(可能有可能没有)
		可以根据结构体中的字段的最高位判断, 导入信息
		是以名称导入还是以序号导入
		typedef struct _IMAGE_THUNK_DATA32 {
		union {
		DWORD ForwarderString;      // PBYTE
		DWORD Function;             // PDWORD
		DWORD Ordinal;
		DWORD AddressOfData;        // PIMAGE_IMPORT_BY_NAME
		} u1;
		} IMAGE_THUNK_DATA32;
		*/
		// 		pInt = (IMAGE_THUNK_DATA*)(INTOfs + pDosHdr);//my-原程序错误地方
		pInt = (IMAGE_THUNK_DATA*)(INTOfs + (DWORD)pDosHdr);//
		pIat = (IMAGE_THUNK_DATA*)(IATOfs + (DWORD)pDosHdr);

		while( pInt->u1.Function != 0 )
		{
			// 判断是否是以序号导入
			if( IMAGE_SNAP_BY_ORDINAL32 ( pInt->u1.Function ) )
			{
				// 以序号方式导入
				// 结构体保存的值低16位就是一个导入的序号
				printf ( "\t导入序号[%d]\n", pInt->u1.Ordinal & 0xFFFF );
			}
			else
			{
				// 是以名称导入的]
				// 当函数是以名称导入的时候, 
				// pInt->u1.Function 保存的是一个
				// rva , 这个RVA指向一个保存函数名称
				// 信息的结构体
				IMAGE_IMPORT_BY_NAME* pImpName;
				DWORD dwImpNameOfs = RVAToOffset ( pDosHdr, pInt->u1.Function );
				pImpName = (IMAGE_IMPORT_BY_NAME*)
					(dwImpNameOfs + (DWORD)pDosHdr);

				printf ( "\t序号:[%d],函数名[%s]\n",
						 pImpName->Hint,
						 pImpName->Name );
			}
			++pInt;
		}

		++pImpArray;
	}
	printf ( "\n=================================================================\n" );

	return TRUE;
}


//LoadDll 获取模块导出函数名为反汇编解析函数名做准备不是调试器的异常返回DBG_EXCEPTION_NOT_HANDLED
//获取函数名过程中出现错误返回FALSE
//首次LoadDll不会有内存断点，如果之后再次LoadDll该dll没有内存断点影响map相同的key会覆盖一次
//有内存断点影响不用做处理可以直接返回DBG_EXCEPTION_NOT_HANDLED调试程序继续运行
DWORD COperate::OnLoadDll ( DEBUG_EVENT &DebugEvent )
{
	PIMAGE_DOS_HEADER		pPeDos = NULL;
	PIMAGE_NT_HEADERS		pNtHeaders = NULL;
	PIMAGE_OPTIONAL_HEADER	pOptional = NULL;
	PIMAGE_EXPORT_DIRECTORY pExport = NULL;
	DWORD					dwExport = 0;
	DWORD					dwe_lfanew;
	DWORD					dwTmp;
	DWORD					dwModSize;
	byte					*pBuffer = NULL;
	CString					szModeName;	//模块名称

	//获取模块大小
	pPeDos = (PIMAGE_DOS_HEADER)DebugEvent.u.LoadDll.lpBaseOfDll;
	if( !ReadProcessMemory ( m_pi.hProcess, &(pPeDos->e_lfanew), &dwe_lfanew, 4, &dwTmp ) )
		//my-读取远程进程内存数据
	{
		return DBG_EXCEPTION_NOT_HANDLED;
	}
	pNtHeaders = (PIMAGE_NT_HEADERS)(dwe_lfanew + (DWORD)DebugEvent.u.LoadDll.lpBaseOfDll);
	pOptional = &(pNtHeaders->OptionalHeader);
	if( !ReadProcessMemory ( m_pi.hProcess, &(pOptional->SizeOfImage), &dwModSize, 4, &dwTmp ) )
	{
		return DBG_EXCEPTION_NOT_HANDLED;
	}
	//申请空间
	pBuffer = new byte[dwModSize];
	if( pBuffer == NULL )
	{
		printf ( "OnLoadDll函数出错!" );
		return FALSE;
	}
	//读取被调试进程模块
	if( !ReadProcessMemory ( m_pi.hProcess, DebugEvent.u.LoadDll.lpBaseOfDll, pBuffer, dwModSize, &dwTmp ) )
	{
		return DBG_EXCEPTION_NOT_HANDLED;
	}
	if( dwTmp != dwModSize )
	{
		return DBG_EXCEPTION_NOT_HANDLED;
	}
	//解析pe获取函数名
	pPeDos = (PIMAGE_DOS_HEADER)pBuffer;
	pNtHeaders = (PIMAGE_NT_HEADERS)(pPeDos->e_lfanew + (UINT)pBuffer);
	pOptional = &(pNtHeaders->OptionalHeader);
	dwExport = pOptional->DataDirectory[0].VirtualAddress;
	//没有导出函数直接释放资源退出，主模块可能没有导出函数
	if( dwExport == 0 )
	{
		delete[] pBuffer;
		return DBG_EXCEPTION_NOT_HANDLED;
	}
	pExport = (PIMAGE_EXPORT_DIRECTORY)(pBuffer + dwExport);
	//遍历导出表获取函数名
	int*			pFunNameRvaExport = NULL;
	unsigned short*	pOrdinalExport = NULL;
	int*			pFunAddressRvaExport = NULL;
	int				FunRvaExport;
	int				FunVaExport;
	DWORD			dwModBase = (DWORD)DebugEvent.u.LoadDll.lpBaseOfDll;
	// 	CString			strFormat;

		//获取模块名称并用字符串分割去掉后面的.dll
		// 	if (!AfxExtractSubString(szModeName, (char *)(pBuffer + pExport->Name), 0, ' '))
		// 	{
		// 		delete[] pBuffer;
		// 		return DBG_EXCEPTION_NOT_HANDLED;
		// 	}
	szModeName = (char *)(pBuffer + pExport->Name);//my-将分割.dll换成这一行

	pFunNameRvaExport = (int*)(pBuffer + pExport->AddressOfNames);

	pOrdinalExport = (unsigned short*)(pBuffer + pExport->AddressOfNameOrdinals);

	pFunAddressRvaExport = (int*)(pBuffer + pExport->AddressOfFunctions);

	for( int i = 0; i < pExport->NumberOfNames; i++ )
	{
		//函数地址Rva
		FunRvaExport = pFunAddressRvaExport[*pOrdinalExport];
		//函数地址Va
		FunVaExport = dwModBase + FunRvaExport;
		//以函数地址为key和函数名一起添加进入map
		ApiExportNameMap[FunVaExport] = szModeName + '-' + (char *)(pBuffer + *pFunNameRvaExport);

		//取下一个函数名称和地址
		pFunNameRvaExport++;
		pOrdinalExport++;
	}

	//释放空间
	delete[] pBuffer;
	pBuffer = NULL;

	return DBG_EXCEPTION_NOT_HANDLED;
}

DWORD COperate::RVAToOffset ( IMAGE_DOS_HEADER* pDos,DWORD dwRva )
{
	IMAGE_SECTION_HEADER* pScnHdr;

	IMAGE_NT_HEADERS* pNtHdr =
		(IMAGE_NT_HEADERS*)(pDos->e_lfanew + (DWORD)pDos);

	pScnHdr = IMAGE_FIRST_SECTION ( pNtHdr );
	DWORD dwNumberOfScn = pNtHdr->FileHeader.NumberOfSections;

	// 1. 遍历所有区段找到所在区段
	for( int i = 0; i < dwNumberOfScn; ++i )
	{
		DWORD dwEndOfSection = pScnHdr[i].VirtualAddress + pScnHdr[i].SizeOfRawData;
		// 判断这个RVA是否在一个区段的范围内
		if( dwRva >= pScnHdr[i].VirtualAddress
			&& dwRva < dwEndOfSection )
		{
			// 2. 计算该RVA在区段内的偏移:rva 减去首地址
			DWORD dwOffset = dwRva - pScnHdr[i].VirtualAddress;
			// 3. 将区段内偏移加上区段的文件开始偏移
			return dwOffset + pScnHdr[i].PointerToRawData;
		}
	}
	return -1;
}
