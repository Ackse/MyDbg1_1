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
	// 	 HardBp[4] = { 0 };				//4��Ӳ���ϵ���Ϣ
	HardBp[0].isActive = FALSE;
	HardBp[1].isActive = FALSE;
	HardBp[2].isActive = FALSE;
	HardBp[3].isActive = FALSE;

}


COperate::~COperate ()
{
}

// BOOL COperate::isSystemBreak = TRUE;

//ע�⾲̬��Ա�������÷�
//������
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
	 	//�����ȡ���Խ���Ŀ���ļ���ַ
	 // 	CFileDialog infdlg(TRUE, NULL, NULL, NULL, "*.exe|*.exe|All Files|*.*||");
	 	CFileDialog infdlg ( TRUE );
	 	infdlg.m_ofn.lpstrFilter = L"����\0*.exe\0";
	 
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
								   DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,	//�����½����� | ӵ���¿���̨,���̳��丸������̨��Ĭ�ϣ�
								   NULL,
								   NULL,
								   &startUpInfo,
								   &m_pi );

	if( !bStatus )
	{
		printf ( "�������Խ���ʧ��!\n" );
		return;
	}
	//1.2	��ʼ�������¼��ṹ��
	DEBUG_EVENT DbgEvent;
	//  	DEBUG_EVENT DbgEvent;
	// 	LPDEBUG_EVENT lpDebugEvent = &DbgEvent;
	DWORD dwState = DBG_EXCEPTION_NOT_HANDLED;
	//2.�ȴ�Ŀ��Exe���������¼�
	while( TRUE )
	{
		WaitForDebugEvent ( &DbgEvent, INFINITE );
		m_pDbgEvt = &DbgEvent;
		//2.1 ���ݵ����¼�����,�ֱ���
		dwState = DispatchDbgEvent ( DbgEvent );
		ContinueDebugEvent ( DbgEvent.dwProcessId, DbgEvent.dwThreadId, dwState );
	}
	return;
}

//�ַ�����dbgEvent
DWORD COperate::DispatchDbgEvent ( DEBUG_EVENT &DebugEvent )
{
	//�жϵ�������
	DWORD dwRet = DBG_EXCEPTION_NOT_HANDLED;
	switch( DebugEvent.dwDebugEventCode )
	{
		case CREATE_PROCESS_DEBUG_EVENT:	//���̵���
		dwRet = OnCreateProcess ( DebugEvent );
		break;
		case EXCEPTION_DEBUG_EVENT:			//�쳣����
		dwRet = DispatchException ( DebugEvent );
		break;
		case CREATE_THREAD_DEBUG_EVENT:		//�̵߳���
		break;
		case EXIT_THREAD_DEBUG_EVENT:		//�˳��߳�
		break;
		case EXIT_PROCESS_DEBUG_EVENT:		//�˳�����
		printf ( "�����Խ����˳�\r\n" );
		break;
		case LOAD_DLL_DEBUG_EVENT:			//����DLL
		dwRet = OnLoadDll ( DebugEvent );
		break;
		case UNLOAD_DLL_DEBUG_EVENT:		//ж��DLL
		dwRet = OnLoadDll ( DebugEvent );
		break;
		case OUTPUT_DEBUG_STRING_EVENT:		//��������ַ���
		break;
		case RIP_EVENT:						//RIP����(RIP�쳣�¼�,�ڲ�����)
		return dwRet;	//������
	}
	return dwRet;
}

//��������
DWORD COperate::OnCreateProcess ( DEBUG_EVENT& DebugEvent )
{
	// 	DWORD dwRet = DBG_CONTINUE;
	WCHAR path[MAX_PATH] = { 0 };
	DWORD dwSize = MAX_PATH;
	m_lpBaseOfImage = DebugEvent.u.CreateProcessInfo.lpBaseOfImage;

	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////

	//���OEP
	SetConsoleTextAttribute ( GetStdHandle ( STD_OUTPUT_HANDLE ), 0xa );
	/*				 �Ե���ɫ���
	SetConsoleTextAttribute��API���ÿ���̨����������ɫ�ͱ���ɫ�ĺ���
	GetStdHandle��һ��Windows API������
	�����ڴ�һ���ض��ı�׼�豸����׼���롢��׼������׼������ȡ��һ�������������ʶ��ͬ�豸����ֵ��������Ƕ��ʹ�á�
	GetStdHandle�������ر�׼�����롢����������豸�ľ����Ҳ���ǻ�����롢��� / �������Ļ�������ľ����
	*/
	QueryFullProcessImageName ( DebugEvent.u.CreateProcessInfo.hProcess,
								0,
								path,
								&dwSize );

	printf ( "���̱�����:%S\n", path );

	//oep������ڵ�
	printf ( "OEP: %p          IMAGEBASE: %p\r\n\r\n",
			 DebugEvent.u.CreateProcessInfo.lpStartAddress,
			 DebugEvent.u.CreateProcessInfo.lpBaseOfImage );

	m_pi.dwProcessId = DebugEvent.dwProcessId;
	m_pi.dwThreadId = DebugEvent.dwThreadId;
	// 	���̾��������ʹ��
	m_pi.hProcess = DebugEvent.u.CreateProcessInfo.hProcess;
	// 	����߳̾������ʹ��
	m_pi.hThread = DebugEvent.u.CreateProcessInfo.hThread;

	CmdSetInt3BP ( (DWORD)DebugEvent.u.CreateProcessInfo.lpStartAddress ,FALSE);
	// 	CloseHandle ( DebugEvent.u.CreateProcessInfo.hThread );

	return DBG_CONTINUE;
}

//�쳣����
DWORD COperate::DispatchException ( DEBUG_EVENT &DebugEvent )
{
	//�쳣�����ж�
	switch( DebugEvent.u.Exception.ExceptionRecord.ExceptionCode )
	{
		//int3�쳣
		case EXCEPTION_BREAKPOINT:
		{
			return OnExceptionInt3Bp ( DebugEvent );
		}
		//�����Ĵ���
		case EXCEPTION_SINGLE_STEP:
		{
			return OnExceptionSingleStep ( DebugEvent );
		}
		//�����쳣//my-�ڴ�ϵ�?
		case EXCEPTION_ACCESS_VIOLATION:
		{
			return OnExceptionAccess ( DebugEvent );
// 			return DBG_EXCEPTION_NOT_HANDLED;
		}
	}
	return DBG_EXCEPTION_NOT_HANDLED;
}

//����ϵ��쳣(int3��)
DWORD COperate::OnExceptionInt3Bp ( DEBUG_EVENT &DebugEvent )
{
	//��һ��ϵͳ�ϵ����
	if( isSystemBreak )
	{
		isSystemBreak = FALSE;
		//�û�����
// 		return UserInput ( DebugEvent );
		return DBG_CONTINUE;
	}

	//����ǲ��ǵ������ϵ�
	list<INT3BPNODE>::iterator itInt3Bp;
	for( itInt3Bp = g_Int3BpList.begin (); itInt3Bp != g_Int3BpList.end (); itInt3Bp++ )
	{
		PINT3BPNODE pINT3BPNODE = &(*itInt3Bp);
		if( pINT3BPNODE->lpBpAddr == DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress )
		{
			//���е��������õĶϵ㣬��ֹ���ڴ�ϵ����޸��ڴ�����
			DWORD	dwOldprotect;
			DWORD	dwRetCount;
			//�޸��ڴ汣������,ʹ��ɸ�д
			if( !VirtualProtectEx ( m_pi.hProcess, pINT3BPNODE->lpBpAddr, 1, PAGE_READWRITE, &dwOldprotect ) )
			{
				DBGOUT ("%s\n", "OnExceptionBreakPoint�����д���!" );
				return FALSE;
			}
			//��ʱ��ԭ�ϵ�Ϊԭֵ
			//WriteProcessMemory�˺�����д��ĳһ���̵��ڴ����������������Է��ʣ����������ʧ�ܡ�
			if( !WriteProcessMemory ( m_pi.hProcess, pINT3BPNODE->lpBpAddr, &pINT3BPNODE->OldByte, 1, &dwRetCount ) )
			{
				DBGOUT ( "%s\n", "OnExceptionBreakPoint�����д���!" );
				VirtualProtectEx ( m_pi.hProcess, pINT3BPNODE->lpBpAddr, 1, dwOldprotect, &dwRetCount );
				return FALSE;
			}
			//��ԭ��������
			if( !VirtualProtectEx ( m_pi.hProcess, pINT3BPNODE->lpBpAddr, 1, dwOldprotect, &dwRetCount ) )
			{
				DBGOUT ( "%s\n", "��ԭ�������Դ���!" );
				return FALSE;
			}

			// ����1������
			HANDLE hThread = OpenThread ( THREAD_ALL_ACCESS, NULL, m_pDbgEvt->dwThreadId );
			CONTEXT ct = {};
			ct.ContextFlags = CONTEXT_ALL;// ָ��Ҫ��ȡ��Щ�Ĵ�������Ϣ������Ҫ
			GetThreadContext ( hThread, &ct );
			PEFLAGS pElg = (PEFLAGS)&ct.EFlags;
			// 	PDBG_REG6 pDr6 = (PDBG_REG6)&ct.Dr6;
// 			pElg->TF = 1;
			//�ָ�EIP
			ct.Eip--;			
			//��Ϊ�����쳣��eip�ڷ����쳣���ֽ�֮��
			SetThreadContext ( hThread, &ct );
			if( pINT3BPNODE->isOnce == FALSE )
			{//���е������öϵ���Ҫ�ָ�
				//���öϵ�ΪʧЧ
				pINT3BPNODE->isActive = FALSE;
				//���õ�����־
				pElg->TF = 1;

// 				context.EFlags |= 0x100;
				// 				context.EFlags
								/*
								//my-��λ��������� | ����˫Ŀ��������书���ǲ����������������Ӧ�Ķ���λ���
								ֻҪ��Ӧ�Ķ�������λ��һ��Ϊ1ʱ�����λ��Ϊ1��������������Ǹ���ʱ���������������Բ������
								�൱��  			  0x0000 0001 0000 0000
								��TF��flag�ĵڰ�λ
								�������ı�־�Ĵ�������һ�������־λ����ΪTrap Flag�����TF����TFλΪ1ʱ��
								CPUÿִ����һ��ָ�������һ�������쳣���жϵ������쳣������򣬵������ĵ���ִ�й��ܴ��������һ������ʵ�ֵ�,
								��ΪCPU�ڽ����쳣��������ǰ���Զ����TF��־����ˣ���CPU�жϵ����������ٹ۲�TF��־������ֵ����0

								*/
								//���ûָ��ϵ��־
				isResumeInt3Bp = TRUE;
			}
			//��ʱ�ϵ�����,��ʱ�ϵ�ʹ������������ʱ�ϵ�
			else
			{
				//��ִ��"g ��ַ"����ʱ,������ʱ�ϵ�,����ִ�е�����
				g_Int3BpList.erase ( itInt3Bp );
			}
			CloseHandle ( hThread );

			//�û��������
			isUserStep = FALSE;

			//�û�����
			printf ( "ON int3 Breakpoint\r\n" );
			return UserInput ( DebugEvent );
		}
	}
	//���ǵ������öϵ�
	return DBG_EXCEPTION_NOT_HANDLED;
}

//��ʾ�Ĵ���ֵ
void COperate::ShowRegInfo ( LPCONTEXT lpContext )
{
	// 	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0xD);

	printf ( "EAX=%p EBX=%p ECX=%p EDX=%p ESI=%p EDI=%p\r\n",
			 lpContext->Eax, lpContext->Ebx, lpContext->Ecx, lpContext->Edx,
			 lpContext->Esi, lpContext->Edi );
	printf ( "EIP=%p ESP=%p EBP=%p                OF DF IF SF ZF AF PF CF\r\n",
			 lpContext->Eip, lpContext->Esp, lpContext->Ebp );
	//my-��ջ��Ϣ
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

// ��ʾһ���������룬���ش��볤�ȣ�ʧ�ܷ���0
DWORD COperate::ShowDisasmOneCode ( LPVOID pCodeAddr )
{
	byte	szCodeBuf[20];		//��������ݻ�����
// 	char	szASM[128];			//������ַ���������
// 	char	szOpcode[64] = { 0 };	//�����֮����ָ�������
	WCHAR	szOpcode[64] = { 0 };	//�����֮����ָ�������
	UINT	nCodeSize;			//����൥��ָ���  

	DWORD	dwFirstProtect;		//�ڴ��ҳ��������//my-��һ��λ��
	DWORD	dwSecondProtect;	//�ڴ��ҳ��������//my-�ڶ���λ��
	DWORD	dwTmp;//my-temp�ų�������
	DWORD	dwReadCodeCount;	//ʵ�ʶ�ȡ�Ĵ�������ݳ���
	DWORD	*pdwAddr = NULL;	//����Ǽ��call��ָ��Ϊ���callָ��api����ַָ��

	//��ֹ���ڴ�ϵ��޸��ڴ�����
	VirtualProtectEx ( m_pi.hProcess, pCodeAddr, 1, PAGE_READWRITE, &dwFirstProtect );

	/*
	VirtualProtectEx�������Ըı����ض��������ڴ�����ı�������
	����ԭ�Σ�
	BOOL VirtualProtectEx(
	HANDLE m_pi.hProcess, // Ҫ�޸��ڴ�Ľ��̾��
	LPVOID lpAddress, // Ҫ�޸��ڴ����ʼ��ַ
	DWORD dwSize, // ҳ�����С
	DWORD flNewProtect, // �·��ʷ�ʽ
	PDWORD lpflOldProtect // ԭ���ʷ�ʽ ���ڱ���ı�ǰ�ı������� ������Ҫ��ַ
	);
	*/

	//my-Ϊ��szCodeBuf��20,����ֻ�Ǵ���ʵ��ʵ�ʳ��ȵ�ֵ����
	VirtualProtectEx ( m_pi.hProcess, (LPVOID)((DWORD)pCodeAddr + sizeof ( szCodeBuf ) - 1), 1, PAGE_READWRITE, &dwSecondProtect );
	//my-��ȡԶ�̽����ڴ�����,��ȡ�����ʵ�ʳ���
	if( !ReadProcessMemory ( m_pi.hProcess, pCodeAddr, szCodeBuf, sizeof ( szCodeBuf ), &dwReadCodeCount ) )
	{
		// 		printf ( "ShowDisasmOneCode�����ڲ�����!" );
		DBGOUT ( "%s\n", "��ȡ�ڴ�ʧ��!" );
		//my-�������ѱ����������¸Ļ�ȥ���˳�
		VirtualProtectEx ( m_pi.hProcess, (LPVOID)((DWORD)pCodeAddr + sizeof ( szCodeBuf ) - 1), 1, dwSecondProtect, &dwTmp );
		VirtualProtectEx ( m_pi.hProcess, pCodeAddr, 1, dwFirstProtect, &dwTmp );
		return FALSE;
	}

	//��ԭ�ڴ����ԣ��Ȼ�ԭ���ڶ�������ҳ���п��ܵڶ��͵�һ��ͬһ����ҳ��
	VirtualProtectEx ( m_pi.hProcess, (LPVOID)((DWORD)pCodeAddr + sizeof ( szCodeBuf ) - 1), 1, dwSecondProtect, &dwTmp );
	VirtualProtectEx ( m_pi.hProcess, pCodeAddr, 1, dwFirstProtect, &dwTmp );

	//����Ƿ������õĶϵ㣬����л�ԭΪԭֵ
	for( int i = 0; i < dwReadCodeCount; i++ )
	{
		if( szCodeBuf[i] == 0xCC )//�����
		{
			list<INT3BPNODE>::iterator itInt3Bp;
			//my-���д����Ҳ���ԭ��,��ϸ������ͷ���Ƿ�û������
			for( itInt3Bp = g_Int3BpList.begin (); itInt3Bp != g_Int3BpList.end (); itInt3Bp++ )
			{
				PINT3BPNODE pINT3BPNODE = &(*itInt3Bp);
				//���������ҵ��ϵ��Ӧ��,�ָ������
				if( pINT3BPNODE->lpBpAddr == (LPVOID)((DWORD)pCodeAddr + i) )
				{
					szCodeBuf[i] = pINT3BPNODE->OldByte;
				}
			}
		}
	}
	//�����
	DISASM objDiasm;
	objDiasm.EIP = (UIntPtr)szCodeBuf; // ��ʼ��ַ
	objDiasm.VirtualAddr = (UINT64)pCodeAddr;     // �����ڴ��ַ��������������ڼ����ַ��
	objDiasm.Archi = 0;                     // AI-X86
	objDiasm.Options = 0x000;                 // MASM
	 // 3. ��������
	nCodeSize = Disasm ( &objDiasm );

	if( nCodeSize == -1 )
		return nCodeSize;
	// 4. ��������ת��Ϊ�ַ���
	LPWSTR lpOPCode = szOpcode;
	PBYTE  lpBuffer = szCodeBuf;
	for( UINT i = 0; i < nCodeSize; i++ )
	{
		StringCbPrintf ( lpOPCode++, 50, L"%X", *lpBuffer & 0xF0 );
		StringCbPrintf ( lpOPCode++, 50, L"%X", *lpBuffer & 0x0F );
		lpBuffer++;
	}
	// 6. ���淴������ָ��
	WCHAR szASM[50] = { 0 };
	MultiByteToWideChar ( CP_ACP, 0, objDiasm.CompleteInstr, -1, szASM, _countof ( szASM ) );
	// 	StringCchCopy(pASM, 50, szASM);
	wprintf_s ( L"0x%08x %-16s%s\n", pCodeAddr, szOpcode, szASM );
	//szOpcodeû�и�ֵ����ʶ���CC
// 	wprintf_s(L"0x%08x %-16s%s\n", (int)objDiasm.VirtualAddr, szOpcode, szASM);
	return nCodeSize;
}


/**************************************************************************************************************
�û������ʾ�ǵ��������õ��쳣�����ұ����Գ����Ѿ����е��������õ��쳣ͣ������
UserInput����ֵΪDBG_CONTINUE����FALSE
FALSE			��ʾ����ִ�й����д��󣬵����޷�����������ú����Ѵ��󷵻ظ�����ѭ�������Գ��������˳���q����
�˳���������Ҳ�ǲ��÷���FALSEʵ��
DBG_CONTINUE	���� t p g ��ʹ�������е��������ִ�й���û�д��󣩸ú����˳�ѭ��������DBG_CONTINUE
***************************************************************************************************************/
DWORD COperate::UserInput ( DEBUG_EVENT &DebugEvent )
{
	// 1.����Ĵ�����Ϣ
	HANDLE hThread = OpenThread ( THREAD_ALL_ACCESS, 0, m_pDbgEvt->dwThreadId );
	CONTEXT ct;
	ct.ContextFlags = CONTEXT_ALL;
	GetThreadContext ( hThread, &ct );
	ShowRegInfo ( &ct );
	// 2.����������Ϣ
	// ��!!!�쳣��ַ!!!��ʼ�����5����Ϣ����Ҫ��eip��ʼ
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
		// 			�ָ��ַ���
		/ *
		����һ��ָ�洢������ַ�����Ŀ���ַ�����
		�������ǵȴ������ԭʼ�ַ�����
		3����ȡ�ڼ��Σ�
		����4��ָ����ı�־��ʲô��������������־���ǡ� ���ո�
		* /
		//��������һ��MFC�еĺ���Ҫ��"����-����-MFC��ʹ������Ϊ�ڹ���DLL��ʹ��MFC"
		if( !AfxExtractSubString ( strSub[i], strInput, j, ' ' ) )
		{
		break;
		}
		else
		{
		if( !strSub[i].IsEmpty () )
		/ *
		��VC�У�IsEmpty()������Ա������CString::IsEmpty���������жϳ�Ա�����Ƿ�Ϊ�գ����Ϊ���򷵻�TRUE�����򷵻�FALSE��
		* /
		{
		i++;//my-Ϊ������ڶ���������׼��,�ڿռ����ֵ
		}
		}
		j++;//my-����ڶ�������
		}
		*/

		gets_s ( szCommand, MAX_PATH );
		// ����ָ�� ǰ׺  ��ַ ����/IsOnce ����(���ȿ�ʡ��)
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
		// ������ַ
		// token = address(123456)
		bhLen = strtok_s ( NULL, seps, &next_token );
		bhType = strtok_s ( NULL, seps, &next_token );
		DWORD dwAddress;
		if ( bhAddr )
		{
			dwAddress = strtol ( bhAddr, NULL, 16 );
		}
		DWORD dwOrder = dwAddress;//Ҫɾ���Ķϵ����
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
					case 'i'://ifǰ׺
					bCmdRet = CmdSetIfBp ( dwAddress, dwLen/*������ʵ��EIP��Χ*/ );
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
		//ִ������
// 		bCmdRet = pFunCmd(strSub[1], strSub[2], strSub[3], lpDebugEvent);

		if( bCmdRet == MYCONTINUE )
		{
			//Ҫ��ʾ�ĵ�ַ��0�´�������ʾ
// 			dwShowDataAddr = 0;//my-ִ��d����ʱ		g_dwShowDataAddr = dwShowAddr + 128;
// 			dwShowDisasmAddr = 0;//my-ִ��u����ʱ	g_dwShowDisasmAddr = dwShowDisasmAddr;
			return DBG_CONTINUE;			//����� g �����������������,�����ܵ�������
// 			return DBG_EXCEPTION_NOT_HANDLED;//����� g ������ܵ��ϵ㴦(�����)����int�쳣
		}
		//����ִ�й����г�����ֹ���Բ��˳�
		if( bCmdRet == FALSE )
		{
			return FALSE;
		}
	}
}


//��ʾ�Ĵ�����ֵ r
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

//��ջ��Ϣ
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
	printf ( "��ջ��ַ\t" );
	printf ( "������Ϣ\n" );

	for (int i=0;i<5;i++)
	{
		printf ( "%08X\t", ct.Esp +i*4 );
		printf ( "%08X\n", ((DWORD*)buff)[i] );
	}
	printf ( "\n=================================================================\n" );

	return TRUE;
}

/**************************************************************************************
�������쳣
���ڶϵ�Ļָ����ڸ��쳣�¼��У����Ҹ����쳣�Ļָ���Ƴ��п���ͬʱ���ֵ���������Ըú�
����Ƴ����������ֻ�ں���ĩβ���أ��д�����ʱ���������м䷵�ء�
**************************************************************************************/
DWORD COperate::OnExceptionSingleStep ( DEBUG_EVENT &DebugEvent )
{
	BOOL isDebugSetp = FALSE;
	//my-�����м�û�д���ʱisDebugSetpΪTRUE
	//�ж��Ƿ�ָ���ͨ�ϵ�
	if( isResumeInt3Bp )
	{
		list<INT3BPNODE>::iterator itInt3Bp;
		for( itInt3Bp = g_Int3BpList.begin (); itInt3Bp != g_Int3BpList.end (); itInt3Bp++ )
		{
			PINT3BPNODE pGeneralbp = &(*itInt3Bp);
			//����ΪʧЧ�����öϵ����Ҫ�ָ�
			//						   ʧЧ							����
			if( pGeneralbp->isActive == FALSE && pGeneralbp->isOnce == FALSE )
			{
				DWORD	dwOldprotect;
				DWORD	dwRetCount;
				byte	int3 = 0xCC;
				if( !VirtualProtectEx ( m_pi.hProcess, pGeneralbp->lpBpAddr, 1, PAGE_READWRITE, &dwOldprotect ) )
				{
					printf ( "�����쳣�����ڳ���" );
					return FALSE;
				}
				//��ԭcc�ϵ�
				if( !WriteProcessMemory ( m_pi.hProcess, pGeneralbp->lpBpAddr, &int3, 1, &dwRetCount ) )
				{
					printf ( "�����쳣�����ڳ���" );
					VirtualProtectEx ( m_pi.hProcess, pGeneralbp->lpBpAddr, 1, dwOldprotect, &dwRetCount );
					return FALSE;
				}
				//��ԭ��������
				if( !VirtualProtectEx ( m_pi.hProcess, pGeneralbp->lpBpAddr, 1, dwOldprotect, &dwRetCount ) )
				{
					printf ( "�����쳣�����ڳ���" );
					return FALSE;
				}
				pGeneralbp->isActive = TRUE;
			}
		}

		//�ָ���־ʧЧ
		isResumeInt3Bp = FALSE;
		isDebugSetp = TRUE;
	}

	//�ж��Ƿ�ָ��ڴ�ϵ�
	if( isResumeMemBp )
	{
		DWORD	dwOldprotect;

		map<DWORD, DWORD>::iterator itMemPag;
		for( itMemPag = g_MemPagMap.begin (); itMemPag != g_MemPagMap.end (); itMemPag++ )
		{
			if( !VirtualProtectEx ( m_pi.hProcess, (LPVOID)itMemPag->first, 1, PAGE_NOACCESS, &dwOldprotect ) )
			{
				printf ( "�������쳣����!" );
				return FALSE;
			}
		}
		//�ָ���־ʧЧ
		isResumeMemBp = FALSE;
		isDebugSetp = TRUE;
	}


	//////////////////////////////////////////////////////////////////////////
	//����nDrNumӲ���Ĵ���
	HANDLE hThread = OpenThread ( THREAD_ALL_ACCESS, NULL, m_pDbgEvt->dwThreadId );
	CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };
	ct.ContextFlags = CONTEXT_ALL;// ָ��Ҫ��ȡ��д�Ĵ�������Ϣ������Ҫ
	GetThreadContext ( hThread, &ct );//��ȡ�̻߳�����
// 	PDBG_REG7 pDR7 = (PDBG_REG7)&ct.Dr7;

	//�ж��Ƿ�ָ�Ӳ���ϵ�
	if( isResumeHardBp )
	{
		for( int i = 0; i < 4; i++ )
		{
			//�ϵ㴦�ڼ���״̬����Ҫ�ָ���־Ϊ��ָ�Ӳ���ϵ�
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

		//�ָ���־ʧЧ
		isResumeHardBp = FALSE;
		isDebugSetp = TRUE;
	}

	//�ж��Ƿ�ΪӲ���ϵ��쳣
	DWORD dwHardRet = ct.Dr6 & 0xF;
	/*
	my-��λ��
	Ϊ��ֻ��1,2,4,8������ÿ��ֻ��һ��Ӳ���ϵ㴦,
	ֻ���������,�ֱ��Ӧ��lpContext->Dr6�е�ֵҲ����4��?
	0001		&1111
	0010
	0100
	1000
	*/
	//ֻ��ִ��Ӳ���ϵ����Ҫ��ʱ��ԭ�ڵ����ָ�
	DWORD dwDr7 = ct.Dr7;

	if( dwHardRet )
	{
		switch( dwHardRet )
		{
			case 1:
			if( HardBp[0].isActive )
			{
				//ִ�жϵ���Ҫ�ָ�������Ӳ���ϵ㲻��Ҫ�ָ�
				if( ((dwDr7 >> 16) & 3) == 0 )//16λ��0,17λ��0����д��
				{
					//��ʱʹӲ���ϵ�ʧЧ
					HardBp[0].isResume = TRUE;
					ct.Dr7 &= 0xFFFFFFFC;//L0,G0���0
					//���õ���
					ct.EFlags |= 0x100;
					isResumeHardBp = TRUE;
				}

				//�û�����ʧЧ
				isUserStep = FALSE;
				//�û�����
				printf ( "ON 00 Hardware Breakpoint\r\n" );
				//�������Ϊ�˱�֤û�д�����ʱ�����ܴ������ͬʱ���ֵ����
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
					//��ʱʹӲ���ϵ�ʧЧ
					HardBp[1].isResume = TRUE;
					ct.Dr7 &= 0xFFFFFFF3;
					//���õ���
					ct.EFlags |= 0x100;
					isResumeHardBp = TRUE;
				}

				//�û�����ʧЧ
				isUserStep = FALSE;
				//�û�����
				printf ( "ON 01 Hardware Breakpoint\r\n" );
				//�������Ϊ�˱�֤û�д�����ʱ�����ܴ������ͬʱ���ֵ����
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
					//��ʱʹӲ���ϵ�ʧЧ
					HardBp[2].isResume = TRUE;
					ct.Dr7 &= 0xFFFFFFCF;
					//���õ���
					ct.EFlags |= 0x100;
					isResumeHardBp = TRUE;
				}

				//�û�����ʧЧ
				isUserStep = FALSE;
				//�û�����
				printf ( "ON 02 Hardware Breakpoint\r\n" );
				//�������Ϊ�˱�֤û�д�����ʱ�����ܴ������ͬʱ���ֵ����
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
					//��ʱʹӲ���ϵ�ʧЧ
					HardBp[3].isResume = TRUE;
					ct.Dr7 &= 0xFFFFFF3F;
					//���õ���
					ct.EFlags |= 0x100;
					isResumeHardBp = TRUE;
				}

				//�û�����ʧЧ
				isUserStep = FALSE;
				//�û�����
				printf ( "ON 03 Hardware Breakpoint\r\n" );
				//�������Ϊ�˱�֤û�д�����ʱ�����ܴ������ͬʱ���ֵ����
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
	//�ж��Ƿ�Ϊ�û����õ���
	if( isUserStep )
	{
		//������־ʧЧ
		isUserStep = FALSE;

		//�û�����
		printf ( "ON UserStep Breakpoint\r\n" );
		//�������Ϊ�˱�֤û�д�����ʱ�����ܴ������ͬʱ���ֵ����
		if( UserInput ( DebugEvent ) == FALSE )
		{
			return FALSE;
		}
		isDebugSetp = TRUE;
	}

	//�����м�û�д�����
	if( isDebugSetp )
	{
		//���������쳣�Ѿ�����
		return DBG_CONTINUE;
	}
	else
	{
		//�ǵ������쳣
		return DBG_EXCEPTION_NOT_HANDLED;
	}
}

//����int3�ϵ� bp �������д��󷵻�FALSE���ϲ��UserInput��⵽����������ϲ����ѭ�������Զ����FALSE�����Գ����˳�
DWORD COperate::CmdSetInt3BP ( DWORD dwAddress, BOOL IsAlways )
{
	INT3BPNODE Generalbp;

	if( !dwAddress )
	{
		DBGOUT ("%s\n", "û����������ϵ��ַ" );
		return MYERRCONTINUE;
	}

	//�жϵڶ���������Ϊ������һ���Զϵ�
	if( !IsAlways )
	{
		Generalbp.isOnce = TRUE;
	}
	else
	{
		Generalbp.isOnce = FALSE;
	}
	//�ϵ��ַת��ֵ����
// 	wchar_t	*pRet = NULL;
// 	DWORD	dwBpAddr = wcstoul ( str1, &pRet, 16 );
	//strtoul���ַ���ת�����޷��ų�������,����16����ʾ�Զ�ʶ��str1�Ǽ�����
	LPVOID	lpBpAddr = (LPVOID)dwAddress;

	//ת��ʧ��
	//��ѯ�Ƿ��Ѿ����ڸöϵ�,�������ֱ�ӷ���
// 	list<INT3BPNODE>::iterator itInt3Bp;
// 	for( itInt3Bp = g_Int3BpList.begin (); itInt3Bp != g_Int3BpList.end (); itInt3Bp++ )
// 	{
// 		if( (*itInt3Bp).lpBpAddr == lpBpAddr )
// 		{
// 			//��ͬ�Ķϵ�ֻ�����ʱ�ϵ��Ϊ���öϵ�
// 			//my-�õ����ԭ������,��ô�������öϵ���?
// 			if( Generalbp.isOnce == FALSE )
// 			{
// 				(*itInt3Bp).isOnce = FALSE;
// 			}
// 			return TRUE;
// 		}
// 	}
	//todo-my-������õĶϵ��Ƿ���Ч��ַ
	//��ѯ�õ�ַ�Ƿ�Ϊ��Ч�ڴ��ַ

// 	MEMORY_BASIC_INFORMATION mbi = { 0 };
// 	if( sizeof ( mbi ) != VirtualQueryEx ( m_pi.hProcess, lpBpAddr, &mbi, sizeof ( mbi ) ) )
// 	{
// 		printf ( "���öϵ����" );
// 		return FALSE;
// 	}
// 	//���ڴ��ַ�������öϵ�
// 	if( mbi.State != MEM_COMMIT )//MEM_COMMIT ָ���ѷ��������ڴ����ϵͳҳ�ļ���
// 	{
// 		printf ( "����Ķϵ��ַ���ڴ��ҳ\r\n" );
// 		return MYERRCONTINUE;
// 	}

	//Ϊ��ֹ�÷�ҳ���ڴ�ϵ������ø÷�ҳ������
	DWORD	dwOldprotect;
	DWORD	dwRetCount;
	byte	int3 = 0xCC;
	if( !VirtualProtectEx ( m_pi.hProcess, lpBpAddr, 1, PAGE_READWRITE, &dwOldprotect ) )
	{
		printf ( "�޸ı������Գ���\n" );
		return FALSE;
	}
	//��ȡ��ַ����ֵ����
	if( !ReadProcessMemory ( m_pi.hProcess, lpBpAddr, &(Generalbp.OldByte), 1, &dwRetCount ) )
	{
		printf ( "��ȡ��ַ��Ϣ����\n" );
		VirtualProtectEx ( m_pi.hProcess, lpBpAddr, 1, dwOldprotect, &dwRetCount );
		return FALSE;
	}
	//����cc�ϵ�
	if( !WriteProcessMemory ( m_pi.hProcess, lpBpAddr, &int3, 1, &dwRetCount ) )
	{
		printf ( "д��CC�ϵ����\n" );
		VirtualProtectEx ( m_pi.hProcess, lpBpAddr, 1, dwOldprotect, &dwRetCount );
		return FALSE;
	}
	//��ԭ��������
	if( !VirtualProtectEx ( m_pi.hProcess, lpBpAddr, 1, dwOldprotect, &dwRetCount ) )
	{
		printf ( "��ԭ�������Գ���\n" );
		return FALSE;
	}
	//���öϵ���Ϣ
	//�ϵ���Ϣ����ֵ��ֵ��ѹ������
	Generalbp.lpBpAddr = lpBpAddr;
	Generalbp.dwBpOrder = dwBpOrder++;
	Generalbp.isActive = TRUE;
	g_Int3BpList.push_back ( Generalbp );
	return TRUE;
}

//�����ϵ�
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

//��ʾint3�ϵ� bpl
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

//ɾ����ͨ�ϵ� bpc
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
			//�޸��ڴ�����
			if( !VirtualProtectEx ( m_pi.hProcess, pGeneralbp->lpBpAddr, 1, PAGE_READWRITE, &dwOldprotect ) )
			{
				printf ( "bpc�������" );
				return FALSE;
			}
			//��ԭ�ϵ�
			if( !WriteProcessMemory ( m_pi.hProcess, pGeneralbp->lpBpAddr, &(pGeneralbp->OldByte), 1, &dwRetCount ) )
			{
				printf ( "bpc�������" );
				VirtualProtectEx ( m_pi.hProcess, pGeneralbp->lpBpAddr, 1, dwOldprotect, &dwTmp );
				return FALSE;
			}
			//��ԭ��������
			if( !VirtualProtectEx ( m_pi.hProcess, pGeneralbp->lpBpAddr, 1, dwOldprotect, &dwTmp ) )
			{
				printf ( "bpc�������" );
				return FALSE;
			}
			g_Int3BpList.erase ( itInt3Bp );

			return TRUE;
		}
	}
	if( itInt3Bp == g_Int3BpList.end () )
	{
		printf ( "û���ҵ�����Ŷ�Ӧ�Ķϵ�\r\n" );
		return MYERRCONTINUE;
	}

	return FALSE;
}

//��ʾ���� help or ?
DWORD COperate::CmdShowHelp ()
{

	printf ( "================================= ���� ===================================\r\n" );
	printf ( "��� ������      ������    Ӣ��˵��        ����1    ����2    ����3        \r\n"
			 "1    ��������      t      step into       ��                             \r\n"
			 "2    ��������      p      step over       ��                             \r\n"
			 "3    ����          g      run             ��ַ����                       \r\n"
			 "--------------------------------------------------------------------------\r\n"
			 "4    �����        u      assemble        ��ַ����                       \r\n"
			 "5    ����          d      data            ��ַ����                       \r\n"
			 "6    �Ĵ���        r      register        ��                             \r\n"
			 "--------------------------------------------------------------------------\r\n"
			 "7    һ��ϵ�      bp     breakpoint      ��ַ    once(һ����)           \r\n"
			 "8    һ��ϵ��б�  bpl    bp list                                        \r\n"
			 "9   ɾ��һ��ϵ�  bpc    clear bp        ���                           \r\n"
			 "--------------------------------------------------------------------------\r\n"
			 "10   Ӳ���ϵ�      bh ��  hard bp         ��ַ     e/a/w    ����         \r\n"
			 "11   Ӳ���ϵ��б�  bhl    hard bp list                                   \r\n"
			 "12   ɾ��Ӳ���ϵ�  bhc    clear hard bp   ���                           \r\n"
			 "--------------------------------------------------------------------------\r\n"
			 "13   �ڴ�ϵ�      bm     memory bp       ��ʼ��ַ a/w      ����         \r\n"
			 "14   �ڴ�ϵ��б�  bml    Bp Memory List                                 \r\n"
			 "15   ��ҳ�ϵ��б�  bmpl   Bp Page List                                   \r\n"
			 "16   ɾ���ڴ�ϵ�  bmc    clear memory bp ���                           \r\n"
			 "--------------------------------------------------------------------------\r\n"
			 "17   �鿴ģ��      lm     List Module     ��                             \r\n"
			 "18   �鿴������	   et    ShowExportTable  ��                             \r\n"
			 "19   �鿴�����	   it    ShowImportTable  ��                             \r\n"
			 "--------------------------------------------------------------------------\r\n"
			 "20   �˳�          q      quit            ��                             \r\n"
			 "21   ����          ?      help            ��                             \r\n"
			 "22   ����          cls    CLS             ��                             \r\n" );
	printf ( "===========================================================================\r\n" );
	return TRUE;
}


//���� t �����Զ����MYCONTINUE���ϲ��UserInput����ֵ�˳�����ѭ��ʹ���Գ����������
DWORD COperate::CmdStepInto ()
{
	// ���õ���
	HANDLE hThread = OpenThread ( THREAD_ALL_ACCESS, NULL, m_pDbgEvt->dwThreadId );
	CONTEXT ct = {};
	ct.ContextFlags = CONTEXT_ALL;// ָ��Ҫ��ȡ��д�Ĵ�������Ϣ������Ҫ
	GetThreadContext ( hThread, &ct );
	PEFLAGS pElg = (PEFLAGS)&ct.EFlags;
	PDBG_REG6 pDr6 = (PDBG_REG6)&ct.Dr6;
	pElg->TF = 1;
	SetThreadContext ( hThread, &ct );
	CloseHandle ( hThread );
// 	context.EFlags |= 0x100;
	//my-��TFλ����Ϊ1���������ж�
	//�����û�����
	isUserStep = TRUE;

	return MYCONTINUE;
}

// �������� p �����Զ����MYCONTINUE
DWORD COperate::CmdStepOver ( DEBUG_EVENT &DebugEvent )
{

	//�����ָ�����Ϊcall��callָ����һ��������ʱ�ϵ㣬����ָ���õ���
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
	//�ָ��ַ���
	if( !AfxExtractSubString ( szSub, szDisasm, 0, ' ' ) )
	{
		printf ( "������������!\n" );
		return FALSE;
	}
	if( szSub == "call" )
	{
		//��һ��ָ��������ʱ�ϵ�//my-call����β��������ʱ�ϵ�
		dwAddr += dwCodeSize;
// 		szBpAddr.Format ( L"%08X", dwAddr );
		if( CmdSetInt3BP ( dwAddr, FALSE ) != TRUE )
		{
			return FALSE;
		}
	}
	else
	{
		//������ǵ�t-F7����ִ��
		CmdStepInto ();
// 		context.EFlags |= 0x100;
// 		//�����û�����
// 		isUserStep = TRUE;
	}

	return MYCONTINUE;
}


/***************************************************************
�����һ������
���ظ������볤�ȣ��������0��ʾ����ִ�д���
szDisasm	����һ�������Ľ��
szDisasmAll	����һ����������ϸ���������ַ��api��
****************************************************************/
DWORD COperate::DisasmOneCode ( HANDLE hProcess, LPVOID pCodeAddr, CString *szDisasm )
{
	byte	szCodeBuf[20];		//��������ݻ�����
	// 	char	szASM[128];			//������ַ���������
	// 	char	szOpcode[64] = { 0 };	//�����֮����ָ�������
	WCHAR	szOpcode[64] = { 0 };	//�����֮����ָ�������
	UINT	nCodeSize;			//����൥��ָ���  

	DWORD	dwFirstProtect;		//�ڴ��ҳ��������//my-��һ��λ��
	DWORD	dwSecondProtect;	//�ڴ��ҳ��������//my-�ڶ���λ��
	DWORD	dwTmp;//my-temp�ų�������
	DWORD	dwReadCodeCount;	//ʵ�ʶ�ȡ�Ĵ�������ݳ���
	DWORD	*pdwAddr = NULL;	//����Ǽ��call��ָ��Ϊ���callָ��api����ַָ��

	//��ֹ���ڴ�ϵ��޸��ڴ�����
	VirtualProtectEx ( m_pi.hProcess, pCodeAddr, 1, PAGE_READWRITE, &dwFirstProtect );

	/*
	VirtualProtectEx�������Ըı����ض��������ڴ�����ı�������
	����ԭ�Σ�
	BOOL VirtualProtectEx(
	HANDLE m_pi.hProcess, // Ҫ�޸��ڴ�Ľ��̾��
	LPVOID lpAddress, // Ҫ�޸��ڴ����ʼ��ַ
	DWORD dwSize, // ҳ�����С
	DWORD flNewProtect, // �·��ʷ�ʽ
	PDWORD lpflOldProtect // ԭ���ʷ�ʽ ���ڱ���ı�ǰ�ı������� ������Ҫ��ַ
	);
	*/

	//my-Ϊ��szCodeBuf��20,����ֻ�Ǵ���ʵ��ʵ�ʳ��ȵ�ֵ����
	VirtualProtectEx ( m_pi.hProcess, (LPVOID)((DWORD)pCodeAddr + sizeof ( szCodeBuf ) - 1), 1, PAGE_READWRITE, &dwSecondProtect );
	//my-��ȡԶ�̽����ڴ�����,��ȡ�����ʵ�ʳ���
	if( !ReadProcessMemory ( m_pi.hProcess, pCodeAddr, szCodeBuf, sizeof ( szCodeBuf ), &dwReadCodeCount ) )
	{
		printf ( "ShowDisasmOneCode�����ڲ�����!" );
		//my-�������ѱ����������¸Ļ�ȥ���˳�
		VirtualProtectEx ( m_pi.hProcess, (LPVOID)((DWORD)pCodeAddr + sizeof ( szCodeBuf ) - 1), 1, dwSecondProtect, &dwTmp );
		VirtualProtectEx ( m_pi.hProcess, pCodeAddr, 1, dwFirstProtect, &dwTmp );
		return FALSE;
	}

	//��ԭ�ڴ����ԣ��Ȼ�ԭ���ڶ�������ҳ���п��ܵڶ��͵�һ��ͬһ����ҳ��
	VirtualProtectEx ( m_pi.hProcess, (LPVOID)((DWORD)pCodeAddr + sizeof ( szCodeBuf ) - 1), 1, dwSecondProtect, &dwTmp );
	VirtualProtectEx ( m_pi.hProcess, pCodeAddr, 1, dwFirstProtect, &dwTmp );

	//����Ƿ������õĶϵ㣬����л�ԭΪԭֵ
	for( int i = 0; i < dwReadCodeCount; i++ )
	{
		if( szCodeBuf[i] == 0xCC )//�����
		{
			list<INT3BPNODE>::iterator itInt3Bp;
			//my-���д����Ҳ���ԭ��,��ϸ������ͷ���Ƿ�û������
			for( itInt3Bp = g_Int3BpList.begin (); itInt3Bp != g_Int3BpList.end (); itInt3Bp++ )
			{
				PINT3BPNODE pINT3BPNODE = &(*itInt3Bp);
				//���������ҵ��ϵ��Ӧ��,�ָ������
				if( pINT3BPNODE->lpBpAddr == (LPVOID)((DWORD)pCodeAddr + i) )
				{
					szCodeBuf[i] = pINT3BPNODE->OldByte;
				}
			}
		}
	}
	//�����
	DISASM objDiasm;
	objDiasm.EIP = (UIntPtr)szCodeBuf; // ��ʼ��ַ
	objDiasm.VirtualAddr = (UINT64)pCodeAddr;     // �����ڴ��ַ��������������ڼ����ַ��
	objDiasm.Archi = 0;                     // AI-X86
	objDiasm.Options = 0x000;                 // MASM
	// 3. ��������
	nCodeSize = Disasm ( &objDiasm );

	if( nCodeSize == -1 )
		return nCodeSize;
	// 4. ��������ת��Ϊ�ַ���
	LPWSTR lpOPCode = szOpcode;
	PBYTE  lpBuffer = szCodeBuf;
	for( UINT i = 0; i < nCodeSize; i++ )
	{
		StringCbPrintf ( lpOPCode++, 50, L"%X", *lpBuffer & 0xF0 );
		StringCbPrintf ( lpOPCode++, 50, L"%X", *lpBuffer & 0x0F );
		lpBuffer++;
	}
	// 6. ���淴������ָ��
	WCHAR szASM[50] = { 0 };
	MultiByteToWideChar ( CP_ACP, 0, objDiasm.CompleteInstr, -1, szASM, _countof ( szASM ) );
	// 	StringCchCopy(pASM, 50, szASM);
// 	wprintf_s(L"0x%08x %-16s%s\n", pCodeAddr, szOpcode, szASM);
	(*szDisasm) = szASM;
	//szOpcodeû�и�ֵ����ʶ���CC
	// 	wprintf_s(L"0x%08x %-16s%s\n", (int)objDiasm.VirtualAddr, szOpcode, szASM);
	return nCodeSize;
}

//ִ�� g �����Զ����MYCONTINUE
DWORD COperate::CmdRun (  )
{

// 	DWORD dwSetBpRet;
// 	if( str1.IsEmpty () )
		/*
		my-���go����û�е�ַ,ֱ�ӷ���,����û���쳣����,����ͻ�һֱ��
		�����е�ַ,����ܵ���ַ����������ϵ�
		*/
// 	{
		return MYCONTINUE;
// 	}
// 	//�������ַ��������ʱ�ϵ�
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


//�������� u//my-һ����ʾ��������
DWORD COperate::CmdShowAsmCode ( DWORD dwAddr, DEBUG_EVENT &DebugEvent )
{
// 	DWORD	m_dwShowDisasmAddr;
	DWORD	m_dwCodeSize = 0;

// 	if( str1.IsEmpty () )
// 	{
// 		if( dwShowDisasmAddr )
// 		{
// 			//my-��ִ�й�"u-��"����ִ��"u-��"�����
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
		//ת������
// 		wchar_t	*pRet = NULL;
// 		m_dwShowDisasmAddr = wcstoul ( str1, &pRet, 16 );
// 		//ת��ʧ��
// 		if( *pRet != NULL )
// 		{
// 			printf ( "�����ַ�������\r\n" );
// 			return MYERRCONTINUE;
// 		}
// 	}
	//���÷������ʾ��������
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


//��ʾ�ڴ����� d
DWORD COperate::CmdShowData ( DWORD dwAddr, DEBUG_EVENT &DebugEvent )
{
	byte	dbBuf[128] = { 0 };
	byte	dbFlg[128] = { 0 };	//0��ʾ��ȡ�ɹ���1��ʾ��ȡʧ��
	DWORD	m_dwFirstProtect;
	DWORD	m_dwSecondProtect;
	DWORD	m_dwTmp;
	DWORD	m_dwShowAddr;

// 	if( str1.IsEmpty () )
// 	{//���ǿյ�,û����ַ
// 		if( dwShowDataAddr )
// 		{
// 			//my-��ִ�й�"d-��"����ִ��"d-��"�����
// 			m_dwShowAddr = dwShowDataAddr;
// 		}
// 		else
// 		{
// 			m_dwShowAddr = (DWORD)DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
// 		}
// 	}
// 	else
// 	{
// 		//ת������
// 		wchar_t	*pRet = NULL;
// 		m_dwShowAddr = wcstoul ( str1, &pRet, 16 );
// 		//ת��ʧ��
// 		if( *pRet != NULL )
// 		{
// 			printf ( "���ݵ�ַ�������\r\n" );
// 			return MYERRCONTINUE;
// 		}
// 	}
	//�޸��ڴ�����
	VirtualProtectEx ( m_pi.hProcess, (LPVOID)dwAddr, 1, PAGE_READWRITE, &m_dwFirstProtect );
	VirtualProtectEx ( m_pi.hProcess, (LPVOID)(dwAddr + 128 - 1), 1, PAGE_READWRITE, &m_dwSecondProtect );
	//���ڴ�
	for( int i = 0; i < 128; i++ )
	{
		if( !ReadProcessMemory ( m_pi.hProcess, (LPVOID)(dwAddr + i), dbBuf + i, 1, &m_dwTmp ) )
		{//my-���ʧ��,��������
			dbFlg[i] = 1;
		}
	}
	//my-128=16*8,128�����Ƕ���ʾ����

	//��ʾ����
	for( int i = 0; i < 8; i++ )//8����ʾ8��
	{
		printf ( "%p:  ", dwAddr + 0x10 * i );//��ַ��16ƫ��-ÿ�е�ַ
		for( int j = 0; j < 16; j++ )//my-һ����ʾ16��16��������-HEX����
		{
			if( dbFlg[i * 0x10 + j] == 1 )
			{//my-�ڼ��еڼ���
				printf ( "%s ", "??" );
			}
			else
			{
				printf ( "%0.2X ", dbBuf[i * 0x10 + j] );
			}
		}
		for( int j = 0; j < 16; j++ )//my-һ����ʾ-UNICODE����
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

	//��ԭ�ڴ����Դ�����ͬһ��ҳ������Ȼ�ԭ�ڶ�����ҳ����
	VirtualProtectEx ( m_pi.hProcess, (LPVOID)(dwAddr + 128), 1, m_dwSecondProtect, &m_dwTmp );
	VirtualProtectEx ( m_pi.hProcess, (LPVOID)dwAddr, 1, m_dwFirstProtect, &m_dwTmp );

// 	dwShowDataAddr = m_dwShowAddr + 128;
	return TRUE;
}


/************************************************************************
����Ӳ���ϵ� bh
1 ��δ��ʹ�õ�Ӳ���ϵ�Ĵ�����Dr0-Dr3�����Ѷϵ��ַ����üĴ���
2 ����Dr7��Ӧ��GX��LXλΪ1�����磺�ϵ�������Dr0��������Dr7��G0��L0λΪ1��
3 ����Dr7��Ӧ�Ķϵ�����λ��R/W0��R/W3����֮һ��Ϊִ�С�д������
4 ����Dr7��Ӧ�Ķϵ㳤��λ��LEN0��LEN3����֮һ��Ϊ1��2��4�ֽ�
ɾ���ϵ�
��Dr7��Ӧ��GX��LXλ����Ϊ0����ȫ����Ϊ0��
************************************************************************/
DWORD COperate::CmdSetHardBP ( DWORD dwAddr, DWORD dwLen, CHAR *pType)
{
	LPVOID	lpBpAddr = (LPVOID)dwAddr;
	if( !((*pType == 'a') || (*pType == 'w') || (*pType == 'e')) )
	{
		printf ( "Ӳ���ϵ������������\r\n" );
		return MYERRCONTINUE;
	}
	if( !((dwLen == 1) || (dwLen == 2) || (dwLen == 4)) )
	{
		printf ( "Ӳ���ϵ㳤���������\r\n" );
		return MYERRCONTINUE;
	}
	//Ҫ���öϵ�ĵ�ַ�ڴ��Ƿ���Ч
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	if( sizeof ( mbi ) != VirtualQueryEx ( m_pi.hProcess, lpBpAddr, &mbi, sizeof ( mbi ) ) )
	{
		printf ( "����Ӳ���ϵ����" );
		return FALSE;
	}
	//���ڴ��ַ�������öϵ�
	if( mbi.State != MEM_COMMIT )
	{
		printf ( "����Ķϵ��ַ���ڴ��ҳ\r\n" );
		return MYERRCONTINUE;
	}
	//���Ӳ���ϵ�����
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
		//Ӳ��ִ�жϵ㳤���Զ�����Ϊ1
		dwLen = 1;
		enuRwe = EXECUTE;
	}
	//����Ƿ��Ѿ����ڸöϵ�
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
	//�Ƿ��мĴ���
	int nDrNum = -1;
	for( int i = 0; i < 4; i++ )
	{
		/*
		my-����ĸ��Ĵ���,�Ǹ�isActive��FALSE,�ͰѶϵ���Ϣ���ڸõ�
		*/
		if( HardBp[i].isActive == FALSE )
		{
			nDrNum = i;
			break;
		}
	}
	if( nDrNum == -1 )
	{
		printf ( "�������ø���Ӳ���ϵ�\r\n" );
		return FALSE;
	}
	//����g_HardBp[nDrNum]
	HardBp[nDrNum].dwBpLen = dwLen;
	HardBp[nDrNum].dwBpOrder = nDrNum;
	HardBp[nDrNum].enuBpRWE = enuRwe;
	HardBp[nDrNum].isActive = TRUE;
	HardBp[nDrNum].isResume = FALSE;
	HardBp[nDrNum].lpBpAddr = lpBpAddr;

	//����nDrNumӲ���Ĵ���
	HANDLE hThread = OpenThread ( THREAD_ALL_ACCESS, NULL, m_pDbgEvt->dwThreadId );
	CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };
	ct.ContextFlags = CONTEXT_ALL;// ָ��Ҫ��ȡ��д�Ĵ�������Ϣ������Ҫ
	GetThreadContext ( hThread, &ct );//��ȡ�̻߳�����
	PDBG_REG7 pDR7 = (PDBG_REG7)&ct.Dr7;

	switch( nDrNum )
	{
		case 0:
		{
			ct.Dr0 = (DWORD)HardBp[nDrNum].lpBpAddr;
// 			context.Dr7 |= 1;
			pDR7->L0 = 1;
// 			context.Dr7 &= 0xFFF0FFFF;		//16��17��18��19λ��0
			pDR7->RW0 = 0;
			pDR7->LEN0 = 0;
			//LEN ��������									//my-���洢λ�ô���ֵ1=��1��λ��,��0��0��λ��
			switch( HardBp[nDrNum].dwBpLen )
			{
				case 1:
				break;
				case 2:
// 				context.Dr7 |= 0x00040000;	//18λ��1
				pDR7->LEN0 = 1;
				break;
				case 4:
// 				context.Dr7 |= 0x000C0000;	//18,19λͬʱ��1
				pDR7->LEN0 = 3;
				break;
			}
			//R/W ��������
			switch( HardBp[nDrNum].enuBpRWE )
			{
				case EXECUTE:
				break;
				case WRITE:
// 				context.Dr7 |= 0x00010000;	//16λ��1
				pDR7->RW0 = 1;
				break;
				case ACCESS:
// 				context.Dr7 |= 0x00030000;	//16,17λͬʱ��1
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
// 			context.Dr7 &= 0xFF0FFFFF;		//20��21��22��23λ��0
			pDR7->RW1 = 0;
			pDR7->LEN1 = 0;
			//LEN ��������
			switch( HardBp[nDrNum].dwBpLen )
			{
				case 1:
				break;
				case 2:
// 				p.Dr7 |= 0x00400000;	//22λ��1
				pDR7->LEN1 = 1;
				break;
				case 4:
// 				context.Dr7 |= 0x00C00000;	//22,23λͬʱ��1
				pDR7->LEN1 = 3;
				break;
			}
			//R/W ��������
			switch( HardBp[nDrNum].enuBpRWE )
			{
				case EXECUTE:
				break;
				case WRITE:
// 				context.Dr7 |= 0x00100000;	//20λ��1
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
// 			context.Dr7 &= 0xF0FFFFFF;		//24��25��26��27λ��0
			pDR7->RW2 = 0;
			pDR7->LEN2 = 0;
			//LEN ��������
			switch( HardBp[nDrNum].dwBpLen )
			{
				case 1:
				break;
				case 2:
// 				context.Dr7 |= 0x04000000;	//26λ��1
				pDR7->LEN2 = 1;
				break;
				case 4:
				pDR7->LEN2 = 3;
				break;
			}
			//R/W ��������
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

// 			context.Dr7 &= 0x0FFFFFFF;		//28��29��30��31λ��0
			pDR7->RW3 = 0;
			pDR7->LEN3 = 0;
			//LEN ��������
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
			//R/W ��������
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


// ��ʾӲ���ϵ� bhl
DWORD COperate::CmdShowHardBPList ()
{
	HANDLE hThread = OpenThread ( THREAD_ALL_ACCESS, NULL, m_pDbgEvt->dwThreadId );
	CONTEXT ct = {};
	ct.ContextFlags = CONTEXT_ALL;// ָ��Ҫ��ȡ��д�Ĵ�������Ϣ������Ҫ
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
			//��ַ���
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
			//�������
			//my-����16+i*4λ ����11��λ��
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
			//�������
			//my-����18+i*4λ ����11��λ��
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


//ɾ��Ӳ���ϵ� bhc
DWORD COperate::CmdDelHardBP ( DWORD dwOrder )
{
	HANDLE hThread = OpenThread ( THREAD_ALL_ACCESS, NULL, m_pDbgEvt->dwThreadId );
	CONTEXT ct = {};
	ct.ContextFlags = CONTEXT_ALL;// ָ��Ҫ��ȡ��д�Ĵ�������Ϣ������Ҫ
	GetThreadContext ( hThread, &ct );
	// 	PDBG_REG7 pDr7 = (PDBG_REG7)&ct.Dr7;
	CloseHandle ( hThread );


	if( dwOrder < 0 || dwOrder >3 )
	{
		printf ( "����������\r\n" );
		return MYERRCONTINUE;
	}
	//ɾ��Ӳ���ϵ�
	HardBp[dwOrder].isActive = FALSE;
	//���üĴ�����־λʹ�ϵ�ʧЧ
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


//�����ڴ�ϵ� bm
DWORD COperate::CmdSetMemBP ( DWORD dwAddr, DWORD dwLen, CHAR *pType )
{
	BP_RWE	enuMemBpRwe;		//�ϵ�����
	LPVOID	lpBpAddr = (LPVOID)dwAddr;
	if( dwLen == 0 )
	{
		printf ( "�ϵ㳤���������\r\n" );
		return MYERRCONTINUE;
	}
	if( !((*pType == 'a') || (*pType == 'w')) )
	{
		printf ( "�ϵ������������\r\n" );
		return MYERRCONTINUE;
	}
	//��ȡ�ϵ�����
	if( *pType == 'w' )
	{
		enuMemBpRwe = WRITE;
	}
	else
	{
		enuMemBpRwe = ACCESS;
	}
	//�ڴ�ϵ㳤�Ȳ��ܴ���һ����ҳ
	if( dwLen > 0x1000 )
	{
		printf ( "�ϵ㳤�Ȳ��ܴ���һ����ҳ��С\r\n" );
		return MYERRCONTINUE;
	}
	//Ҫ���õ��ڴ�ϵ��Ƿ�������ڴ��ҳ��������������Զ���Ϊ�����ڴ�ϵ�
	if( (dwAddr & 0xFFFFF000) == ((dwAddr + dwLen) & 0xFFFFF000) )
	{//				 my- 0x1000֮�����
		if( !SetMemBpOnOnePag ( lpBpAddr, dwLen, enuMemBpRwe ) )
		{
			return FALSE;
		}
	}
	else
	{
		DWORD dwSecondPagStart = (dwAddr + dwLen) & 0xFFFFF000;
		//my-���0xFFFF1XXX
		DWORD dwFirstLen = dwSecondPagStart - dwAddr;
		//my-0xFFFF1000-0xFFFFFXXX
		DWORD dwSecondLen = dwLen - dwFirstLen;

		if( !SetMemBpOnOnePag ( lpBpAddr, dwFirstLen, enuMemBpRwe ) )
		{//my-���õ�һҳ�ڴ�ϵ�
			return FALSE;
		}

		if( !SetMemBpOnOnePag ( (LPVOID)dwSecondPagStart, dwSecondLen, enuMemBpRwe ) )
		{//my-���õڶ�ҳ�ڴ�ϵ�
			return FALSE;
		}
	}

	return TRUE;
}

//������һ����ҳ���ڵ��ڴ�ϵ�
DWORD COperate::SetMemBpOnOnePag ( LPVOID lpBpAddr, DWORD dwLen, BP_RWE enuMemBpRwe )
{
	DWORD	dwMemBpAddr = (DWORD)lpBpAddr;				//�ڴ�ϵ��ַ
	DWORD	dwMemBpPagAddr = dwMemBpAddr & 0xFFFFF000;	//�ڴ�ϵ����ڷ�ҳ��ʼ��ַ
	BPNODE	MemBpNode;		//�ڴ�ϵ�ڵ�
	//����ڴ��ҳ����Ч��
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	if( sizeof ( mbi ) != VirtualQueryEx ( m_pi.hProcess, lpBpAddr, &mbi, sizeof ( mbi ) ) )
	{//virtualQueryEx��ѯ���������ڴ�״̬
		printf ( "SetMemBpOnOnePag��������!" );
		return FALSE;
	}
	//���ڴ��ַ�������öϵ�
	if( mbi.State != MEM_COMMIT )
	{
		printf ( "����Ķϵ��ַ���ڴ��ҳ\r\n" );
		return MYERRCONTINUE;
	}

	//����ǲ����Ѿ����ڵ��ڴ�ϵ�,�ڴ�ϵ㲻ͬ������,���ص������Ѿ�����
	list<BPNODE>::iterator itMemBp;
	for( itMemBp = g_MemBplist.begin (); itMemBp != g_MemBplist.end (); itMemBp++ )
	{
		PBPNODE pMemBp = &(*itMemBp);

		//�Ѵ����ڴ�ϵ㿪ʼ��ַ
		LPVOID lpMemBpAddr = pMemBp->lpBpAddr;
		//�Ѵ����ڴ�ϵ������ַ
		LPVOID lpMemBpAddrEnd = (LPVOID)((DWORD)lpMemBpAddr + pMemBp->dwBpLen - 1);

		//���Ѿ����ڵĶϵ��ص�
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
			printf ( "�������ڴ�ϵ����ص�\r\n" );
			return MYERRCONTINUE;
		}
	}

	//�������ڴ�ϵ� �жϸöϵ����ڷ�ҳ�Ƿ��Ѿ������ڴ�ϵ�
	DWORD dwOldProtect = g_MemPagMap[dwMemBpPagAddr];
	//�öϵ����ڷ�ҳ�����������ϵ����ø÷�ҳ����
	if( dwOldProtect == 0 )
	{
		if( !VirtualProtectEx ( m_pi.hProcess, lpBpAddr, 1, PAGE_NOACCESS, &dwOldProtect ) )
		{
			printf ( "SetMemBpOnOnePag��������!" );
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


//��ʾ�ڴ�ϵ� bml
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

//��ʾ��ҳ�ϵ��б� bmpl
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
						map��ģ�壬һ��map����key��value����ֵ��������������������map<int, int> m_map�ı�������ʾ������Ķ�����
						m_map->first����ȡ��keyֵ��m_map->second����ȡ��valueֵ��
						map�Զ�����keyֵ���������У�key��ֵ�����޸ģ������޸�value��ֵ�����Ƶ�д����
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

//ɾ���ڴ�ϵ� bmc
DWORD COperate::CmdDelMemBP ( DWORD dwOrder )
{
	DWORD	dwDelMemPagAddr;	//��ɾ���ڴ�ڵ���ڴ��ҳ��ʼ��ַ
	DWORD	dwTmp;
// 	if( str1.IsEmpty () )
// 	{
// 		printf ( "��������ȱ�ٲ���\r\n" );
// 		return MYERRCONTINUE;
// 	}
// 	//ת��
// 	wchar_t	*pRet = NULL;
// 	DWORD	dwOrder = wcstoul ( str1, &pRet, 10 );
// 	//ת��ʧ��
// 	if( *pRet != NULL )
// 	{
// 		printf ( "Ҫɾ���Ķϵ�����������\r\n" );
// 		return MYERRCONTINUE;
// 	}

	//ɾ���ڴ�ϵ��б��еĽڵ�
	list<BPNODE>::iterator itMemBp;
	for( itMemBp = g_MemBplist.begin (); itMemBp != g_MemBplist.end (); itMemBp++ )
	{
		//�ҵ��˸ýڵ�
		PBPNODE pMemBpNode = &(*itMemBp);
		if( pMemBpNode->dwBpOrder == dwOrder )
		{
			//����ɾ���ڴ�ڵ���ڴ��ҳ��ʼ��ַ
			dwDelMemPagAddr = (DWORD)pMemBpNode->lpBpAddr & 0xFFFFF000;
			//ɾ���ڵ�
			g_MemBplist.erase ( itMemBp );
			//���²��Ҷϵ������Ƿ��д��ڸ��ڴ�ҳ��Ķϵ�
			for( itMemBp = g_MemBplist.begin (); itMemBp != g_MemBplist.end (); itMemBp++ )
			{
				pMemBpNode = &(*itMemBp);
				if( ((DWORD)(pMemBpNode->lpBpAddr) & 0xFFFFF000) == dwDelMemPagAddr )
				{
					break;
				}
			}
			//���ڴ��ҳ�Ѿ������������ڴ�ϵ�
			if( itMemBp == g_MemBplist.end () )
			{
				//�ڴ��ҳ��ָ����ڴ��ҳ���Բ��ڱ���ɾ���÷�ҳ��¼
				DWORD dwOldProtect = g_MemPagMap[dwDelMemPagAddr];
				if( dwOldProtect )
				{
					//�ָ��ڴ�����
					if( !VirtualProtectEx ( m_pi.hProcess, (LPVOID)dwDelMemPagAddr, 1, dwOldProtect, &dwTmp ) )
					{
						printf ( "bmc�������" );
						return FALSE;
					}
					//ɾ����ҳ��¼
					map<DWORD, DWORD>::iterator itMemPag = g_MemPagMap.find ( dwDelMemPagAddr );
					g_MemPagMap.erase ( itMemPag );
				}

				return TRUE;
			}
			//�÷�ҳ���������ڴ�ϵ�
			else
			{
				return TRUE;
			}
		}
	}

	printf ( "û���ҵ�����Ŷ�Ӧ���ڴ�ϵ�\r\n" );
	return MYERRCONTINUE;
}

//��������쳣
DWORD COperate::OnExceptionAccess ( DEBUG_EVENT &DebugEvent )
{
	DWORD	dwAccessFlg = DebugEvent.u.Exception.ExceptionRecord.ExceptionInformation[0];
	DWORD	dwAccessAddr = DebugEvent.u.Exception.ExceptionRecord.ExceptionInformation[1];
	DWORD	dwAccessPagAddr = dwAccessAddr & 0xFFFFF000;
	DWORD	dwTmp;

	// 	printf("Addr:%p Flg:%p\r\n",dwAccessAddr,dwAccessFlg);

	//�ж��ǲ��ǵ��������õ��ڴ�ϵ㣬�����ж��Ƿ����з�ҳ
	DWORD dwOldProtect = g_MemPagMap[dwAccessPagAddr];
	//�����ڴ��ҳ���ڴ�ϵ�
	if( dwOldProtect )
	{
		//��ʱ��ԭ�÷�ҳ�ڴ�����
		if( !VirtualProtectEx ( m_pi.hProcess, (LPVOID)dwAccessAddr, 1, dwOldProtect, &dwTmp ) )
		{
			printf ( "��������쳣����!" );
			return FALSE;
		}
		//���ûָ��ڴ�ϵ��־
		isResumeMemBp = TRUE;
		// ����1������
		HANDLE hThread = OpenThread ( THREAD_ALL_ACCESS, NULL, m_pDbgEvt->dwThreadId );
		CONTEXT ct = {};
		ct.ContextFlags = CONTEXT_ALL;// ָ��Ҫ��ȡ��д�Ĵ�������Ϣ������Ҫ
		GetThreadContext ( hThread, &ct );
		PEFLAGS pElg = (PEFLAGS)&ct.EFlags;
		pElg->TF = 1;
		SetThreadContext ( hThread, &ct );
		CloseHandle ( hThread );

		//�����ж��Ƿ������ڴ�ϵ�
		list<BPNODE>::iterator itMemBp;
		for( itMemBp = g_MemBplist.begin (); itMemBp != g_MemBplist.end (); itMemBp++ )
		{
			PBPNODE pMemBpNode = &(*itMemBp);
			DWORD dwMemBpAddr = (DWORD)pMemBpNode->lpBpAddr;

			//���ʵ�ַ���з��ʶϵ㷶Χ�ϵ�����Ϊ���ʼ����жϵ�
			if( (dwAccessAddr >= dwMemBpAddr) && (dwAccessAddr < dwMemBpAddr + pMemBpNode->dwBpLen)
				&& (pMemBpNode->enuBpRWE == ACCESS) )
			{
				break;
			}
			//���ʵ�ַ���з��ʶϵ㷶Χ�����쳣Ϊд���쳣������д��ϵ�
			if( (dwAccessAddr >= dwMemBpAddr) && (dwAccessAddr < dwMemBpAddr + pMemBpNode->dwBpLen)
				&& (dwAccessFlg == 1) && (pMemBpNode->enuBpRWE == WRITE) )
			{
				break;
			}
		}
		//���е��������õ��ڴ�ϵ㣬��ʱ���û�����
		if( itMemBp != g_MemBplist.end () )
		{
			//�û��������
			isUserStep = FALSE;
			//�û�����
			printf ( "ON Memory Breakpoint\r\n" );
			return UserInput ( DebugEvent );
		}

		//�ϵ����ڷ�ҳ���ڴ�ϵ㣬����û�������û���ַ
		return DBG_CONTINUE;
	}

	//���ڷ�ҳû���ڴ�ϵ�
	return DBG_EXCEPTION_NOT_HANDLED;
}

//��ʾģ�� lm
DWORD COperate::CmdShowMod ( DEBUG_EVENT &DebugEvent )
{
	if( GetCurrentModules ( DebugEvent ) == FALSE )
	{
		return FALSE;
	}
	//��ʾģ����Ϣ
	printf ( "Base      Size      Entry     Name          Path    \r\n" );
	list<DLLNODE>::iterator itDll;
	for( itDll = DllList.begin (); itDll != DllList.end (); itDll++ )
	{
		PDLLNODE pDllNode = &(*itDll);
		printf ( "%p  %p  %p  ", pDllNode->dwModBase, pDllNode->dwModSize, pDllNode->dwModEntry );
		// 		printf("%-14s", pDllNode->szModName);//��printf����ֻ��ʾ��һ���ַ�
		wprintf_s ( L"%-14s", pDllNode->szModName );
		// 		printf(pDllNode->szModPath);
		wprintf_s ( pDllNode->szModPath );
		printf ( "\r\n" );
	}
	printf ( "\r\n" );
	printf ( "\n=================================================================\n" );

	return TRUE;
}


//��ȡ��ǰ��������ģ��
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

	//�ͷ�֮ǰ������Դ
	DllList.clear ();

	//��������ģ��
	HANDLE hmodule = CreateToolhelp32Snapshot ( TH32CS_SNAPMODULE, DebugEvent.dwProcessId );
	if( hmodule == INVALID_HANDLE_VALUE )
	{
		printf ( "����ģ��ʱ����!" );
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
			//����pe�ṹ����ڵ�
			//ע�Ͳ���Ϊxpϵͳ��������win7ϵͳ��ȡntdll��ʧ�ܣ�һ��pe pOptionalλ��ǰ1Kλ�ú������text��
			//win7���ö�ȡǰ1K���ݷ�����ڵ�λ��
			pBuffer = new byte[0x1000];
			if( pBuffer == NULL )
			{
				printf ( "����ģ��ʱ����!" );
				goto ERROR_EXIT;
			}
			VirtualProtectEx ( m_pi.hProcess, me.modBaseAddr, 1, PAGE_READWRITE, &dwOldProtect );
			if( !ReadProcessMemory ( m_pi.hProcess, me.modBaseAddr, pBuffer, 0x1000, &dwTmp ) )
			{
				printf ( "����ģ��ʱ����!" );
				goto ERROR_EXIT;
			}
			if( dwTmp != 0x1000 )
			{
				goto ERROR_EXIT;
			}
			//win7��ԭ����
			VirtualProtectEx ( m_pi.hProcess, me.modBaseAddr, 1, dwOldProtect, &dwTmp );
			//pe������ȡ��ڵ�
			pPeDos = (PIMAGE_DOS_HEADER)pBuffer;
			if( pPeDos->e_lfanew >= 0x1000 )
			{
				//��ȡ���Ȳ����޷�������ڵ�
				goto ERROR_EXIT;
			}
			pNtHeaders = (PIMAGE_NT_HEADERS)(pPeDos->e_lfanew + (UINT)pBuffer);
			pOptional = &(pNtHeaders->OptionalHeader);
			if( (UINT)pOptional - (UINT)pBuffer > 0x1000 )
			{
				//��ȡ���Ȳ����޷�������ڵ�
				goto ERROR_EXIT;
			}
			DWORD *pEntryPoint = &(pOptional->AddressOfEntryPoint);
			if( (UINT)pEntryPoint - (UINT)pBuffer > 0x1000 )
			{
				//��ȡ���Ȳ����޷�������ڵ�
				goto ERROR_EXIT;
			}

			DllNode.dwModEntry = pOptional->AddressOfEntryPoint + (DWORD)me.modBaseAddr;

			delete[] pBuffer;
			pBuffer = NULL;

			// 			//�����ģ��ռ������ҳ
			// 			dwPagCount = me.modBaseSize / 0x1000;
			// 			//����ռ䱣�������
			// 			pdwOldProtect = new DWORD[dwPagCount];
			// 			if (pdwOldProtect == NULL)
			// 			{
			// 				ShowError();
			// 				goto ERROR_EXIT;
			// 			}
			// 
			// 			//��ֹ���ڴ�ϵ���ʱ�޸��ڴ�����
			// 			for (i=0; i<dwPagCount; i++)
			// 			{
			// 				if (!VirtualProtectEx(m_pi.hProcess, me.modBaseAddr + i*0x1000, 1, PAGE_READWRITE, pdwOldProtect+i))
			// 				{
			// 					ShowError();
			// 					goto ERROR_EXIT;
			// 				}
			// 			}
			// 			//����ռ�ѶԷ�ģ��������������̿ռ�
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
			// 			//��ԭ�ڴ汣������
			// 			for (i=0; i<dwPagCount; i++)
			// 			{
			// 				VirtualProtectEx(m_pi.hProcess, me.modBaseAddr + i*0x1000, 1, pdwOldProtect[i], &dwTmp);
			// 			}
			// 			//pe������ȡ��ڵ�
			// 			pPeDos = (PIMAGE_DOS_HEADER)pBuffer;
			// 			pNtHeaders = (PIMAGE_NT_HEADERS)(pPeDos->e_lfanew + (UINT)pBuffer);
			// 			pOptional = &(pNtHeaders->OptionalHeader);
			// 
			// 			DllNode.dwModEntry = pOptional->AddressOfEntryPoint + (DWORD)me.modBaseAddr;
			// 
			// 			//ѭ�����ͷ�һ���ڵ㴦��������������Դ
			// 			delete[] pdwOldProtect;
			// 			pdwOldProtect = NULL;
			// 			delete[] pBuffer;
			// 			pBuffer = NULL;

			//���ģ����Ϣ��ģ������
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

	//win7��ԭ����
	VirtualProtectEx ( m_pi.hProcess, me.modBaseAddr, 1, dwOldProtect, &dwTmp );

	return FALSE;
}


//��ʾ������
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

//��ʾ�����
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
		printf ( "�ļ�������\n" );
		return 0;
	}

	DWORD dwFileSize = 0;
	dwFileSize = GetFileSize ( hFile, NULL );

	// 2. �����ڴ�ռ�
	BYTE* pBuf = new BYTE[dwFileSize];

	// 3. ���ļ����ݶ�ȡ���ڴ���
	DWORD dwRead = 0;
	ReadFile ( hFile,
			   pBuf,
			   dwFileSize,
			   &dwRead,
			   NULL );

	// ������������DOSͷ�ṹ��������
	// 1. �ҵ�Dosͷ
	IMAGE_DOS_HEADER* pDosHdr;// DOSͷ
	pDosHdr = (IMAGE_DOS_HEADER*)pBuf;

	// 2. �ҵ�Ntͷ
	IMAGE_NT_HEADERS* pNtHdr = NULL;
	pNtHdr = (IMAGE_NT_HEADERS*)(pDosHdr->e_lfanew + (DWORD)pDosHdr);

	// 3. �ҵ���չͷ
	IMAGE_OPTIONAL_HEADER* pOptHdr = NULL;
	pOptHdr = &pNtHdr->OptionalHeader;

	// 4. �ҵ�����Ŀ¼��
	IMAGE_DATA_DIRECTORY* pDataDir = NULL;
	pDataDir = pOptHdr->DataDirectory;
	// 5. �õ�������RVA
	DWORD dwImpRva = pDataDir[1].VirtualAddress;

	IMAGE_IMPORT_DESCRIPTOR* pImpArray;

	pImpArray = (IMAGE_IMPORT_DESCRIPTOR*)
		(RVAToOffset ( pDosHdr, dwImpRva ) + (DWORD)pDosHdr);

	// ���������ĸ�����û�������ֶμ�¼.
	// �����ı�־����һ��ȫ0��Ԫ����Ϊ��β
	while( pImpArray->Name != 0 )
	{
		// �����Dll������(Rva)
		DWORD dwNameOfs = RVAToOffset ( pDosHdr, pImpArray->Name );
		// 		char* pDllName = (char*)(dwNameOfs - (DWORD)pDosHdr);//my-ԭ�������ط�
		char* pDllName = (char*)(dwNameOfs + (DWORD)pDosHdr);

		printf ( "DLL: [%s]\n", pDllName );

		// ����,�����dll��,һ��������Щ����
		pImpArray->OriginalFirstThunk;
		// INT(��������)
		// ��¼��һ����һ��dll�е�������Щ����
		// ��Щ����Ҫô�������Ƶ���,Ҫô������ŵ����
		// ����¼��һ��������. ���������IMAGE_THUNK_DATA
		// ���͵Ľṹ������.
		// FirstThunk�����������RVA
		pImpArray->FirstThunk;
		DWORD INTOfs = RVAToOffset ( pDosHdr, pImpArray->FirstThunk );
		DWORD IATOfs = RVAToOffset ( pDosHdr, pImpArray->FirstThunk );
		IMAGE_THUNK_DATA* pInt = NULL;
		IMAGE_THUNK_DATA* pIat = NULL;
		/*
		����һ��ֻ��4���ֽڵĽṹ��.�����������е�ÿһ���ֶα����
		ֵ����һ��.
		��Щֵ, ���ǵ��뺯������Ϣ.
		���뺯������Ϣ�����²���:
		1. ���뺯�������
		2. ���뺯��������(�����п���û��)
		���Ը��ݽṹ���е��ֶε����λ�ж�, ������Ϣ
		�������Ƶ��뻹������ŵ���
		typedef struct _IMAGE_THUNK_DATA32 {
		union {
		DWORD ForwarderString;      // PBYTE
		DWORD Function;             // PDWORD
		DWORD Ordinal;
		DWORD AddressOfData;        // PIMAGE_IMPORT_BY_NAME
		} u1;
		} IMAGE_THUNK_DATA32;
		*/
		// 		pInt = (IMAGE_THUNK_DATA*)(INTOfs + pDosHdr);//my-ԭ�������ط�
		pInt = (IMAGE_THUNK_DATA*)(INTOfs + (DWORD)pDosHdr);//
		pIat = (IMAGE_THUNK_DATA*)(IATOfs + (DWORD)pDosHdr);

		while( pInt->u1.Function != 0 )
		{
			// �ж��Ƿ�������ŵ���
			if( IMAGE_SNAP_BY_ORDINAL32 ( pInt->u1.Function ) )
			{
				// ����ŷ�ʽ����
				// �ṹ�屣���ֵ��16λ����һ����������
				printf ( "\t�������[%d]\n", pInt->u1.Ordinal & 0xFFFF );
			}
			else
			{
				// �������Ƶ����]
				// �������������Ƶ����ʱ��, 
				// pInt->u1.Function �������һ��
				// rva , ���RVAָ��һ�����溯������
				// ��Ϣ�Ľṹ��
				IMAGE_IMPORT_BY_NAME* pImpName;
				DWORD dwImpNameOfs = RVAToOffset ( pDosHdr, pInt->u1.Function );
				pImpName = (IMAGE_IMPORT_BY_NAME*)
					(dwImpNameOfs + (DWORD)pDosHdr);

				printf ( "\t���:[%d],������[%s]\n",
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


//LoadDll ��ȡģ�鵼��������Ϊ����������������׼�����ǵ��������쳣����DBG_EXCEPTION_NOT_HANDLED
//��ȡ�����������г��ִ��󷵻�FALSE
//�״�LoadDll�������ڴ�ϵ㣬���֮���ٴ�LoadDll��dllû���ڴ�ϵ�Ӱ��map��ͬ��key�Ḳ��һ��
//���ڴ�ϵ�Ӱ�첻�����������ֱ�ӷ���DBG_EXCEPTION_NOT_HANDLED���Գ����������
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
	CString					szModeName;	//ģ������

	//��ȡģ���С
	pPeDos = (PIMAGE_DOS_HEADER)DebugEvent.u.LoadDll.lpBaseOfDll;
	if( !ReadProcessMemory ( m_pi.hProcess, &(pPeDos->e_lfanew), &dwe_lfanew, 4, &dwTmp ) )
		//my-��ȡԶ�̽����ڴ�����
	{
		return DBG_EXCEPTION_NOT_HANDLED;
	}
	pNtHeaders = (PIMAGE_NT_HEADERS)(dwe_lfanew + (DWORD)DebugEvent.u.LoadDll.lpBaseOfDll);
	pOptional = &(pNtHeaders->OptionalHeader);
	if( !ReadProcessMemory ( m_pi.hProcess, &(pOptional->SizeOfImage), &dwModSize, 4, &dwTmp ) )
	{
		return DBG_EXCEPTION_NOT_HANDLED;
	}
	//����ռ�
	pBuffer = new byte[dwModSize];
	if( pBuffer == NULL )
	{
		printf ( "OnLoadDll��������!" );
		return FALSE;
	}
	//��ȡ�����Խ���ģ��
	if( !ReadProcessMemory ( m_pi.hProcess, DebugEvent.u.LoadDll.lpBaseOfDll, pBuffer, dwModSize, &dwTmp ) )
	{
		return DBG_EXCEPTION_NOT_HANDLED;
	}
	if( dwTmp != dwModSize )
	{
		return DBG_EXCEPTION_NOT_HANDLED;
	}
	//����pe��ȡ������
	pPeDos = (PIMAGE_DOS_HEADER)pBuffer;
	pNtHeaders = (PIMAGE_NT_HEADERS)(pPeDos->e_lfanew + (UINT)pBuffer);
	pOptional = &(pNtHeaders->OptionalHeader);
	dwExport = pOptional->DataDirectory[0].VirtualAddress;
	//û�е�������ֱ���ͷ���Դ�˳�����ģ�����û�е�������
	if( dwExport == 0 )
	{
		delete[] pBuffer;
		return DBG_EXCEPTION_NOT_HANDLED;
	}
	pExport = (PIMAGE_EXPORT_DIRECTORY)(pBuffer + dwExport);
	//�����������ȡ������
	int*			pFunNameRvaExport = NULL;
	unsigned short*	pOrdinalExport = NULL;
	int*			pFunAddressRvaExport = NULL;
	int				FunRvaExport;
	int				FunVaExport;
	DWORD			dwModBase = (DWORD)DebugEvent.u.LoadDll.lpBaseOfDll;
	// 	CString			strFormat;

		//��ȡģ�����Ʋ����ַ����ָ�ȥ�������.dll
		// 	if (!AfxExtractSubString(szModeName, (char *)(pBuffer + pExport->Name), 0, ' '))
		// 	{
		// 		delete[] pBuffer;
		// 		return DBG_EXCEPTION_NOT_HANDLED;
		// 	}
	szModeName = (char *)(pBuffer + pExport->Name);//my-���ָ�.dll������һ��

	pFunNameRvaExport = (int*)(pBuffer + pExport->AddressOfNames);

	pOrdinalExport = (unsigned short*)(pBuffer + pExport->AddressOfNameOrdinals);

	pFunAddressRvaExport = (int*)(pBuffer + pExport->AddressOfFunctions);

	for( int i = 0; i < pExport->NumberOfNames; i++ )
	{
		//������ַRva
		FunRvaExport = pFunAddressRvaExport[*pOrdinalExport];
		//������ַVa
		FunVaExport = dwModBase + FunRvaExport;
		//�Ժ�����ַΪkey�ͺ�����һ����ӽ���map
		ApiExportNameMap[FunVaExport] = szModeName + '-' + (char *)(pBuffer + *pFunNameRvaExport);

		//ȡ��һ���������ƺ͵�ַ
		pFunNameRvaExport++;
		pOrdinalExport++;
	}

	//�ͷſռ�
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

	// 1. �������������ҵ���������
	for( int i = 0; i < dwNumberOfScn; ++i )
	{
		DWORD dwEndOfSection = pScnHdr[i].VirtualAddress + pScnHdr[i].SizeOfRawData;
		// �ж����RVA�Ƿ���һ�����εķ�Χ��
		if( dwRva >= pScnHdr[i].VirtualAddress
			&& dwRva < dwEndOfSection )
		{
			// 2. �����RVA�������ڵ�ƫ��:rva ��ȥ�׵�ַ
			DWORD dwOffset = dwRva - pScnHdr[i].VirtualAddress;
			// 3. ��������ƫ�Ƽ������ε��ļ���ʼƫ��
			return dwOffset + pScnHdr[i].PointerToRawData;
		}
	}
	return -1;
}
