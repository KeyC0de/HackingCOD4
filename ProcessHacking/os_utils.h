#pragma once

#include "winner.h"
#include <string>
#include <sstream>
#include <winternl.h>
#include <functional>
#include <optional>
#include <comdef.h>
#include "console.h"


namespace util
{

//===================================================
//	\function	printHresultErrorDescription
//	\brief  print HRESULT errors in understandable English
//	\date	2021/09/03 21:45
std::string printHresultErrorDescription( HRESULT hres );
std::wstring printHresultErrorDescriptionW( HRESULT hres );
//===================================================
//	\function	getLastErrorAsString
//	\brief  Returns the last Win32 error, in string format.
//			Returns an empty string if there is no error.
//	\date	2020/11/10 1:44
std::string getLastErrorAsString();
void getSystemVersion();
int32_t fileExistsWin32( const std::string& path );
int getCpuCount();
PPEB getPeb();
HMODULE getProcess( DWORD processId, char* processName );
HWND getWindow( const std::string& name );

std::wstring bstrToStr( const BSTR& bstr );
BSTR strToBstr( const std::wstring& str );

//===================================================
//	\function	isFileBinary
//	\brief  read 255 chars just to be sure
//	\date	2020/10/30 2:31
bool isFileBinary( const char* fname );
//===================================================
//	\function	printFile
//	\brief  for text files
//	\date	2020/10/30 2:30
#if defined _DEBUG && !defined NDEBUG
bool printFile( const char* fname );
#endif

void pinThreadToCore( HANDLE hThread, DWORD core );

void setupDetachedThreadsVector( unsigned nThreads );
void terminateDetachedThreads();
void doPeriodically( const std::function<void(void)>& f, size_t intervalMs, bool now = true );
void doAfter( const std::function<void(void)>& f, size_t intervalMs );

std::optional<DWORD> registryGetDword( HKEY hKey, const std::wstring& regName );
std::optional<std::wstring> registryGetString( HKEY hKey, const std::wstring& regName );

}// namespace util

#if defined _DEBUG && !defined NDEBUG
#	define ASSERT_RETURN_HRES_IF_FAILED( hres ) if ( FAILED ( hres ) )\
	{\
		std::ostringstream oss;\
		using namespace std::string_literals;\
		oss	<< "\n"s\
			<< __FUNCTION__\
			<< " @ line: "s\
			<< __LINE__\
			<< "\n"s\
			<< util::printHresultErrorDescription( hres )\
			<< "\n\n"s;\
		KeyConsole& console = KeyConsole::getInstance();\
		console.log( oss.str() );\
		std::system( "pause" );\
		return hres;\
	}
#else
#	define ASSERT_RETURN_HRES_IF_FAILED( hres ) (void)0;
#endif

#if defined _DEBUG && !defined NDEBUG
#	define ASSERT_HRES_IF_FAILED_( hres ) if ( FAILED ( hres ) )\
	{\
		std::ostringstream oss;\
		using namespace std::string_literals;\
		oss	<< "\n"s\
			<< __FUNCTION__\
			<< " @ line: "s\
			<< __LINE__\
			<< "\n"s\
			<< util::printHresultErrorDescription( hres )\
			<< "\n\n"s;\
		KeyConsole& console = KeyConsole::getInstance();\
		console.log( oss.str() );\
		std::system( "pause" );\
		std::exit( hres );\
	}
#else
#	define ASSERT_HRES_IF_FAILED_( hres ) (void)0;
#endif

#if defined _DEBUG && !defined NDEBUG
#	define ASSERT_HRES_IF_FAILED if ( FAILED ( hres ) )\
	{\
		std::ostringstream oss;\
		using namespace std::string_literals;\
		oss	<< "\n"s\
			<< __FUNCTION__\
			<< " @ line: "s\
			<< __LINE__\
			<< "\n"s\
			<< util::printHresultErrorDescription( hres )\
			<< "\n\n"s;\
		KeyConsole& console = KeyConsole::getInstance();\
		console.log( oss.str() );\
		std::system( "pause" );\
		std::exit( hres );\
	}
#else
#	define ASSERT_HRES_IF_FAILED (void)0;
#endif

#if defined _DEBUG && !defined NDEBUG
#	define ASSERT_HRES_IF_FAILED_MSG( msg ) if ( FAILED ( hres ) )\
	{\
		std::ostringstream oss;\
		using namespace std::string_literals;\
		oss	<< "\n"s\
			<< __FUNCTION__\
			<< " @ line: "s\
			<< __LINE__\
			<< "\n"s\
			<< util::printHresultErrorDescription( hres )\
			<< "\n"\
			<< "msg: "\
			<< msg\
			<< "\n\n"s;\
		KeyConsole& console = KeyConsole::getInstance();\
		console.log( oss.str() );\
		std::system( "pause" );\
		std::exit( hres );\
	}
#else
#	define ASSERT_HRES_IF_FAILED_MSG (void)0;
#endif


#if defined _DEBUG && !defined NDEBUG
// or call getLastErrorAsString()
#	define ASSERT_HRES_WIN32_IF_FAILED( hres ) \
	hres = HRESULT_FROM_WIN32( GetLastError() );\
	ASSERT_HRES_IF_FAILED
#else
#	define ASSERT_HRES_WIN32_IF_FAILED (void)0;
#endif
