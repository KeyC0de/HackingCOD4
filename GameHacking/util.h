#pragma once

#include <string>

//===================================================
//	\function	s2ws
//	\brief	convert from strings/chars to wide strings/wchar_ts
//	\date	2020/12/30 20:38
std::wstring s2ws( const std::string& narrow );
//===================================================
//	\function	ws2s
//	\brief	convert wide strings/wchar_ts to strings/chars
//	\date	2020/12/30 20:38
std::string ws2s( const std::wstring& wide );