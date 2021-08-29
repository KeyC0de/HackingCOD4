#pragma once

#include "util.h"
#include "winner.h"
#include <locale>
#include <codecvt>


std::wstring s2ws( const std::string& s )
{
	try
	{
		return std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>>{}
			.from_bytes( s );
	}
	catch( std::range_error& e )
	{
		(void)e;
		size_t length = s.length();
		std::wstring result;
		result.reserve( length );
		for ( size_t i = 0; i < length; ++i )
		{
			result.push_back( s[i] & 0xFF );
		}
		return result;
	}
}

std::string ws2s( const std::wstring& ws )
{
	try
	{
		return std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>>{}
			.to_bytes( ws );
	}
	catch( std::range_error& e )
	{
		(void)e;
		size_t length = ws.length();
		std::string result;
		result.reserve( length );
		for ( size_t i = 0; i < length; ++i )
		{
			result.push_back( ws[i] & 0xFF );
		}
		return result;
	}
}