#pragma once
#include "Windows.h"

namespace Offsets
{
	// bypass roblox checks
	constexpr uint32_t SCF_END_MARKER = 0xF4CC02EB;
	constexpr uintptr_t SCF_MARKER_STK = 0xDEADBEEFDEADC0DE;

	// Updated offsets for the latest Roblox version (April 2023)
	// Match exactly with RMMInject.cpp version
	static constexpr auto cfg_cachee = 0x2A8558;
	static constexpr auto cfg_cache_alignment = 0x10000;

	static constexpr auto map = 0x2A86A0;
	static constexpr auto set_insert = 0xB57060;

	constexpr uint8_t kPageShift = 0xc;
	constexpr uint64_t kPageHash = 0x5f9213b9;
	constexpr uint64_t kPageMask = 0xFFF;
	constexpr uint16_t SCF_INSERTED_JMP = 0x04EB;
	
	// Keep these for backward compatibility
	constexpr uint64_t Offset_InsertSet = set_insert;  
	constexpr uint64_t Offset_WhitelistedPages = map;
	constexpr uint64_t Offset_TargetCacheBitmap = cfg_cachee;
	constexpr uint64_t cfg_cache = cfg_cachee;
}
