#pragma once
#include "Windows.h"
#include <cstdint>

namespace Offsets
{
	// smegma
	constexpr uint32_t SCF_END_MARKER = 0xF4CC02EB;
	constexpr uintptr_t SCF_MARKER_STK = 0xDEADBEEFDEADC0DE;

	static constexpr auto cfg_cachee = 0x299ac0;
	static constexpr auto cfg_cache_alignment = 0x10000;

	static constexpr auto map = 0x2d3a48;
	static constexpr auto set_insert = 0xcea020;

	constexpr uint8_t kPageShift = 0xc;
	constexpr uint64_t kPageHash = 0x5f9213b9;
	constexpr uint64_t kPageMask = 0xFFFFFFFF;
	constexpr uint16_t SCF_INSERTED_JMP = 0x90dd36fed8ea4ff4;
	
	constexpr uint64_t Offset_InsertSet = set_insert;  
	constexpr uint64_t Offset_WhitelistedPages = map;
	constexpr uint64_t Offset_TargetCacheBitmap = cfg_cachee;
	constexpr uint64_t cfg_cache = cfg_cachee;
}

