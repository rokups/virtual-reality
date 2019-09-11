/*
 * MIT License
 *
 * Copyright (c) 2017 Rokas Kupstys
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#pragma once

#include <type_traits>
#include <stdexcept>
#include <cstdint>

namespace hooker
{
    namespace detail
    {
        extern "C"
        {
            #include "hooker.h"
        }
    }
#if __cplusplus >= 201402L
    /// Pattern for find_pattern() function.
    template <size_t N>
    struct pattern
    {
        /// Bytes to find. Value of wildcard byte or byte half can be anything.
        uint8_t pattern[N];
        /// Wildcard pattern. Byte value may be one of: 0? = 1, ?0 = 2, ?? = 3.
        uint8_t wildcard[N];
    };

#   define CPP14(x) x
    namespace detail
    {
        struct Helper { };

        // Convert hex character to a number.
        constexpr uint8_t char_to_byte(char c)
        {
            if (c >= '0' && c <= '9')
                return c - '0';
            else if (c >= 'a' && c <= 'f')
                return 0x0A + c - 'a';
            else if (c >= 'A' && c <= 'F')
                return 0x0A + c - 'A';
            else if (c == '?')
                return 0;
            else
                throw std::runtime_error("Not a hex character.");
        }

        // Convert text hex byte at `idx` to binary.
        template <size_t N>
        constexpr uint8_t get_pattern_byte(const char(&s)[N], size_t idx)
        {
            if (s[idx * 3 + 2] != ' ' && s[idx * 3 + 2] != '\0')
                throw std::runtime_error("Improperly formatted pattern.");
            else
                return (char_to_byte(s[idx * 3]) << 4) | char_to_byte(s[idx * 3 + 1]);
        }

        // Convert text wildcard to binary mask.
        template <size_t N>
        constexpr uint8_t get_wildcard_byte(const char(&s)[N], size_t idx)
        {
            return (s[idx * 3] == '?' ? 2 : 0) | (s[idx * 3 + 1] == '?' ? 1 : 0);
        }

        // Convert a character array to binary version and wildcard array.
        template <size_t N, size_t... Is>
        constexpr pattern<sizeof...(Is)> decode_string_pattern(const char(&s)[N], std::index_sequence<Is...>)
        {
            return {
                { get_pattern_byte(s, Is)... },
                { get_wildcard_byte(s, Is)... },
            };
        }
    }

    // Create a binary pattern from raw string litteral in format: "AB C? ?D ??".
    template <size_t N>
    constexpr const pattern<N / 3> mkpat(const char(&s)[N])
    {
        if ((N % 3) == 0)
            return detail::decode_string_pattern(s, std::make_index_sequence<N / 3>());
        else
            throw std::runtime_error("Improperly formatted pattern.");
    }

#else
#   define CPP14(x)
#endif

#if __cplusplus > 201703L
    using bit_cast = std::bit_cast;
#else
    template<typename To, typename From>
#if __cplusplus >= 201703L
    [[nodiscard]]
#endif
    To bit_cast(From &&from)
#if __cplusplus >= 201402L
        noexcept(std::is_nothrow_constructible<To>::value)
#endif
    {
        static_assert(std::is_trivially_copyable<typename std::remove_cv<typename std::remove_reference<From>::type>::type>::value, "From type must be trivially copable.");
        static_assert(std::is_trivially_copyable<typename std::remove_cv<typename std::remove_reference<To>::type>::type>::value, "To type must be trivially copiable.");
        static_assert(sizeof(From) == sizeof(To), "Sizes of From and To types must be the same.");
        static_assert(std::is_default_constructible<To>::value, "To type must be default constructible.");
#if __cplusplus >= 201402L
        auto result = (typename std::aligned_storage_t<sizeof(To), alignof(To)>){};
#else
        To result{};
#endif
        return *static_cast<To*>(memcpy(&result, &from, sizeof(To)));
    }
#endif

    namespace detail
    {
        template<typename Addr>
        typename std::enable_if<std::is_integral<Addr>::value, void*>::type
        any_to_voidp(Addr addr) { return reinterpret_cast<void*>(addr); }

        template<typename Addr>
        typename std::enable_if<!std::is_integral<Addr>::value, void*>::type
        any_to_voidp(Addr addr) { return bit_cast<void*>(addr); }
    }
#if _WIN32
    /// Calls specified address as __stdcall function passing any amount of arguments. Return type is specified as first template argument. Available only on windows.
    /// \param address of function to call.
    /// \param ... any amount of arguments with any types.
    /// \returns value of type specified as first template argument, or none if no type is specified.
    template<typename Result, typename Addr, typename... Args>
    Result stdcall(Addr address, Args... arguments)
    {
        typedef Result(__stdcall*UniversalCall)(Args...);
        return UniversalCall(address)(arguments...);
    }
#   define HOOKER_CDECL __cdecl
#else
#   define HOOKER_CDECL
#endif
    /// Calls specified address as __cdecl function passing any amount of arguments. Return type is specified as first template argument.
    /// \param address of function to call.
    /// \param ... any amount of arguments with any types.
    /// \returns value of type specified as first template argument, or none if no type is specified.
    template<typename Result, typename Addr, typename... Args>
    Result ccall(Addr address, Args... arguments)
    {
        typedef Result(HOOKER_CDECL*UniversalCall)(Args...);
        return reinterpret_cast<UniversalCall>(address)(arguments...);
    }
#undef HOOKER_CDECL
    /// Calls specified address as __thiscall function with provided address as 'this' pointer, passing any amount of arguments. Return type is specified as first template argument.
    /// \param address of function to call.
    /// \param ... any amount of arguments with any types.
    /// \returns value of type specified as first template argument, or none if no type is specified.
    template<typename Result, typename Addr, typename This, typename... Args>
    Result thiscall(Addr address, This thisPtr, Args... arguments)
    {
        detail::Helper* thisHelper = bit_cast<detail::Helper*>(thisPtr);
        typedef Result(detail::Helper::*TUniversalCall)(Args...);
        TUniversalCall UniversalCall = bit_cast<TUniversalCall>(address);
        return (thisHelper->*UniversalCall)(arguments...);
    }

    /// Return object of specified `Type` which is located at `base + offset`.
    template<typename Type, typename Base>
    Type at_offset(Base base, unsigned offset)
    {
        return bit_cast<Type>(bit_cast<std::uintptr_t>(base) + offset);
    }
    /// Return object of specified `Type` which is located at `base + offset`.
    template<typename Type, typename Base>
    Type from_offset(Base base, unsigned offset)
    {
        return *at_offset<Type*>(base, offset);
    }
    /// Change protection of memory range.
    /// \param p memory address.
    /// \param size of memory at address p.
    /// \param protection a combination of HOOKER_MEM_* flags.
    /// \param original_protection on supported platforms will be set to current memory protection mode. May be null. If not null - always initialize to a best-guess current protection flags value, because on some platforms (like linux) this variable will not be set.
    template<typename Type CPP14(=void*), typename Addr>
    bool mem_protect(Addr p, size_t size, size_t protection, size_t* original_protection=nullptr) { return detail::hooker_mem_protect(detail::any_to_voidp(p), size, protection, original_protection) == HOOKER_SUCCESS;  }
    /// Get mnemonic size of current platform.
    template<typename Addr>
    size_t get_mnemonic_size(Addr address, size_t min_size) { return detail::hooker_get_mnemonic_size(detail::any_to_voidp(address), min_size); }

    /// Hotpatch a call.
    template<typename OriginalProc CPP14(=void*), typename Addr, typename ProcAddr>
    OriginalProc hotpatch(Addr location, ProcAddr new_proc) { return bit_cast<OriginalProc>(detail::hooker_hotpatch(detail::any_to_voidp(location), detail::any_to_voidp(new_proc))); }
    /// Unhotpatch a call.
    template<typename Type CPP14(=void*), typename Addr>
    bool unhotpatch(Addr location) { return detail::hooker_unhotpatch(detail::any_to_voidp(location)) == HOOKER_SUCCESS; }

    /// Writes a jump or call hook from `address` to `new_proc`.
    /// \param address a pointer where hook should be written
    /// \param new_proc a pointer where hook should point to.
    /// \param flags any of HOOKER_HOOK_* flags. They may not be combined.
    /// \param nops of bytes to nop after hook instruction. Specify -1 to autocalculate.
    /// \returns null on failure or non-null on success.
    template<typename Addr, typename ProcAddr>
    bool hook(Addr address, ProcAddr new_proc, size_t flags, size_t nops=-1) { return detail::hooker_hook(detail::any_to_voidp(address), detail::any_to_voidp(new_proc), flags, nops) == HOOKER_SUCCESS; }

    /// Redirect call to custom proc.
    /// \param address a start of original call. Warning: It should not contain any relatively-addressed instructions like calls or jumps.
    /// \param new_proc a proc that will be called instead of original one.
    /// \returns pointer, calling which will invoke original proc. It is user's responsibility to call original code when necessary.
    template<typename OriginalProc CPP14(=void*), typename Addr, typename ProcAddr>
    OriginalProc redirect(Addr address, ProcAddr new_proc, size_t flags=0) { return bit_cast<OriginalProc>(detail::hooker_redirect(detail::any_to_voidp(address), detail::any_to_voidp(new_proc), flags)); }

    /// Unhook a hook created by hooker::hook(.., .., HOOKER_HOOK_REDIRECT, ..).
    /// \param address where hook was written to.
    /// \param original result of hooker::redirect() call.
    template<typename Addr, typename OriginalProc>
    void unhook(Addr address, OriginalProc original) { detail::hooker_unhook(detail::any_to_voidp(address), detail::any_to_voidp(original)); }

    /// Return address in object's vmt which is pointing to specified method.
    /// \param object is a pointer to a c++ object.
    /// \param method is a pointer to a c++ object method.
    template<typename Proc, typename Addr, typename ProcAddr>
    Proc& get_vmt_address(Addr object, ProcAddr method) { return *bit_cast<Proc*>(detail::hooker_get_vmt_address(reinterpret_cast<void*>(object), detail::any_to_voidp(method))); }

    /// Find a first occourence of memory pattern.
    /// \param start a pointer to beginning of memory range.
    /// \param size a size of memory range. If size is 0 then entire memory space will be searched. If pattern does not exist this will likely result in a crash. Negative size will search backwards.
    /// \param pattern a array of bytes to search for.
    /// \param pattern_len a length of pattern array.
    /// \param a wildcard byte in the pattern array.
    template<typename Type CPP14(=uint8_t*), typename Addr, typename Pattern>
    Type find_pattern(Addr start, int size, const Pattern* pattern, size_t pattern_len, uint8_t wildcard) { return bit_cast<Type>(detail::hooker_find_pattern(detail::any_to_voidp(start), size, reinterpret_cast<const uint8_t*>(pattern), pattern_len, wildcard)); }

#if __cplusplus >= 201402L
    /// Find a first occourence of memory pattern.
    /// \param start a pointer to beginning of memory range.
    /// \param size a size of memory range. If size is 0 then entire memory space will be searched. If pattern does not exist this will likely result in a crash. Negative size will search backwards.
    /// \param pattern and wildcard mask.
    template<typename Type CPP14(=uint8_t*), typename Addr, size_t N>
    Type find_pattern(Addr start, int size, const pattern<N>& pattern) { return bit_cast<Type>(detail::hooker_find_pattern_ex(detail::any_to_voidp(start), size, pattern.pattern, N, pattern.wildcard)); }
#endif

    /// Find a first occourence of string pattern.
    /// \param start a pointer to beginning of memory range.
    /// \param size a size of memory range. If size is 0 then entire memory space will be searched. If pattern does not exist this will likely result in a crash. Negative size will search backwards.
    /// \param pattern a string to search.
    /// \param wildcard a wildcard character.
    template<typename Type CPP14(=char*), typename Addr>
    Type find_pattern(Addr start, int size, const char* pattern, char wildcard='?') { return bit_cast<Type>(detail::hooker_find_pattern(detail::any_to_voidp(start), size, reinterpret_cast<const uint8_t*>(pattern), strlen(pattern), static_cast<uint8_t>(wildcard))); }

    /// Fill memory with nops (0x90 opcode).
    /// \param start of the memory address.
    /// \param size of the memory that will be filled.
    /// \returns true on success or false on failure.
    template<typename Addr>
    bool nop(Addr start, size_t size) { return detail::hooker_nop(detail::any_to_voidp(start), size) == HOOKER_SUCCESS; }

    /// Write a value to specified memory address.
    /// \param start of the memory address.
    /// \param value to be written.
    /// \returns true on success or false on failure.
    template<typename Type, typename Addr>
    bool write(Addr address, const Type value) { return detail::hooker_write(detail::any_to_voidp(address), (void*)&value, sizeof(value)) == HOOKER_SUCCESS; }

    /// Write an array to specified memory address.
    /// \param start of the memory address.
    /// \param value to be written.
    /// \param count of elements in the array.
    template<typename Type, typename Addr>
    bool write(Addr address, const Type* value, size_t count) { return detail::hooker_write(detail::any_to_voidp(address), (void*)value, sizeof(Type) * count) == HOOKER_SUCCESS; }

    /// Write bytes to specified memory address.
    /// \param start of the memory address.
    /// \param data to be written.
    /// \param size of data.
    /// \returns true on success or false on failure.
    template<typename Addr>
    bool write(Addr address, const void* data, size_t size) { return detail::hooker_write(detail::any_to_voidp(address), data, size) == HOOKER_SUCCESS; }

    /// Searches for symbol in specified library. On Windows LoadLibrary() will be called if its not loaded yet, otherwise GetModuleHandle() will be used.
    /// On linux dlopen(RTLD_NODELETE) and dlclose() will always be called.
    /// \param lib_name string with dynamic library name.
    /// \param sym_name string with exported symbol name.
    /// \returns pointer to resolved dynamic symbol.
    template<typename Proc CPP14(=void*)>
    Proc dlsym(const char* lib_name, const char* sym_name) { return bit_cast<Proc>(detail::hooker_dlsym(lib_name, sym_name)); }

#if _WIN32
    /// Replaces entry in import address table of specified module.
    /// \param mod_name string with name of module whose import table is to be modified.
    /// \param imp_mod_name string with name of module which module specified in `mod_name` imports.
    /// \param imp_proc_name string with name of symbol imported from module specified in `imp_mod_name`.
    /// \param new_proc a pointer that should replace old entry in import address table.
    /// \returns original value that was in import address table or null pointer on failure.
    template<typename OrigProc CPP14(= void*), typename NewProc>
    OrigProc hook_iat(const char* mod_name, const char* imp_mod_name, const char* imp_proc_name, NewProc new_proc) { return bit_cast<OrigProc>(detail::hooker_hook_iat(mod_name, imp_mod_name, imp_proc_name, detail::any_to_voidp(new_proc))); }

    /// Replaces entry in import address table of specified module.
    /// \param mod_name string with name of module whose import table is to be modified.
    /// \param imp_mod_name string with name of module which module specified in `mod_name` imports.
    /// \param imp_proc_name string with name of symbol imported from module specified in `imp_mod_name`.
    /// \param new_proc a pointer that should replace old entry in import address table.
    /// \param old_proc a pointer which will receive  Can be null.
    /// \returns true on success or false on failure.
    template<typename OrigProc CPP14(=void*), typename NewProc>
    bool hook_iat(const char* mod_name, const char* imp_mod_name, const char* imp_proc_name, NewProc new_proc, OrigProc* old_proc)
    {
        auto result = hook_iat<OrigProc>(mod_name, imp_mod_name, imp_proc_name, detail::any_to_voidp(new_proc));
        if (old_proc)
            *old_proc = result;
        return result != HOOKER_ERROR;
    }
#endif

};

#if HOOKER_USE_SHORT_NAMESPACE
#   ifndef HOOKER_SHORT_NAMESPACE
#       define HOOKER_SHORT_NAMESPACE hk
#   endif
namespace HOOKER_SHORT_NAMESPACE = hooker;
#endif
