//
// Copyright (c) 2015 Hugo Amiard <hugo.amiard@laposte.net>
//
// This software is provided 'as-is', without any express or implied
// warranty. In no event will the authors be held liable for any damages
// arising from the use of this software.
//
// Permission is granted to anyone to use this software for any purpose,
// including commercial applications, and to alter it and redistribute it
// freely, subject to the following restrictions:
//
// 1. The origin of this software must not be misrepresented; you must not
// claim that you wrote the original software. If you use this software
// in a product, an acknowledgment in the product documentation would be
// appreciated but is not required.
// 2. Altered source versions must be plainly marked as such, and must not be
// misrepresented as being the original software.
// 3. This notice may not be removed or altered from any source distribution.
//
#pragma once


#include <type_traits>
#include <utility>

namespace tinystl
{

template <typename T>
class function;

template <typename Return, typename... Args>
class function<Return(Args...)>
{
public:
    function() {}

    template <class T, typename = typename std::enable_if<std::is_invocable<T, Args...>::value>::type>
    function(T functor)
    {
        m_func = [](const void* user, Args... args) -> Return
        {
            const T& func = *static_cast<const T*>(user);
            return func(static_cast<Args&&>(args)...);
        };

        m_dtor = [](void* user)
        {
            T& func = *static_cast<T*>(user);
            func.~T();
        };

        static_assert(sizeof(T) <= sizeof(m_storage));
        new(m_storage) T(std::move(functor));
    }

    ~function()
    {
        if(m_dtor) m_dtor(m_storage);
    }

    Return operator()(Args... args) const
    {
        return m_func(m_storage, static_cast<Args&&>(args)...);
    }

    explicit operator bool() { return m_func != nullptr; }

    using Func = Return(*)(const void*, Args...); Func m_func = nullptr;
    using Dtor = void(*)(void*); Dtor m_dtor = nullptr;
    void* m_storage[8];
};

}
