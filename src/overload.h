#ifndef OVERLOAD_H
#define OVERLOAD_H

/*
 * Helper for std::visit provided by Andreas Fertig.
 * https://andreasfertig.blog/2023/07/visiting-a-stdvariant-safely/
 */
template<class...>
constexpr bool always_false_v = false;

template<class... Ts>
struct overload : Ts...
{
    using Ts::operator()...;

    template<typename T>
    constexpr void operator()(T) const
    {
        static_assert(always_false_v<T>, "Unsupported type");
    }
};

template<class... Ts>
overload(Ts...) -> overload<Ts...>;

#endif