#ifndef SDBUS_JSON_H
#define SDBUS_JSON_H

#include <sdbus-c++/sdbus-c++.h>
#include <boost/json.hpp>

namespace sdbus
{
    namespace json = boost::json;
    
    sdbus::Message &operator<<(sdbus::Message &msg, json::value const &item)
    {
        return msg;
    }

    sdbus::Message &operator>>(sdbus::Message &msg, json::value &item);

    /**
     * Used for deserializing arrays _and structs_ for lack of better container to put them in.
     */
    sdbus::Message &operator>>(sdbus::Message &msg, json::array &array)
    {
        auto [type, contents] = msg.peekType();

        if(type == 'a')
        {
            msg.enterContainer(contents);
        }
        else
        {
            msg.enterStruct(contents);
        }

        while(!msg.isAtEnd(false))
        {
            json::value item;
            msg >> item;
            array.push_back(item);
        }

        if(type == 'a')
        {
            msg.exitContainer();
        }
        else
        {
            msg.exitStruct();
        }

        return msg;
    }

    sdbus::Message &operator>>(sdbus::Message &msg, json::object &object) { return msg; }

    sdbus::Message &operator>>(sdbus::Message &msg, json::string &string) 
    { 
        std::string value;
        msg >> value;
        string = value;

        return msg; 
    }

    sdbus::Message &operator>>(sdbus::Message &msg, json::value &item)
    {
        auto [type, contents] = msg.peekType();

        switch (type)
        {
            case 'y': 
            {
                std::uint8_t value;
                msg >> value;
                item = value;
                break;
            }

            case 'b': 
            {
                bool value;
                msg >> value;
                item = value;
                break;
            }

            case 'n': 
            {
                std::int16_t value;
                msg >> value;
                item = value;
                break;
            }

            case 'q': 
            {
                std::uint16_t value;
                msg >> value;
                item = value;
                break;
            }

            case 'i': 
            {
                std::int32_t value;
                msg >> value;
                item = value;
                break;
            }

            case 'u': 
            {
                std::uint32_t value;
                msg >> value;
                item = value;
                break;
            }

            case 'x': 
            {
                std::int64_t value;
                msg >> value;
                item = value;
                break;
            }

            case 't': 
            {
                std::uint64_t value;
                msg >> value;
                item = value;
                break;
            }

            case 'd': 
            {
                double value;
                msg >> value;
                item = value;
                break;
            }

            case 's':
            {
                item = json::string{};
                msg >> item.as_string();
                break;
            }

            case 'o':
            {
                sdbus::ObjectPath value;
                msg >> value;
                item = value.c_str();
                break;
            }

            case 'r':
            case 'a':
            {
                item = json::array{};
                msg >> item.as_array();
                break;
            }

            default:
            {
                throw std::runtime_error("Unable to deserialize type into JSON!");
            }
        }

        return msg;
    }
}

#endif