#ifndef REST_PROVIDER_H
#define REST_PROVIDER_H

namespace webctl
{
    using Response = http::message_generator;
    using Request = http::request<http::string_body>;

    template<typename ContextType>
    struct Route
    {
        using HandlerFunctionType = Response(*)(ContextType &, Request const&);

        http::verb method;
        char const *path;
        HandlerFunctionType handler_function;
    };

    template<typename ContextType>
    struct Middleware
    {
        using MiddlewareFunctionType = std::optional<Response>(*)(ContextType &, Request&);

        char const *path;
        MiddlewareFunctionType middleware_function;
    };

    template<typename ContextType>
    using Handler = std::variant<Route<ContextType>, Middleware<ContextType>>;

    template<typename ContextType>
    using RestDescription = std::initializer_list<Handler<ContextType>>;

    template<typename ContextType>
    struct HandlerTree
    {
        std::vector<Handler<ContextType>> handlers;
        std::unordered_map<std::string, HandlerTree> children;
    };

    template<typename ContextType>
    class RestProvider
    {
        HandlerTree<ContextType> handlers_;

    public:
        [[nodiscard]] Response Handle(ContextType &ctx, Request &req)
        {
            auto path = req.target();

            HandlerTree<ContextType> *tree = &this->handlers_;
            for (auto const part : std::views::split(path, std::string_view{"/"}))
            {
                if (!part.empty())
                {
                    tree = &tree->children[std::string{part.begin(), part.end()}];
                }

                for (auto const &handler : tree->handlers)
                {
                    if (std::holds_alternative<Middleware<ContextType>>(handler))
                    {
                        auto middleware = std::get<Middleware<ContextType>>(handler);
                        auto res = middleware.middleware_function(ctx, req);

                        if (res)
                        {
                            return std::move(res.value());
                        }
                    }
                }
            }

            auto const it = std::ranges::find_if(tree->handlers, [&](Handler<ContextType> &handler) {
                if (std::holds_alternative<Middleware<ContextType>>(handler)) return false;
                auto const &node = std::get<Route<ContextType>>(handler);

                return (path == node.path && req.method() == node.method);
            });

            if (it != tree->handlers.end())
            {
                return std::get<Route<ContextType>>(*it).handler_function(ctx, req);
            }

            auto res = http::response<http::string_body>{http::status::not_found, req.version()};
            res.body() = "404 Not Found";
            return res;
        }

        /**
         *
         * @param description Description of REST routes to build Provider from.
         */
        RestProvider(RestDescription<ContextType> const &description)
        {
            for (auto const &handler : description)
            {
                std::string path = std::visit(overload{
                    [](Route<ContextType> const &node) {
                        return node.path;
                    },
                    [](Middleware<ContextType> const &middleware) {
                        return middleware.path;
                    }
                }, handler);

                HandlerTree<ContextType> *tree = &this->handlers_;
                for (auto const part : std::views::split(path.substr(1), std::string_view{"/"}))
                {
                    if (part.empty()) continue;

                    tree = &tree->children[std::string{part.begin(), part.end()}];
                }

                tree->handlers.push_back(handler);
            }
        }
    };
}

#endif