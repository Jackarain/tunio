//
// test_throw.hpp
// ~~~~~~~~~~~~~~
//
// Copyright (c) 2026 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#pragma once

#include <stdexcept>
#include <string>

// 测试异常宏：在信息前附加文件与行号，保证所有测试抛出点的异常信息
// 唯一，崩溃时可直接定位到具体抛异常的代码位置.
#define TEST_THROW(msg) \
    throw std::runtime_error(std::string(__FILE__) + ":" + \
        std::to_string(__LINE__) + " " + (msg))

